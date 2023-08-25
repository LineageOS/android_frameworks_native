/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ftl/small_vector.h>
#include <gui/ISurfaceComposer.h>
#include <gui/TraceUtils.h>
#include <gui/WindowInfosUpdate.h>
#include <scheduler/Time.h>

#include "BackgroundExecutor.h"
#include "WindowInfosListenerInvoker.h"

namespace android {

using gui::DisplayInfo;
using gui::IWindowInfosListener;
using gui::WindowInfo;

using WindowInfosListenerVector = ftl::SmallVector<const sp<gui::IWindowInfosListener>, 3>;

struct WindowInfosReportedListenerInvoker : gui::BnWindowInfosReportedListener,
                                            IBinder::DeathRecipient {
    WindowInfosReportedListenerInvoker(WindowInfosListenerVector windowInfosListeners,
                                       WindowInfosReportedListenerSet windowInfosReportedListeners)
          : mCallbacksPending(windowInfosListeners.size()),
            mWindowInfosListeners(std::move(windowInfosListeners)),
            mWindowInfosReportedListeners(std::move(windowInfosReportedListeners)) {}

    binder::Status onWindowInfosReported() override {
        if (--mCallbacksPending == 0) {
            for (const auto& listener : mWindowInfosReportedListeners) {
                sp<IBinder> asBinder = IInterface::asBinder(listener);
                if (asBinder->isBinderAlive()) {
                    listener->onWindowInfosReported();
                }
            }

            auto wpThis = wp<WindowInfosReportedListenerInvoker>::fromExisting(this);
            for (const auto& listener : mWindowInfosListeners) {
                sp<IBinder> binder = IInterface::asBinder(listener);
                binder->unlinkToDeath(wpThis);
            }
        }
        return binder::Status::ok();
    }

    void binderDied(const wp<IBinder>&) { onWindowInfosReported(); }

private:
    std::atomic<size_t> mCallbacksPending;
    static constexpr size_t kStaticCapacity = 3;
    const WindowInfosListenerVector mWindowInfosListeners;
    WindowInfosReportedListenerSet mWindowInfosReportedListeners;
};

void WindowInfosListenerInvoker::addWindowInfosListener(sp<IWindowInfosListener> listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);
    asBinder->linkToDeath(sp<DeathRecipient>::fromExisting(this));

    std::scoped_lock lock(mListenersMutex);
    mWindowInfosListeners.try_emplace(asBinder, std::move(listener));
}

void WindowInfosListenerInvoker::removeWindowInfosListener(
        const sp<IWindowInfosListener>& listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);

    std::scoped_lock lock(mListenersMutex);
    asBinder->unlinkToDeath(sp<DeathRecipient>::fromExisting(this));
    mWindowInfosListeners.erase(asBinder);
}

void WindowInfosListenerInvoker::binderDied(const wp<IBinder>& who) {
    std::scoped_lock lock(mListenersMutex);
    mWindowInfosListeners.erase(who);
}

void WindowInfosListenerInvoker::windowInfosChanged(
        gui::WindowInfosUpdate update, WindowInfosReportedListenerSet reportedListeners,
        bool forceImmediateCall) {
    WindowInfosListenerVector listeners;
    {
        std::scoped_lock lock{mMessagesMutex};

        if (!mDelayInfo) {
            mDelayInfo = DelayInfo{
                    .vsyncId = update.vsyncId,
                    .frameTime = update.timestamp,
            };
        }

        // If there are unacked messages and this isn't a forced call, then return immediately.
        // If a forced window infos change doesn't happen first, the update will be sent after
        // the WindowInfosReportedListeners are called. If a forced window infos change happens or
        // if there are subsequent delayed messages before this update is sent, then this message
        // will be dropped and the listeners will only be called with the latest info. This is done
        // to reduce the amount of binder memory used.
        if (mActiveMessageCount > 0 && !forceImmediateCall) {
            mDelayedUpdate = std::move(update);
            mReportedListeners.merge(reportedListeners);
            return;
        }

        if (mDelayedUpdate) {
            mDelayedUpdate.reset();
        }

        {
            std::scoped_lock lock{mListenersMutex};
            for (const auto& [_, listener] : mWindowInfosListeners) {
                listeners.push_back(listener);
            }
        }
        if (CC_UNLIKELY(listeners.empty())) {
            mReportedListeners.merge(reportedListeners);
            mDelayInfo.reset();
            return;
        }

        reportedListeners.insert(sp<WindowInfosListenerInvoker>::fromExisting(this));
        reportedListeners.merge(mReportedListeners);
        mReportedListeners.clear();

        mActiveMessageCount++;
        updateMaxSendDelay();
        mDelayInfo.reset();
    }

    auto reportedInvoker =
            sp<WindowInfosReportedListenerInvoker>::make(listeners, std::move(reportedListeners));

    for (const auto& listener : listeners) {
        sp<IBinder> asBinder = IInterface::asBinder(listener);

        // linkToDeath is used here to ensure that the windowInfosReportedListeners
        // are called even if one of the windowInfosListeners dies before
        // calling onWindowInfosReported.
        asBinder->linkToDeath(reportedInvoker);

        auto status = listener->onWindowInfosChanged(update, reportedInvoker);
        if (!status.isOk()) {
            reportedInvoker->onWindowInfosReported();
        }
    }
}

binder::Status WindowInfosListenerInvoker::onWindowInfosReported() {
    BackgroundExecutor::getInstance().sendCallbacks({[this]() {
        gui::WindowInfosUpdate update;
        {
            std::scoped_lock lock{mMessagesMutex};
            mActiveMessageCount--;
            if (!mDelayedUpdate || mActiveMessageCount > 0) {
                return;
            }
            update = std::move(*mDelayedUpdate);
            mDelayedUpdate.reset();
        }
        windowInfosChanged(std::move(update), {}, false);
    }});
    return binder::Status::ok();
}

WindowInfosListenerInvoker::DebugInfo WindowInfosListenerInvoker::getDebugInfo() {
    std::scoped_lock lock{mMessagesMutex};
    updateMaxSendDelay();
    mDebugInfo.pendingMessageCount = mActiveMessageCount;
    return mDebugInfo;
}

void WindowInfosListenerInvoker::updateMaxSendDelay() {
    if (!mDelayInfo) {
        return;
    }
    nsecs_t delay = TimePoint::now().ns() - mDelayInfo->frameTime;
    if (delay > mDebugInfo.maxSendDelayDuration) {
        mDebugInfo.maxSendDelayDuration = delay;
        mDebugInfo.maxSendDelayVsyncId = VsyncId{mDelayInfo->vsyncId};
    }
}

} // namespace android
