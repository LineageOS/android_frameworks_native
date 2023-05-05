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
#include <gui/WindowInfosUpdate.h>

#include "WindowInfosListenerInvoker.h"

namespace android {

using gui::DisplayInfo;
using gui::IWindowInfosListener;
using gui::WindowInfo;

using WindowInfosListenerVector = ftl::SmallVector<const sp<IWindowInfosListener>, 3>;

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
        std::vector<WindowInfo> windowInfos, std::vector<DisplayInfo> displayInfos,
        WindowInfosReportedListenerSet reportedListeners, bool forceImmediateCall, VsyncId vsyncId,
        nsecs_t timestamp) {
    reportedListeners.insert(sp<WindowInfosListenerInvoker>::fromExisting(this));
    auto callListeners = [this, windowInfos = std::move(windowInfos),
                          displayInfos = std::move(displayInfos), vsyncId,
                          timestamp](WindowInfosReportedListenerSet reportedListeners) mutable {
        WindowInfosListenerVector windowInfosListeners;
        {
            std::scoped_lock lock(mListenersMutex);
            for (const auto& [_, listener] : mWindowInfosListeners) {
                windowInfosListeners.push_back(listener);
            }
        }

        auto reportedInvoker =
                sp<WindowInfosReportedListenerInvoker>::make(windowInfosListeners,
                                                             std::move(reportedListeners));

        gui::WindowInfosUpdate update(std::move(windowInfos), std::move(displayInfos),
                                      vsyncId.value, timestamp);

        for (const auto& listener : windowInfosListeners) {
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
    };

    {
        std::scoped_lock lock(mMessagesMutex);
        // If there are unacked messages and this isn't a forced call, then return immediately.
        // If a forced window infos change doesn't happen first, the update will be sent after
        // the WindowInfosReportedListeners are called. If a forced window infos change happens or
        // if there are subsequent delayed messages before this update is sent, then this message
        // will be dropped and the listeners will only be called with the latest info. This is done
        // to reduce the amount of binder memory used.
        if (mActiveMessageCount > 0 && !forceImmediateCall) {
            mWindowInfosChangedDelayed = std::move(callListeners);
            mUnsentVsyncId = vsyncId;
            mUnsentTimestamp = timestamp;
            mReportedListenersDelayed.merge(reportedListeners);
            return;
        }

        mWindowInfosChangedDelayed = nullptr;
        mUnsentVsyncId = {-1};
        mUnsentTimestamp = -1;
        reportedListeners.merge(mReportedListenersDelayed);
        mActiveMessageCount++;
    }
    callListeners(std::move(reportedListeners));
}

binder::Status WindowInfosListenerInvoker::onWindowInfosReported() {
    std::function<void(WindowInfosReportedListenerSet)> callListeners;
    WindowInfosReportedListenerSet reportedListeners;

    {
        std::scoped_lock lock{mMessagesMutex};
        mActiveMessageCount--;
        if (!mWindowInfosChangedDelayed || mActiveMessageCount > 0) {
            return binder::Status::ok();
        }

        mActiveMessageCount++;
        callListeners = std::move(mWindowInfosChangedDelayed);
        mWindowInfosChangedDelayed = nullptr;
        mUnsentVsyncId = {-1};
        mUnsentTimestamp = -1;
        reportedListeners = std::move(mReportedListenersDelayed);
        mReportedListenersDelayed.clear();
    }

    callListeners(std::move(reportedListeners));
    return binder::Status::ok();
}

} // namespace android
