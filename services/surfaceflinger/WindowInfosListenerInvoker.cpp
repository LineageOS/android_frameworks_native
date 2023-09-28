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

#include <android/gui/BnWindowInfosPublisher.h>
#include <android/gui/IWindowInfosPublisher.h>
#include <android/gui/WindowInfosListenerInfo.h>
#include <gui/ISurfaceComposer.h>
#include <gui/TraceUtils.h>
#include <gui/WindowInfosUpdate.h>
#include <scheduler/Time.h>

#include "BackgroundExecutor.h"
#include "WindowInfosListenerInvoker.h"

#undef ATRACE_TAG
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

namespace android {

using gui::DisplayInfo;
using gui::IWindowInfosListener;
using gui::WindowInfo;

void WindowInfosListenerInvoker::addWindowInfosListener(sp<IWindowInfosListener> listener,
                                                        gui::WindowInfosListenerInfo* outInfo) {
    int64_t listenerId = mNextListenerId++;
    outInfo->listenerId = listenerId;
    outInfo->windowInfosPublisher = sp<gui::IWindowInfosPublisher>::fromExisting(this);

    BackgroundExecutor::getInstance().sendCallbacks(
            {[this, listener = std::move(listener), listenerId]() {
                ATRACE_NAME("WindowInfosListenerInvoker::addWindowInfosListener");
                sp<IBinder> asBinder = IInterface::asBinder(listener);
                asBinder->linkToDeath(sp<DeathRecipient>::fromExisting(this));
                mWindowInfosListeners.try_emplace(asBinder,
                                                  std::make_pair(listenerId, std::move(listener)));
            }});
}

void WindowInfosListenerInvoker::removeWindowInfosListener(
        const sp<IWindowInfosListener>& listener) {
    BackgroundExecutor::getInstance().sendCallbacks({[this, listener]() {
        ATRACE_NAME("WindowInfosListenerInvoker::removeWindowInfosListener");
        sp<IBinder> asBinder = IInterface::asBinder(listener);
        asBinder->unlinkToDeath(sp<DeathRecipient>::fromExisting(this));
        eraseListenerAndAckMessages(asBinder);
    }});
}

void WindowInfosListenerInvoker::binderDied(const wp<IBinder>& who) {
    BackgroundExecutor::getInstance().sendCallbacks({[this, who]() {
        ATRACE_NAME("WindowInfosListenerInvoker::binderDied");
        eraseListenerAndAckMessages(who);
    }});
}

void WindowInfosListenerInvoker::eraseListenerAndAckMessages(const wp<IBinder>& binder) {
    auto it = mWindowInfosListeners.find(binder);
    int64_t listenerId = it->second.first;
    mWindowInfosListeners.erase(binder);

    std::vector<int64_t> vsyncIds;
    for (auto& [vsyncId, state] : mUnackedState) {
        if (std::find(state.unackedListenerIds.begin(), state.unackedListenerIds.end(),
                      listenerId) != state.unackedListenerIds.end()) {
            vsyncIds.push_back(vsyncId);
        }
    }

    for (int64_t vsyncId : vsyncIds) {
        ackWindowInfosReceived(vsyncId, listenerId);
    }
}

void WindowInfosListenerInvoker::windowInfosChanged(
        gui::WindowInfosUpdate update, WindowInfosReportedListenerSet reportedListeners,
        bool forceImmediateCall) {
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
    if (!mUnackedState.empty() && !forceImmediateCall) {
        mDelayedUpdate = std::move(update);
        mReportedListeners.merge(reportedListeners);
        return;
    }

    if (mDelayedUpdate) {
        mDelayedUpdate.reset();
    }

    if (CC_UNLIKELY(mWindowInfosListeners.empty())) {
        mReportedListeners.merge(reportedListeners);
        mDelayInfo.reset();
        return;
    }

    reportedListeners.merge(mReportedListeners);
    mReportedListeners.clear();

    // Update mUnackedState to include the message we're about to send
    auto [it, _] = mUnackedState.try_emplace(update.vsyncId,
                                             UnackedState{.reportedListeners =
                                                                  std::move(reportedListeners)});
    auto& unackedState = it->second;
    for (auto& pair : mWindowInfosListeners) {
        int64_t listenerId = pair.second.first;
        unackedState.unackedListenerIds.push_back(listenerId);
    }

    mDelayInfo.reset();
    updateMaxSendDelay();

    // Call the listeners
    for (auto& pair : mWindowInfosListeners) {
        auto& [listenerId, listener] = pair.second;
        auto status = listener->onWindowInfosChanged(update);
        if (!status.isOk()) {
            ackWindowInfosReceived(update.vsyncId, listenerId);
        }
    }
}

WindowInfosListenerInvoker::DebugInfo WindowInfosListenerInvoker::getDebugInfo() {
    DebugInfo result;
    BackgroundExecutor::getInstance().sendCallbacks({[&, this]() {
        ATRACE_NAME("WindowInfosListenerInvoker::getDebugInfo");
        updateMaxSendDelay();
        result = mDebugInfo;
        result.pendingMessageCount = mUnackedState.size();
    }});
    BackgroundExecutor::getInstance().flushQueue();
    return result;
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

binder::Status WindowInfosListenerInvoker::ackWindowInfosReceived(int64_t vsyncId,
                                                                  int64_t listenerId) {
    BackgroundExecutor::getInstance().sendCallbacks({[this, vsyncId, listenerId]() {
        ATRACE_NAME("WindowInfosListenerInvoker::ackWindowInfosReceived");
        auto it = mUnackedState.find(vsyncId);
        if (it == mUnackedState.end()) {
            return;
        }

        auto& state = it->second;
        state.unackedListenerIds.unstable_erase(std::find(state.unackedListenerIds.begin(),
                                                          state.unackedListenerIds.end(),
                                                          listenerId));
        if (!state.unackedListenerIds.empty()) {
            return;
        }

        WindowInfosReportedListenerSet reportedListeners{std::move(state.reportedListeners)};
        mUnackedState.erase(vsyncId);

        for (const auto& reportedListener : reportedListeners) {
            sp<IBinder> asBinder = IInterface::asBinder(reportedListener);
            if (asBinder->isBinderAlive()) {
                reportedListener->onWindowInfosReported();
            }
        }

        if (!mDelayedUpdate || !mUnackedState.empty()) {
            return;
        }
        gui::WindowInfosUpdate update{std::move(*mDelayedUpdate)};
        mDelayedUpdate.reset();
        windowInfosChanged(std::move(update), {}, false);
    }});
    return binder::Status::ok();
}

} // namespace android
