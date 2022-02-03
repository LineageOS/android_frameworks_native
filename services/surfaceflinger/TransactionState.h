/*
 * Copyright (C) 2021 The Android Open Source Project
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

#pragma once

#include <gui/LayerState.h>

namespace android {
class CountDownLatch;

struct TransactionState {
    TransactionState(const FrameTimelineInfo& frameTimelineInfo,
                     const Vector<ComposerState>& composerStates,
                     const Vector<DisplayState>& displayStates, uint32_t transactionFlags,
                     const sp<IBinder>& applyToken, const InputWindowCommands& inputWindowCommands,
                     int64_t desiredPresentTime, bool isAutoTimestamp,
                     const client_cache_t& uncacheBuffer, int64_t postTime, uint32_t permissions,
                     bool hasListenerCallbacks, std::vector<ListenerCallbacks> listenerCallbacks,
                     int originPid, int originUid, uint64_t transactionId)
          : frameTimelineInfo(frameTimelineInfo),
            states(composerStates),
            displays(displayStates),
            flags(transactionFlags),
            applyToken(applyToken),
            inputWindowCommands(inputWindowCommands),
            desiredPresentTime(desiredPresentTime),
            isAutoTimestamp(isAutoTimestamp),
            buffer(uncacheBuffer),
            postTime(postTime),
            permissions(permissions),
            hasListenerCallbacks(hasListenerCallbacks),
            listenerCallbacks(listenerCallbacks),
            originPid(originPid),
            originUid(originUid),
            id(transactionId) {}

    TransactionState() {}

    void traverseStatesWithBuffers(std::function<void(const layer_state_t&)> visitor);

    FrameTimelineInfo frameTimelineInfo;
    Vector<ComposerState> states;
    Vector<DisplayState> displays;
    uint32_t flags;
    sp<IBinder> applyToken;
    InputWindowCommands inputWindowCommands;
    int64_t desiredPresentTime;
    bool isAutoTimestamp;
    client_cache_t buffer;
    int64_t postTime;
    uint32_t permissions;
    bool hasListenerCallbacks;
    std::vector<ListenerCallbacks> listenerCallbacks;
    int originPid;
    int originUid;
    uint64_t id;
    std::shared_ptr<CountDownLatch> transactionCommittedSignal;
};

class CountDownLatch {
public:
    enum {
        eSyncTransaction = 1 << 0,
        eSyncInputWindows = 1 << 1,
    };
    explicit CountDownLatch(uint32_t flags) : mFlags(flags) {}

    // True if there is no waiting condition after count down.
    bool countDown(uint32_t flag) {
        std::unique_lock<std::mutex> lock(mMutex);
        if (mFlags == 0) {
            return true;
        }
        mFlags &= ~flag;
        if (mFlags == 0) {
            mCountDownComplete.notify_all();
            return true;
        }
        return false;
    }

    // Return true if triggered.
    bool wait_until(const std::chrono::nanoseconds& timeout) const {
        std::unique_lock<std::mutex> lock(mMutex);
        const auto untilTime = std::chrono::system_clock::now() + timeout;
        while (mFlags != 0) {
            // Conditional variables can be woken up sporadically, so we check count
            // to verify the wakeup was triggered by |countDown|.
            if (std::cv_status::timeout == mCountDownComplete.wait_until(lock, untilTime)) {
                return false;
            }
        }
        return true;
    }

private:
    uint32_t mFlags;
    mutable std::condition_variable mCountDownComplete;
    mutable std::mutex mMutex;
};

} // namespace android
