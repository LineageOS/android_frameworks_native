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

#pragma once

#include <optional>
#include <unordered_set>

#include <android/gui/BnWindowInfosPublisher.h>
#include <android/gui/IWindowInfosListener.h>
#include <android/gui/IWindowInfosReportedListener.h>
#include <binder/IBinder.h>
#include <ftl/small_map.h>
#include <ftl/small_vector.h>
#include <gui/SpHash.h>
#include <utils/Mutex.h>

#include "scheduler/VsyncId.h"

namespace android {

using WindowInfosReportedListenerSet =
        std::unordered_set<sp<gui::IWindowInfosReportedListener>,
                           gui::SpHash<gui::IWindowInfosReportedListener>>;

class WindowInfosListenerInvoker : public gui::BnWindowInfosPublisher,
                                   public IBinder::DeathRecipient {
public:
    void addWindowInfosListener(sp<gui::IWindowInfosListener>, gui::WindowInfosListenerInfo*);
    void removeWindowInfosListener(const sp<gui::IWindowInfosListener>& windowInfosListener);

    void windowInfosChanged(gui::WindowInfosUpdate update,
                            WindowInfosReportedListenerSet windowInfosReportedListeners,
                            bool forceImmediateCall);

    binder::Status ackWindowInfosReceived(int64_t, int64_t) override;

    struct DebugInfo {
        VsyncId maxSendDelayVsyncId;
        nsecs_t maxSendDelayDuration;
        size_t pendingMessageCount;
    };
    DebugInfo getDebugInfo();

protected:
    void binderDied(const wp<IBinder>& who) override;

private:
    static constexpr size_t kStaticCapacity = 3;
    std::atomic<int64_t> mNextListenerId{0};
    ftl::SmallMap<wp<IBinder>, const std::pair<int64_t, sp<gui::IWindowInfosListener>>,
                  kStaticCapacity>
            mWindowInfosListeners;

    std::optional<gui::WindowInfosUpdate> mDelayedUpdate;
    WindowInfosReportedListenerSet mReportedListeners;
    void eraseListenerAndAckMessages(const wp<IBinder>&);

    struct UnackedState {
        ftl::SmallVector<int64_t, kStaticCapacity> unackedListenerIds;
        WindowInfosReportedListenerSet reportedListeners;
    };
    ftl::SmallMap<int64_t /* vsyncId */, UnackedState, 5> mUnackedState;

    DebugInfo mDebugInfo;
    struct DelayInfo {
        int64_t vsyncId;
        nsecs_t frameTime;
    };
    std::optional<DelayInfo> mDelayInfo;
    void updateMaxSendDelay();
};

} // namespace android
