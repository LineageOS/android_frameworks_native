/*
 * Copyright 2019 The Android Open Source Project
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

#include <android-base/thread_annotations.h>
#include <ui/FenceTime.h>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include "DispSync.h"

namespace android::scheduler {

class Clock;
class VSyncDispatch;
class VSyncTracker;
class CallbackRepeater;

// TODO (b/145217110): consider renaming.
class VSyncReactor /* TODO (b/140201379): : public android::DispSync */ {
public:
    VSyncReactor(std::unique_ptr<Clock> clock, std::unique_ptr<VSyncDispatch> dispatch,
                 std::unique_ptr<VSyncTracker> tracker, size_t pendingFenceLimit);
    ~VSyncReactor();

    bool addPresentFence(const std::shared_ptr<FenceTime>& fence);
    void setIgnorePresentFences(bool ignoration);

    nsecs_t computeNextRefresh(int periodOffset) const;
    nsecs_t expectedPresentTime();

    void setPeriod(nsecs_t period);
    nsecs_t getPeriod();

    // TODO: (b/145626181) remove begin,endResync functions from DispSync i/f when possible.
    void beginResync();
    bool addResyncSample(nsecs_t timestamp, bool* periodFlushed);
    void endResync();

    status_t addEventListener(const char* name, nsecs_t phase, DispSync::Callback* callback,
                              nsecs_t lastCallbackTime);
    status_t removeEventListener(DispSync::Callback* callback, nsecs_t* outLastCallback);
    status_t changePhaseOffset(DispSync::Callback* callback, nsecs_t phase);

private:
    std::unique_ptr<Clock> const mClock;
    std::unique_ptr<VSyncDispatch> const mDispatch;
    std::unique_ptr<VSyncTracker> const mTracker;
    size_t const mPendingLimit;

    std::mutex mMutex;
    bool mIgnorePresentFences GUARDED_BY(mMutex) = false;
    std::vector<std::shared_ptr<FenceTime>> mUnfiredFences GUARDED_BY(mMutex);
    bool mPeriodChangeInProgress GUARDED_BY(mMutex) = false;
    std::unordered_map<DispSync::Callback*, std::unique_ptr<CallbackRepeater>> mCallbacks
            GUARDED_BY(mMutex);
};

} // namespace android::scheduler
