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

#include "Scheduler/TimeKeeper.h"
#include "Scheduler/Timer.h"
#include "Scheduler/VSyncDispatchTimerQueue.h"
#include "Scheduler/VSyncTracker.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

using namespace testing;
using namespace std::literals;

namespace android::scheduler {

template <typename Rep, typename Per>
constexpr nsecs_t toNs(std::chrono::duration<Rep, Per> const& tp) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(tp).count();
}

class FixedRateIdealStubTracker : public VSyncTracker {
public:
    FixedRateIdealStubTracker() : mPeriod{toNs(3ms)} {}

    bool addVsyncTimestamp(nsecs_t) final { return true; }

    nsecs_t nextAnticipatedVSyncTimeFrom(nsecs_t timePoint) const final {
        auto const floor = timePoint % mPeriod;
        if (floor == 0) {
            return timePoint;
        }
        return timePoint - floor + mPeriod;
    }

    nsecs_t currentPeriod() const final { return mPeriod; }

    void setPeriod(nsecs_t) final {}
    void resetModel() final {}
    bool needsMoreSamples() const final { return false; }
    void dump(std::string&) const final {}

private:
    nsecs_t const mPeriod;
};

class VRRStubTracker : public VSyncTracker {
public:
    VRRStubTracker(nsecs_t period) : mPeriod{period} {}

    bool addVsyncTimestamp(nsecs_t) final { return true; }

    nsecs_t nextAnticipatedVSyncTimeFrom(nsecs_t time_point) const final {
        std::lock_guard<decltype(mMutex)> lk(mMutex);
        auto const normalized_to_base = time_point - mBase;
        auto const floor = (normalized_to_base) % mPeriod;
        if (floor == 0) {
            return time_point;
        }
        return normalized_to_base - floor + mPeriod + mBase;
    }

    void set_interval(nsecs_t interval, nsecs_t last_known) {
        std::lock_guard<decltype(mMutex)> lk(mMutex);
        mPeriod = interval;
        mBase = last_known;
    }

    nsecs_t currentPeriod() const final {
        std::lock_guard<decltype(mMutex)> lk(mMutex);
        return mPeriod;
    }

    void setPeriod(nsecs_t) final {}
    void resetModel() final {}
    bool needsMoreSamples() const final { return false; }
    void dump(std::string&) const final {}

private:
    std::mutex mutable mMutex;
    nsecs_t mPeriod;
    nsecs_t mBase = 0;
};

struct VSyncDispatchRealtimeTest : testing::Test {
    static nsecs_t constexpr mDispatchGroupThreshold = toNs(100us);
    static nsecs_t constexpr mVsyncMoveThreshold = toNs(500us);
    static size_t constexpr mIterations = 20;
};

class RepeatingCallbackReceiver {
public:
    RepeatingCallbackReceiver(VSyncDispatch& dispatch, nsecs_t wl)
          : mWorkload(wl),
            mCallback(
                    dispatch, [&](auto time, auto) { callback_called(time); }, "repeat0") {}

    void repeatedly_schedule(size_t iterations, std::function<void(nsecs_t)> const& onEachFrame) {
        mCallbackTimes.reserve(iterations);
        mCallback.schedule(mWorkload, systemTime(SYSTEM_TIME_MONOTONIC) + mWorkload);

        for (auto i = 0u; i < iterations - 1; i++) {
            std::unique_lock<decltype(mMutex)> lk(mMutex);
            mCv.wait(lk, [&] { return mCalled; });
            mCalled = false;
            auto last = mLastTarget;
            lk.unlock();

            onEachFrame(last);

            mCallback.schedule(mWorkload, last + mWorkload);
        }

        // wait for the last callback.
        std::unique_lock<decltype(mMutex)> lk(mMutex);
        mCv.wait(lk, [&] { return mCalled; });
    }

    void with_callback_times(std::function<void(std::vector<nsecs_t> const&)> const& fn) const {
        fn(mCallbackTimes);
    }

private:
    void callback_called(nsecs_t time) {
        std::lock_guard<decltype(mMutex)> lk(mMutex);
        mCallbackTimes.push_back(time);
        mCalled = true;
        mLastTarget = time;
        mCv.notify_all();
    }

    nsecs_t const mWorkload;
    VSyncCallbackRegistration mCallback;

    std::mutex mMutex;
    std::condition_variable mCv;
    bool mCalled = false;
    nsecs_t mLastTarget = 0;
    std::vector<nsecs_t> mCallbackTimes;
};

TEST_F(VSyncDispatchRealtimeTest, triple_alarm) {
    FixedRateIdealStubTracker tracker;
    VSyncDispatchTimerQueue dispatch(std::make_unique<Timer>(), tracker, mDispatchGroupThreshold,
                                     mVsyncMoveThreshold);

    static size_t constexpr num_clients = 3;
    std::array<RepeatingCallbackReceiver, num_clients>
            cb_receiver{RepeatingCallbackReceiver(dispatch, toNs(1500us)),
                        RepeatingCallbackReceiver(dispatch, toNs(0h)),
                        RepeatingCallbackReceiver(dispatch, toNs(1ms))};

    auto const on_each_frame = [](nsecs_t) {};
    std::array<std::thread, num_clients> threads{
            std::thread([&] { cb_receiver[0].repeatedly_schedule(mIterations, on_each_frame); }),
            std::thread([&] { cb_receiver[1].repeatedly_schedule(mIterations, on_each_frame); }),
            std::thread([&] { cb_receiver[2].repeatedly_schedule(mIterations, on_each_frame); }),
    };

    for (auto it = threads.rbegin(); it != threads.rend(); it++) {
        it->join();
    }

    for (auto const& cbs : cb_receiver) {
        cbs.with_callback_times([](auto times) { EXPECT_THAT(times.size(), Eq(mIterations)); });
    }
}

// starts at 333hz, slides down to 43hz
TEST_F(VSyncDispatchRealtimeTest, vascillating_vrr) {
    auto next_vsync_interval = toNs(3ms);
    VRRStubTracker tracker(next_vsync_interval);
    VSyncDispatchTimerQueue dispatch(std::make_unique<Timer>(), tracker, mDispatchGroupThreshold,
                                     mVsyncMoveThreshold);

    RepeatingCallbackReceiver cb_receiver(dispatch, toNs(1ms));

    auto const on_each_frame = [&](nsecs_t last_known) {
        tracker.set_interval(next_vsync_interval += toNs(1ms), last_known);
    };

    std::thread eventThread([&] { cb_receiver.repeatedly_schedule(mIterations, on_each_frame); });
    eventThread.join();

    cb_receiver.with_callback_times([](auto times) { EXPECT_THAT(times.size(), Eq(mIterations)); });
}

// starts at 333hz, jumps to 200hz at frame 10
TEST_F(VSyncDispatchRealtimeTest, fixed_jump) {
    VRRStubTracker tracker(toNs(3ms));
    VSyncDispatchTimerQueue dispatch(std::make_unique<Timer>(), tracker, mDispatchGroupThreshold,
                                     mVsyncMoveThreshold);

    RepeatingCallbackReceiver cb_receiver(dispatch, toNs(1ms));

    auto jump_frame_counter = 0u;
    auto constexpr jump_frame_at = 10u;
    auto const on_each_frame = [&](nsecs_t last_known) {
        if (jump_frame_counter++ == jump_frame_at) {
            tracker.set_interval(toNs(5ms), last_known);
        }
    };
    std::thread eventThread([&] { cb_receiver.repeatedly_schedule(mIterations, on_each_frame); });
    eventThread.join();

    cb_receiver.with_callback_times([](auto times) { EXPECT_THAT(times.size(), Eq(mIterations)); });
}
} // namespace android::scheduler
