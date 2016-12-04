/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_FENCE_TIME_H
#define ANDROID_FENCE_TIME_H

#include <ui/Fence.h>
#include <utils/Flattenable.h>
#include <utils/Timers.h>

#include <atomic>
#include <mutex>
#include <queue>

namespace android {

// A wrapper around fence that only implements isValid and getSignalTime.
// It automatically closes the fence in a thread-safe manner once the signal
// time is known.
class FenceTime {
public:
    // An atomic snapshot of the FenceTime that is flattenable.
    //
    // This class is needed because the FenceTime class may not stay
    // consistent for all steps of the flattening process.
    //
    // Not thread safe.
    struct Snapshot : public Flattenable<Snapshot> {
        enum class State {
            EMPTY,
            FENCE,
            SIGNAL_TIME,
        };

        Snapshot() = default;  // Creates an empty snapshot.
        explicit Snapshot(const sp<Fence>& fence);
        explicit Snapshot(nsecs_t signalTime);

        // Movable.
        Snapshot(Snapshot&& src) = default;
        Snapshot& operator=(Snapshot&& src) = default;
        // Not copyable.
        Snapshot(const Snapshot& src) = delete;
        Snapshot& operator=(const Snapshot&& src) = delete;

        // Flattenable implementation.
        size_t getFlattenedSize() const;
        size_t getFdCount() const;
        status_t flatten(void*& buffer, size_t& size, int*& fds,
                size_t& count) const;
        status_t unflatten(void const*& buffer, size_t& size, int const*& fds,
                size_t& count);

        State state{State::EMPTY};
        sp<Fence> fence{Fence::NO_FENCE};
        nsecs_t signalTime{Fence::SIGNAL_TIME_INVALID};
    };

    static const std::shared_ptr<FenceTime> NO_FENCE;

    explicit FenceTime(const sp<Fence>& fence);
    explicit FenceTime(sp<Fence>&& fence);

    // Passing in Fence::SIGNAL_TIME_PENDING is not allowed.
    // Doing so will convert the signalTime to Fence::SIGNAL_TIME_INVALID.
    explicit FenceTime(nsecs_t signalTime);

    // Do not allow default construction. Share NO_FENCE or explicitly construct
    // with Fence::SIGNAL_TIME_INVALID instead.
    FenceTime() = delete;

    // Do not allow copy, assign, or move. Use a shared_ptr to share the
    // signalTime result. Or use getSnapshot() if a thread-safe copy is really
    // needed.
    FenceTime(const FenceTime&) = delete;
    FenceTime(FenceTime&&) = delete;
    FenceTime& operator=(const FenceTime&) = delete;
    FenceTime& operator=(FenceTime&&) = delete;

    // This method should only be called when replacing the fence with
    // a signalTime. Since this is an indirect way of setting the signal time
    // of a fence, the snapshot should come from a trusted source.
    void applyTrustedSnapshot(const Snapshot& src);

    bool isValid() const;

    // Attempts to get the timestamp from the Fence if the timestamp isn't
    // already cached. Otherwise, it returns the cached value.
    nsecs_t getSignalTime();

    // Gets the cached timestamp without attempting to query the Fence.
    nsecs_t getCachedSignalTime() const;

    // Returns a snapshot of the FenceTime in its current state.
    Snapshot getSnapshot() const;

    // Override new and delete since this needs 8-byte alignment, which
    // is not guaranteed on x86.
    static void* operator new(size_t nbytes) noexcept;
    static void operator delete(void *p);

private:
    enum class State {
        VALID,
        INVALID,
    };

    const State mState{State::INVALID};

    // mMutex guards mFence and mSignalTime.
    // mSignalTime is also atomic since it is sometimes read outside the lock
    // for quick checks.
    mutable std::mutex mMutex;
    sp<Fence> mFence{Fence::NO_FENCE};
    std::atomic<nsecs_t> mSignalTime{Fence::SIGNAL_TIME_INVALID};
};

// A queue of FenceTimes that are expected to signal in FIFO order.
// Only maintains a queue of weak pointers so it doesn't keep references
// to Fences on its own.
//
// Can be used to get the signal time of a fence and close its file descriptor
// without making a syscall for every fence later in the timeline.
// Additionally, since the FenceTime caches the timestamp internally,
// other timelines that reference the same FenceTime can avoid the syscall.
//
// FenceTimeline only keeps track of a limited number of entries to avoid
// growing unbounded. Users of FenceTime must make sure they can work even
// if FenceTimeline did nothing. i.e. they should eventually call
// Fence::getSignalTime(), not only Fence::getCachedSignalTime().
//
// push() and updateSignalTimes() are safe to call simultaneously from
// different threads.
class FenceTimeline {
public:
    static constexpr size_t MAX_ENTRIES = 64;

    void push(const std::shared_ptr<FenceTime>& fence);
    void updateSignalTimes();

private:
    mutable std::mutex mMutex;
    std::queue<std::weak_ptr<FenceTime>> mQueue;
};

}; // namespace android

#endif // ANDROID_FENCE_TIME_H
