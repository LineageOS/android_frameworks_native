/*
 * Copyright (C) 2011 The Android Open Source Project
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
#include <android/gui/BnDisplayEventConnection.h>
#include <gui/DisplayEventReceiver.h>
#include <private/gui/BitTube.h>
#include <sys/types.h>
#include <utils/Errors.h>

#include <scheduler/FrameRateMode.h>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include "DisplayHardware/DisplayMode.h"
#include "TracedOrdinal.h"
#include "VSyncDispatch.h"
#include "VsyncSchedule.h"

// ---------------------------------------------------------------------------
namespace android {
// ---------------------------------------------------------------------------

class EventThread;
class EventThreadTest;
class SurfaceFlinger;

namespace frametimeline {
class TokenManager;
} // namespace frametimeline

using gui::ParcelableVsyncEventData;
using gui::VsyncEventData;

// ---------------------------------------------------------------------------

using FrameRateOverride = DisplayEventReceiver::Event::FrameRateOverride;

enum class VSyncRequest {
    None = -2,
    // Single wakes up for the next two frames to avoid scheduler overhead
    Single = -1,
    // SingleSuppressCallback only wakes up for the next frame
    SingleSuppressCallback = 0,
    Periodic = 1,
    // Subsequent values are periods.
};

class EventThreadConnection : public gui::BnDisplayEventConnection {
public:
    EventThreadConnection(EventThread*, uid_t callingUid,
                          EventRegistrationFlags eventRegistration = {});
    virtual ~EventThreadConnection();

    virtual status_t postEvent(const DisplayEventReceiver::Event& event);

    binder::Status stealReceiveChannel(gui::BitTube* outChannel) override;
    binder::Status setVsyncRate(int rate) override;
    binder::Status requestNextVsync() override; // asynchronous
    binder::Status getLatestVsyncEventData(ParcelableVsyncEventData* outVsyncEventData) override;
    binder::Status getSchedulingPolicy(gui::SchedulingPolicy* outPolicy) override;

    VSyncRequest vsyncRequest = VSyncRequest::None;
    const uid_t mOwnerUid;
    const EventRegistrationFlags mEventRegistration;

    /** The frame rate set to the attached choreographer. */
    Fps frameRate;

private:
    virtual void onFirstRef();
    EventThread* const mEventThread;
    std::mutex mLock;
    gui::BitTube mChannel GUARDED_BY(mLock);

    std::vector<DisplayEventReceiver::Event> mPendingEvents;
};

class EventThread {
public:
    virtual ~EventThread();

    virtual sp<EventThreadConnection> createEventConnection(
            EventRegistrationFlags eventRegistration = {}) const = 0;

    // Feed clients with fake VSYNC, e.g. while the display is off.
    virtual void enableSyntheticVsync(bool) = 0;

    virtual void onHotplugReceived(PhysicalDisplayId displayId, bool connected) = 0;

    virtual void onHotplugConnectionError(int32_t connectionError) = 0;

    // called when SF changes the active mode and apps needs to be notified about the change
    virtual void onModeChanged(const scheduler::FrameRateMode&) = 0;

    // called when SF updates the Frame Rate Override list
    virtual void onFrameRateOverridesChanged(PhysicalDisplayId displayId,
                                             std::vector<FrameRateOverride> overrides) = 0;

    virtual void dump(std::string& result) const = 0;

    virtual void setDuration(std::chrono::nanoseconds workDuration,
                             std::chrono::nanoseconds readyDuration) = 0;

    virtual status_t registerDisplayEventConnection(
            const sp<EventThreadConnection>& connection) = 0;
    virtual void setVsyncRate(uint32_t rate, const sp<EventThreadConnection>& connection) = 0;
    // Requests the next vsync. If resetIdleTimer is set to true, it resets the idle timer.
    virtual void requestNextVsync(const sp<EventThreadConnection>& connection) = 0;
    virtual VsyncEventData getLatestVsyncEventData(
            const sp<EventThreadConnection>& connection) const = 0;

    virtual void onNewVsyncSchedule(std::shared_ptr<scheduler::VsyncSchedule>) = 0;

    virtual void onHdcpLevelsChanged(PhysicalDisplayId displayId, int32_t connectedLevel,
                                     int32_t maxLevel) = 0;
};

struct IEventThreadCallback {
    virtual ~IEventThreadCallback() = default;

    virtual bool throttleVsync(TimePoint, uid_t) = 0;
    virtual Period getVsyncPeriod(uid_t) = 0;
    virtual void resync() = 0;
    virtual void onExpectedPresentTimePosted(TimePoint) = 0;
};

namespace impl {

class EventThread : public android::EventThread {
public:
    EventThread(const char* name, std::shared_ptr<scheduler::VsyncSchedule>,
                frametimeline::TokenManager*, IEventThreadCallback& callback,
                std::chrono::nanoseconds workDuration, std::chrono::nanoseconds readyDuration);
    ~EventThread();

    sp<EventThreadConnection> createEventConnection(
            EventRegistrationFlags eventRegistration = {}) const override;

    status_t registerDisplayEventConnection(const sp<EventThreadConnection>& connection) override;
    void setVsyncRate(uint32_t rate, const sp<EventThreadConnection>& connection) override;
    void requestNextVsync(const sp<EventThreadConnection>& connection) override;
    VsyncEventData getLatestVsyncEventData(
            const sp<EventThreadConnection>& connection) const override;

    void enableSyntheticVsync(bool) override;

    void onHotplugReceived(PhysicalDisplayId displayId, bool connected) override;

    void onHotplugConnectionError(int32_t connectionError) override;

    void onModeChanged(const scheduler::FrameRateMode&) override;

    void onFrameRateOverridesChanged(PhysicalDisplayId displayId,
                                     std::vector<FrameRateOverride> overrides) override;

    void dump(std::string& result) const override;

    void setDuration(std::chrono::nanoseconds workDuration,
                     std::chrono::nanoseconds readyDuration) override;

    void onNewVsyncSchedule(std::shared_ptr<scheduler::VsyncSchedule>) override EXCLUDES(mMutex);

    void onHdcpLevelsChanged(PhysicalDisplayId displayId, int32_t connectedLevel,
                             int32_t maxLevel) override;

private:
    friend EventThreadTest;

    using DisplayEventConsumers = std::vector<sp<EventThreadConnection>>;

    void threadMain(std::unique_lock<std::mutex>& lock) REQUIRES(mMutex);

    bool shouldConsumeEvent(const DisplayEventReceiver::Event& event,
                            const sp<EventThreadConnection>& connection) const REQUIRES(mMutex);
    void dispatchEvent(const DisplayEventReceiver::Event& event,
                       const DisplayEventConsumers& consumers) REQUIRES(mMutex);

    void removeDisplayEventConnectionLocked(const wp<EventThreadConnection>& connection)
            REQUIRES(mMutex);

    void onVsync(nsecs_t vsyncTime, nsecs_t wakeupTime, nsecs_t readyTime);

    int64_t generateToken(nsecs_t timestamp, nsecs_t deadlineTimestamp,
                          nsecs_t expectedPresentationTime) const;
    void generateFrameTimeline(VsyncEventData& outVsyncEventData, nsecs_t frameInterval,
                               nsecs_t timestamp, nsecs_t preferredExpectedPresentationTime,
                               nsecs_t preferredDeadlineTimestamp) const;

    scheduler::VSyncDispatch::Callback createDispatchCallback();

    // Returns the old registration so it can be destructed outside the lock to
    // avoid deadlock.
    scheduler::VSyncCallbackRegistration onNewVsyncScheduleInternal(
            std::shared_ptr<scheduler::VsyncSchedule>) EXCLUDES(mMutex);

    const char* const mThreadName;
    TracedOrdinal<int> mVsyncTracer;
    TracedOrdinal<std::chrono::nanoseconds> mWorkDuration GUARDED_BY(mMutex);
    std::chrono::nanoseconds mReadyDuration GUARDED_BY(mMutex);
    std::shared_ptr<scheduler::VsyncSchedule> mVsyncSchedule GUARDED_BY(mMutex);
    TimePoint mLastVsyncCallbackTime GUARDED_BY(mMutex) = TimePoint::now();
    scheduler::VSyncCallbackRegistration mVsyncRegistration GUARDED_BY(mMutex);
    frametimeline::TokenManager* const mTokenManager;

    IEventThreadCallback& mCallback;

    std::thread mThread;
    mutable std::mutex mMutex;
    mutable std::condition_variable mCondition;

    std::vector<wp<EventThreadConnection>> mDisplayEventConnections GUARDED_BY(mMutex);
    std::deque<DisplayEventReceiver::Event> mPendingEvents GUARDED_BY(mMutex);

    // VSYNC state of connected display.
    struct VSyncState {
        explicit VSyncState(PhysicalDisplayId displayId) : displayId(displayId) {}

        const PhysicalDisplayId displayId;

        // Number of VSYNC events since display was connected.
        uint32_t count = 0;

        // True if VSYNC should be faked, e.g. when display is off.
        bool synthetic = false;
    };

    // TODO(b/74619554): Create per-display threads waiting on respective VSYNC signals,
    // and support headless mode by injecting a fake display with synthetic VSYNC.
    std::optional<VSyncState> mVSyncState GUARDED_BY(mMutex);

    // State machine for event loop.
    enum class State {
        Idle,
        Quit,
        SyntheticVSync,
        VSync,
    };

    State mState GUARDED_BY(mMutex) = State::Idle;

    static const char* toCString(State);
};

// ---------------------------------------------------------------------------

} // namespace impl
} // namespace android
