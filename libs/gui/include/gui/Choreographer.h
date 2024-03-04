/*
 * Copyright 2022 The Android Open Source Project
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

#include <android/choreographer.h>
#include <gui/DisplayEventDispatcher.h>
#include <jni.h>
#include <utils/Looper.h>

#include <mutex>
#include <queue>
#include <thread>

namespace android {
using gui::VsyncEventData;

enum CallbackType : int8_t {
    CALLBACK_INPUT,
    CALLBACK_ANIMATION,
};

struct FrameCallback {
    AChoreographer_frameCallback callback;
    AChoreographer_frameCallback64 callback64;
    AChoreographer_vsyncCallback vsyncCallback;
    void* data;
    nsecs_t dueTime;
    CallbackType callbackType;

    inline bool operator<(const FrameCallback& rhs) const {
        // Note that this is intentionally flipped because we want callbacks due sooner to be at
        // the head of the queue
        return dueTime > rhs.dueTime;
    }
};

struct RefreshRateCallback {
    AChoreographer_refreshRateCallback callback;
    void* data;
    bool firstCallbackFired = false;
};

class Choreographer;

/**
 * Implementation of AChoreographerFrameCallbackData.
 */
struct ChoreographerFrameCallbackDataImpl {
    int64_t frameTimeNanos{0};

    VsyncEventData vsyncEventData;

    const Choreographer* choreographer;
};

class Choreographer : public DisplayEventDispatcher, public MessageHandler {
public:
    struct Context {
        std::mutex lock;
        std::vector<Choreographer*> ptrs GUARDED_BY(lock);
        std::map<AVsyncId, int64_t> startTimes GUARDED_BY(lock);
        bool registeredToDisplayManager GUARDED_BY(lock) = false;

        std::atomic<nsecs_t> mLastKnownVsync = -1;
    };
    static Context gChoreographers;

    explicit Choreographer(const sp<Looper>& looper, const sp<IBinder>& layerHandle = nullptr)
            EXCLUDES(gChoreographers.lock);
    void postFrameCallbackDelayed(AChoreographer_frameCallback cb,
                                  AChoreographer_frameCallback64 cb64,
                                  AChoreographer_vsyncCallback vsyncCallback, void* data,
                                  nsecs_t delay, CallbackType callbackType);
    void registerRefreshRateCallback(AChoreographer_refreshRateCallback cb, void* data)
            EXCLUDES(gChoreographers.lock);
    void unregisterRefreshRateCallback(AChoreographer_refreshRateCallback cb, void* data);
    // Drains the queue of pending vsync periods and dispatches refresh rate
    // updates to callbacks.
    // The assumption is that this method is only called on a single
    // processing thread, either by looper or by AChoreographer_handleEvents
    void handleRefreshRateUpdates();
    void scheduleLatestConfigRequest();

    enum {
        MSG_SCHEDULE_CALLBACKS = 0,
        MSG_SCHEDULE_VSYNC = 1,
        MSG_HANDLE_REFRESH_RATE_UPDATES = 2,
    };
    virtual void handleMessage(const Message& message) override;

    static void initJVM(JNIEnv* env);
    static Choreographer* getForThread();
    static void signalRefreshRateCallbacks(nsecs_t vsyncPeriod) EXCLUDES(gChoreographers.lock);
    static int64_t getStartTimeNanosForVsyncId(AVsyncId vsyncId) EXCLUDES(gChoreographers.lock);
    virtual ~Choreographer() override EXCLUDES(gChoreographers.lock);
    int64_t getFrameInterval() const;
    bool inCallback() const;
    const sp<Looper> getLooper();

private:
    Choreographer(const Choreographer&) = delete;

    void dispatchVsync(nsecs_t timestamp, PhysicalDisplayId displayId, uint32_t count,
                       VsyncEventData vsyncEventData) override;
    void dispatchCallbacks(const std::vector<FrameCallback>&, VsyncEventData vsyncEventData,
                           nsecs_t timestamp);
    void dispatchHotplug(nsecs_t timestamp, PhysicalDisplayId displayId, bool connected) override;
    void dispatchHotplugConnectionError(nsecs_t timestamp, int32_t connectionError) override;
    void dispatchModeChanged(nsecs_t timestamp, PhysicalDisplayId displayId, int32_t modeId,
                             nsecs_t vsyncPeriod) override;
    void dispatchNullEvent(nsecs_t, PhysicalDisplayId) override;
    void dispatchFrameRateOverrides(nsecs_t timestamp, PhysicalDisplayId displayId,
                                    std::vector<FrameRateOverride> overrides) override;
    void dispatchHdcpLevelsChanged(PhysicalDisplayId displayId, int32_t connectedLevel,
                                   int32_t maxLevel) override;

    void scheduleCallbacks();

    ChoreographerFrameCallbackDataImpl createFrameCallbackData(nsecs_t timestamp) const;
    void registerStartTime() const;

    std::mutex mLock;
    // Protected by mLock
    std::priority_queue<FrameCallback> mFrameCallbacks;
    std::vector<RefreshRateCallback> mRefreshRateCallbacks;

    nsecs_t mLatestVsyncPeriod = -1;
    VsyncEventData mLastVsyncEventData;
    bool mInCallback = false;

    const sp<Looper> mLooper;
    const std::thread::id mThreadId;

    // Approximation of num_threads_using_choreographer * num_frames_of_history with leeway.
    static constexpr size_t kMaxStartTimes = 250;
};

} // namespace android
