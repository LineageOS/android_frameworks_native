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

// #define LOG_NDEBUG 0
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <gui/Choreographer.h>
#include <gui/TraceUtils.h>
#include <jni.h>

#undef LOG_TAG
#define LOG_TAG "AChoreographer"

namespace {
struct {
    // Global JVM that is provided by zygote
    JavaVM* jvm = nullptr;
    struct {
        jclass clazz;
        jmethodID getInstance;
        jmethodID registerNativeChoreographerForRefreshRateCallbacks;
        jmethodID unregisterNativeChoreographerForRefreshRateCallbacks;
    } displayManagerGlobal;
} gJni;

// Gets the JNIEnv* for this thread, and performs one-off initialization if we
// have never retrieved a JNIEnv* pointer before.
JNIEnv* getJniEnv() {
    if (gJni.jvm == nullptr) {
        ALOGW("AChoreographer: No JVM provided!");
        return nullptr;
    }

    JNIEnv* env = nullptr;
    if (gJni.jvm->GetEnv((void**)&env, JNI_VERSION_1_4) != JNI_OK) {
        ALOGD("Attaching thread to JVM for AChoreographer");
        JavaVMAttachArgs args = {JNI_VERSION_1_4, "AChoreographer_env", NULL};
        jint attachResult = gJni.jvm->AttachCurrentThreadAsDaemon(&env, (void*)&args);
        if (attachResult != JNI_OK) {
            ALOGE("Unable to attach thread. Error: %d", attachResult);
            return nullptr;
        }
    }
    if (env == nullptr) {
        ALOGW("AChoreographer: No JNI env available!");
    }
    return env;
}

inline const char* toString(bool value) {
    return value ? "true" : "false";
}
} // namespace

namespace android {

Choreographer::Context Choreographer::gChoreographers;

static thread_local Choreographer* gChoreographer;

void Choreographer::initJVM(JNIEnv* env) {
    env->GetJavaVM(&gJni.jvm);
    // Now we need to find the java classes.
    jclass dmgClass = env->FindClass("android/hardware/display/DisplayManagerGlobal");
    gJni.displayManagerGlobal.clazz = static_cast<jclass>(env->NewGlobalRef(dmgClass));
    gJni.displayManagerGlobal.getInstance =
            env->GetStaticMethodID(dmgClass, "getInstance",
                                   "()Landroid/hardware/display/DisplayManagerGlobal;");
    gJni.displayManagerGlobal.registerNativeChoreographerForRefreshRateCallbacks =
            env->GetMethodID(dmgClass, "registerNativeChoreographerForRefreshRateCallbacks", "()V");
    gJni.displayManagerGlobal.unregisterNativeChoreographerForRefreshRateCallbacks =
            env->GetMethodID(dmgClass, "unregisterNativeChoreographerForRefreshRateCallbacks",
                             "()V");
}

Choreographer* Choreographer::getForThread() {
    if (gChoreographer == nullptr) {
        sp<Looper> looper = Looper::getForThread();
        if (!looper.get()) {
            ALOGW("No looper prepared for thread");
            return nullptr;
        }
        gChoreographer = new Choreographer(looper);
        status_t result = gChoreographer->initialize();
        if (result != OK) {
            ALOGW("Failed to initialize");
            return nullptr;
        }
    }
    return gChoreographer;
}

Choreographer::Choreographer(const sp<Looper>& looper, const sp<IBinder>& layerHandle)
      : DisplayEventDispatcher(looper, gui::ISurfaceComposer::VsyncSource::eVsyncSourceApp, {},
                               layerHandle),
        mLooper(looper),
        mThreadId(std::this_thread::get_id()) {
    std::lock_guard<std::mutex> _l(gChoreographers.lock);
    gChoreographers.ptrs.push_back(this);
}

Choreographer::~Choreographer() {
    std::lock_guard<std::mutex> _l(gChoreographers.lock);
    gChoreographers.ptrs.erase(std::remove_if(gChoreographers.ptrs.begin(),
                                              gChoreographers.ptrs.end(),
                                              [=, this](Choreographer* c) { return c == this; }),
                               gChoreographers.ptrs.end());
    // Only poke DisplayManagerGlobal to unregister if we previously registered
    // callbacks.
    if (gChoreographers.ptrs.empty() && gChoreographers.registeredToDisplayManager) {
        gChoreographers.registeredToDisplayManager = false;
        JNIEnv* env = getJniEnv();
        if (env == nullptr) {
            ALOGW("JNI environment is unavailable, skipping choreographer cleanup");
            return;
        }
        jobject dmg = env->CallStaticObjectMethod(gJni.displayManagerGlobal.clazz,
                                                  gJni.displayManagerGlobal.getInstance);
        if (dmg == nullptr) {
            ALOGW("DMS is not initialized yet, skipping choreographer cleanup");
        } else {
            env->CallVoidMethod(dmg,
                                gJni.displayManagerGlobal
                                        .unregisterNativeChoreographerForRefreshRateCallbacks);
            env->DeleteLocalRef(dmg);
        }
    }
}

void Choreographer::postFrameCallbackDelayed(AChoreographer_frameCallback cb,
                                             AChoreographer_frameCallback64 cb64,
                                             AChoreographer_vsyncCallback vsyncCallback, void* data,
                                             nsecs_t delay, CallbackType callbackType) {
    nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
    FrameCallback callback{cb, cb64, vsyncCallback, data, now + delay, callbackType};
    {
        std::lock_guard<std::mutex> _l{mLock};
        mFrameCallbacks.push(callback);
    }
    if (callback.dueTime <= now) {
        if (std::this_thread::get_id() != mThreadId) {
            if (mLooper != nullptr) {
                Message m{MSG_SCHEDULE_VSYNC};
                mLooper->sendMessage(this, m);
            } else {
                scheduleVsync();
            }
        } else {
            scheduleVsync();
        }
    } else {
        if (mLooper != nullptr) {
            Message m{MSG_SCHEDULE_CALLBACKS};
            mLooper->sendMessageDelayed(delay, this, m);
        } else {
            scheduleCallbacks();
        }
    }
}

void Choreographer::registerRefreshRateCallback(AChoreographer_refreshRateCallback cb, void* data) {
    std::lock_guard<std::mutex> _l{mLock};
    for (const auto& callback : mRefreshRateCallbacks) {
        // Don't re-add callbacks.
        if (cb == callback.callback && data == callback.data) {
            return;
        }
    }
    mRefreshRateCallbacks.emplace_back(
            RefreshRateCallback{.callback = cb, .data = data, .firstCallbackFired = false});
    bool needsRegistration = false;
    {
        std::lock_guard<std::mutex> _l2(gChoreographers.lock);
        needsRegistration = !gChoreographers.registeredToDisplayManager;
    }
    if (needsRegistration) {
        JNIEnv* env = getJniEnv();
        if (env == nullptr) {
            ALOGW("JNI environment is unavailable, skipping registration");
            return;
        }
        jobject dmg = env->CallStaticObjectMethod(gJni.displayManagerGlobal.clazz,
                                                  gJni.displayManagerGlobal.getInstance);
        if (dmg == nullptr) {
            ALOGW("DMS is not initialized yet: skipping registration");
            return;
        } else {
            env->CallVoidMethod(dmg,
                                gJni.displayManagerGlobal
                                        .registerNativeChoreographerForRefreshRateCallbacks,
                                reinterpret_cast<int64_t>(this));
            env->DeleteLocalRef(dmg);
            {
                std::lock_guard<std::mutex> _l2(gChoreographers.lock);
                gChoreographers.registeredToDisplayManager = true;
            }
        }
    } else {
        scheduleLatestConfigRequest();
    }
}

void Choreographer::unregisterRefreshRateCallback(AChoreographer_refreshRateCallback cb,
                                                  void* data) {
    std::lock_guard<std::mutex> _l{mLock};
    mRefreshRateCallbacks.erase(std::remove_if(mRefreshRateCallbacks.begin(),
                                               mRefreshRateCallbacks.end(),
                                               [&](const RefreshRateCallback& callback) {
                                                   return cb == callback.callback &&
                                                           data == callback.data;
                                               }),
                                mRefreshRateCallbacks.end());
}

void Choreographer::scheduleLatestConfigRequest() {
    if (mLooper != nullptr) {
        Message m{MSG_HANDLE_REFRESH_RATE_UPDATES};
        mLooper->sendMessage(this, m);
    } else {
        // If the looper thread is detached from Choreographer, then refresh rate
        // changes will be handled in AChoreographer_handlePendingEvents, so we
        // need to wake up the looper thread by writing to the write-end of the
        // socket the looper is listening on.
        // Fortunately, these events are small so sending packets across the
        // socket should be atomic across processes.
        DisplayEventReceiver::Event event;
        event.header =
                DisplayEventReceiver::Event::Header{DisplayEventReceiver::DISPLAY_EVENT_NULL,
                                                    PhysicalDisplayId::fromPort(0), systemTime()};
        injectEvent(event);
    }
}

void Choreographer::scheduleCallbacks() {
    const nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
    nsecs_t dueTime;
    {
        std::lock_guard<std::mutex> _l{mLock};
        // If there are no pending callbacks then don't schedule a vsync
        if (mFrameCallbacks.empty()) {
            return;
        }
        dueTime = mFrameCallbacks.top().dueTime;
    }

    if (dueTime <= now) {
        ALOGV("choreographer %p ~ scheduling vsync", this);
        scheduleVsync();
        return;
    }
}

void Choreographer::handleRefreshRateUpdates() {
    std::vector<RefreshRateCallback> callbacks{};
    const nsecs_t pendingPeriod = gChoreographers.mLastKnownVsync.load();
    const nsecs_t lastPeriod = mLatestVsyncPeriod;
    if (pendingPeriod > 0) {
        mLatestVsyncPeriod = pendingPeriod;
    }
    {
        std::lock_guard<std::mutex> _l{mLock};
        for (auto& cb : mRefreshRateCallbacks) {
            callbacks.push_back(cb);
            cb.firstCallbackFired = true;
        }
    }

    for (auto& cb : callbacks) {
        if (!cb.firstCallbackFired || (pendingPeriod > 0 && pendingPeriod != lastPeriod)) {
            cb.callback(pendingPeriod, cb.data);
        }
    }
}

void Choreographer::dispatchCallbacks(const std::vector<FrameCallback>& callbacks,
                                      VsyncEventData vsyncEventData, nsecs_t timestamp) {
    for (const auto& cb : callbacks) {
        if (cb.vsyncCallback != nullptr) {
            ATRACE_FORMAT("AChoreographer_vsyncCallback %" PRId64,
                          vsyncEventData.preferredVsyncId());
            const ChoreographerFrameCallbackDataImpl frameCallbackData =
                    createFrameCallbackData(timestamp);
            registerStartTime();
            mInCallback = true;
            cb.vsyncCallback(reinterpret_cast<const AChoreographerFrameCallbackData*>(
                                     &frameCallbackData),
                             cb.data);
            mInCallback = false;
        } else if (cb.callback64 != nullptr) {
            ATRACE_FORMAT("AChoreographer_frameCallback64");
            cb.callback64(timestamp, cb.data);
        } else if (cb.callback != nullptr) {
            ATRACE_FORMAT("AChoreographer_frameCallback");
            cb.callback(timestamp, cb.data);
        }
    }
}

void Choreographer::dispatchVsync(nsecs_t timestamp, PhysicalDisplayId, uint32_t,
                                  VsyncEventData vsyncEventData) {
    std::vector<FrameCallback> animationCallbacks{};
    std::vector<FrameCallback> inputCallbacks{};
    {
        std::lock_guard<std::mutex> _l{mLock};
        nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
        while (!mFrameCallbacks.empty() && mFrameCallbacks.top().dueTime < now) {
            if (mFrameCallbacks.top().callbackType == CALLBACK_INPUT) {
                inputCallbacks.push_back(mFrameCallbacks.top());
            } else {
                animationCallbacks.push_back(mFrameCallbacks.top());
            }
            mFrameCallbacks.pop();
        }
    }
    mLastVsyncEventData = vsyncEventData;
    // Callbacks with type CALLBACK_INPUT should always run first
    {
        ATRACE_FORMAT("CALLBACK_INPUT");
        dispatchCallbacks(inputCallbacks, vsyncEventData, timestamp);
    }
    {
        ATRACE_FORMAT("CALLBACK_ANIMATION");
        dispatchCallbacks(animationCallbacks, vsyncEventData, timestamp);
    }
}

void Choreographer::dispatchHotplug(nsecs_t, PhysicalDisplayId displayId, bool connected) {
    ALOGV("choreographer %p ~ received hotplug event (displayId=%s, connected=%s), ignoring.", this,
          to_string(displayId).c_str(), toString(connected));
}

void Choreographer::dispatchHotplugConnectionError(nsecs_t, int32_t connectionError) {
    ALOGV("choreographer %p ~ received hotplug connection error event (connectionError=%d), "
          "ignoring.",
          this, connectionError);
}

void Choreographer::dispatchModeChanged(nsecs_t, PhysicalDisplayId, int32_t, nsecs_t) {
    LOG_ALWAYS_FATAL("dispatchModeChanged was called but was never registered");
}

void Choreographer::dispatchFrameRateOverrides(nsecs_t, PhysicalDisplayId,
                                               std::vector<FrameRateOverride>) {
    LOG_ALWAYS_FATAL("dispatchFrameRateOverrides was called but was never registered");
}

void Choreographer::dispatchNullEvent(nsecs_t, PhysicalDisplayId) {
    ALOGV("choreographer %p ~ received null event.", this);
    handleRefreshRateUpdates();
}

void Choreographer::dispatchHdcpLevelsChanged(PhysicalDisplayId displayId, int32_t connectedLevel,
                                              int32_t maxLevel) {
    ALOGV("choreographer %p ~ received hdcp levels change event (displayId=%s, connectedLevel=%d, "
          "maxLevel=%d), ignoring.",
          this, to_string(displayId).c_str(), connectedLevel, maxLevel);
}

void Choreographer::handleMessage(const Message& message) {
    switch (message.what) {
        case MSG_SCHEDULE_CALLBACKS:
            scheduleCallbacks();
            break;
        case MSG_SCHEDULE_VSYNC:
            scheduleVsync();
            break;
        case MSG_HANDLE_REFRESH_RATE_UPDATES:
            handleRefreshRateUpdates();
            break;
    }
}

int64_t Choreographer::getFrameInterval() const {
    return mLastVsyncEventData.frameInterval;
}

bool Choreographer::inCallback() const {
    return mInCallback;
}

ChoreographerFrameCallbackDataImpl Choreographer::createFrameCallbackData(nsecs_t timestamp) const {
    return {.frameTimeNanos = timestamp,
            .vsyncEventData = mLastVsyncEventData,
            .choreographer = this};
}

void Choreographer::registerStartTime() const {
    std::scoped_lock _l(gChoreographers.lock);
    for (VsyncEventData::FrameTimeline frameTimeline : mLastVsyncEventData.frameTimelines) {
        while (gChoreographers.startTimes.size() >= kMaxStartTimes) {
            gChoreographers.startTimes.erase(gChoreographers.startTimes.begin());
        }
        gChoreographers.startTimes[frameTimeline.vsyncId] = systemTime(SYSTEM_TIME_MONOTONIC);
    }
}

void Choreographer::signalRefreshRateCallbacks(nsecs_t vsyncPeriod) {
    std::lock_guard<std::mutex> _l(gChoreographers.lock);
    gChoreographers.mLastKnownVsync.store(vsyncPeriod);
    for (auto c : gChoreographers.ptrs) {
        c->scheduleLatestConfigRequest();
    }
}

int64_t Choreographer::getStartTimeNanosForVsyncId(AVsyncId vsyncId) {
    std::scoped_lock _l(gChoreographers.lock);
    const auto iter = gChoreographers.startTimes.find(vsyncId);
    if (iter == gChoreographers.startTimes.end()) {
        ALOGW("Start time was not found for vsync id: %" PRId64, vsyncId);
        return 0;
    }
    return iter->second;
}

const sp<Looper> Choreographer::getLooper() {
    return mLooper;
}

} // namespace android
