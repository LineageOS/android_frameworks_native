/*
 * Copyright (C) 2017 The Android Open Source Project
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

// LOG_TAG defined via build flag.
#ifndef LOG_TAG
#define LOG_TAG "HidlSensorManager"
#endif
#include <android-base/logging.h>

#include "SensorManager.h"

#include <sched.h>

#include <thread>

#include "EventQueue.h"
#include "DirectReportChannel.h"
#include "utils.h"

namespace android {
namespace frameworks {
namespace sensorservice {
namespace V1_0 {
namespace implementation {

using ::android::hardware::sensors::V1_0::SensorInfo;
using ::android::hardware::sensors::V1_0::SensorsEventFormatOffset;
using ::android::hardware::hidl_vec;
using ::android::hardware::Void;
using ::android::sp;

static const char* POLL_THREAD_NAME = "hidl_ssvc_poll";

SensorManager::SensorManager(JavaVM* vm)
        : mJavaVm(vm) {
}

SensorManager::~SensorManager() {
    // Stops pollAll inside the thread.
    std::unique_lock<std::mutex> lock(mLooperMutex);
    if (mLooper != nullptr) {
        mLooper->wake();
    }
}

// Methods from ::android::frameworks::sensorservice::V1_0::ISensorManager follow.
Return<void> SensorManager::getSensorList(getSensorList_cb _hidl_cb) {
    ::android::Sensor const* const* list;
    ssize_t count = getInternalManager().getSensorList(&list);
    if (count < 0 || !list) {
        LOG(ERROR) << "::android::SensorManager::getSensorList encounters " << count;
        _hidl_cb({}, Result::UNKNOWN_ERROR);
        return Void();
    }
    hidl_vec<SensorInfo> ret;
    ret.resize(static_cast<size_t>(count));
    for (ssize_t i = 0; i < count; ++i) {
        ret[i] = convertSensor(*list[i]);
    }
    _hidl_cb(ret, Result::OK);
    return Void();
}

Return<void> SensorManager::getDefaultSensor(SensorType type, getDefaultSensor_cb _hidl_cb) {
    ::android::Sensor const* sensor = getInternalManager().getDefaultSensor(static_cast<int>(type));
    if (!sensor) {
        _hidl_cb({}, Result::NOT_EXIST);
        return Void();
    }
    _hidl_cb(convertSensor(*sensor), Result::OK);
    return Void();
}

template<typename Callback>
void createDirectChannel(::android::SensorManager& manager, size_t size, int type,
        const native_handle_t* handle, const Callback& _hidl_cb) {

    int channelId = manager.createDirectChannel(
        size, type, handle);
    if (channelId < 0) {
        _hidl_cb(nullptr, convertResult(channelId));
        return;
    }
    if (channelId == 0) {
        _hidl_cb(nullptr, Result::UNKNOWN_ERROR);
        return;
    }

    _hidl_cb(sp<IDirectReportChannel>(new DirectReportChannel(manager, channelId)),
            Result::OK);
}

Return<void> SensorManager::createAshmemDirectChannel(
        const hidl_memory& mem, uint64_t size,
        createAshmemDirectChannel_cb _hidl_cb) {
    if (size > mem.size() || size < (uint64_t)SensorsEventFormatOffset::TOTAL_LENGTH) {
        _hidl_cb(nullptr, Result::BAD_VALUE);
        return Void();
    }

    createDirectChannel(getInternalManager(), size, SENSOR_DIRECT_MEM_TYPE_ASHMEM,
            mem.handle(), _hidl_cb);

    return Void();
}

Return<void> SensorManager::createGrallocDirectChannel(
        const hidl_handle& buffer, uint64_t size,
        createGrallocDirectChannel_cb _hidl_cb) {

    createDirectChannel(getInternalManager(), size, SENSOR_DIRECT_MEM_TYPE_GRALLOC,
            buffer.getNativeHandle(), _hidl_cb);

    return Void();
}

/* One global looper for all event queues created from this SensorManager. */
sp<::android::Looper> SensorManager::getLooper() {
    std::unique_lock<std::mutex> lock(mLooperMutex);
    if (mLooper == nullptr) {
        std::condition_variable looperSet;

        std::thread{[&mutex = mLooperMutex, &looper = mLooper, &looperSet, javaVm = mJavaVm] {

            struct sched_param p = {0};
            p.sched_priority = 10;
            if (sched_setscheduler(0 /* current thread*/, SCHED_FIFO, &p) != 0) {
                LOG(WARNING) << "Could not use SCHED_FIFO for looper thread: "
                        << strerror(errno);
            }

            std::unique_lock<std::mutex> lock(mutex);
            if (looper != nullptr) {
                LOG(INFO) << "Another thread has already set the looper, exiting this one.";
                return;
            }
            looper = Looper::prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS /* opts */);
            lock.unlock();

            // Attach the thread to JavaVM so that pollAll do not crash if the event
            // is from Java.
            JavaVMAttachArgs args{
                .version = JNI_VERSION_1_2,
                .name = POLL_THREAD_NAME,
                .group = NULL
            };
            JNIEnv* env;
            if (javaVm->AttachCurrentThread(&env, &args) != JNI_OK) {
                LOG(FATAL) << "Cannot attach SensorManager looper thread to Java VM.";
            }

            looperSet.notify_one();
            int pollResult = looper->pollAll(-1 /* timeout */);
            if (pollResult != ALOOPER_POLL_WAKE) {
                LOG(ERROR) << "Looper::pollAll returns unexpected " << pollResult;
            }

            if (javaVm->DetachCurrentThread() != JNI_OK) {
                LOG(ERROR) << "Cannot detach SensorManager looper thread from Java VM.";
            }

            LOG(INFO) << "Looper thread is terminated.";
        }}.detach();
        looperSet.wait(lock, [this]{ return this->mLooper != nullptr; });
    }
    return mLooper;
}

::android::SensorManager& SensorManager::getInternalManager() {
    std::lock_guard<std::mutex> lock(mInternalManagerMutex);
    if (mInternalManager == nullptr) {
        mInternalManager = &::android::SensorManager::getInstanceForPackage(
                String16(ISensorManager::descriptor));
    }
    return *mInternalManager;
}

Return<void> SensorManager::createEventQueue(
        const sp<IEventQueueCallback> &callback, createEventQueue_cb _hidl_cb) {
    if (callback == nullptr) {
        _hidl_cb(nullptr, Result::BAD_VALUE);
        return Void();
    }

    sp<::android::Looper> looper = getLooper();
    sp<::android::SensorEventQueue> internalQueue = getInternalManager().createEventQueue();
    if (internalQueue == nullptr) {
        LOG(WARNING) << "::android::SensorManager::createEventQueue returns nullptr.";
        _hidl_cb(nullptr, Result::UNKNOWN_ERROR);
        return Void();
    }

    sp<IEventQueue> queue = new EventQueue(callback, looper, internalQueue);
    _hidl_cb(queue, Result::OK);

    return Void();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace sensorservice
}  // namespace frameworks
}  // namespace android
