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

SensorManager::SensorManager()
        : mInternalManager{::android::SensorManager::getInstanceForPackage(
            String16(ISensorManager::descriptor))} {
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
    ssize_t count = mInternalManager.getSensorList(&list);
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
    ::android::Sensor const* sensor = mInternalManager.getDefaultSensor(static_cast<int>(type));
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

    createDirectChannel(mInternalManager, size, SENSOR_DIRECT_MEM_TYPE_ASHMEM,
            mem.handle(), _hidl_cb);

    return Void();
}

Return<void> SensorManager::createGrallocDirectChannel(
        const hidl_handle& buffer, uint64_t size,
        createGrallocDirectChannel_cb _hidl_cb) {

    createDirectChannel(mInternalManager, size, SENSOR_DIRECT_MEM_TYPE_GRALLOC,
            buffer.getNativeHandle(), _hidl_cb);

    return Void();
}

/* One global looper for all event queues created from this SensorManager. */
sp<::android::Looper> SensorManager::getLooper() {
    std::unique_lock<std::mutex> lock(mLooperMutex);
    if (mLooper == nullptr) {
        std::condition_variable looperSet;

        std::thread{[&mutex = mLooperMutex, &looper = mLooper, &looperSet] {

            struct sched_param p = {0};
            p.sched_priority = 10;
            if (sched_setscheduler(0 /* current thread*/, SCHED_FIFO, &p) != 0) {
                LOG(WARNING) << "Could not use SCHED_FIFO for looper thread: "
                        << strerror(errno);
            }

            std::unique_lock<std::mutex> lock(mutex);
            looper = Looper::prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS /* opts */);
            lock.unlock();

            looperSet.notify_one();
            int pollResult = looper->pollAll(-1 /* timeout */);
            if (pollResult != ALOOPER_POLL_WAKE) {
                LOG(ERROR) << "Looper::pollAll returns unexpected " << pollResult;
            }
            LOG(INFO) << "Looper thread is terminated.";
        }}.detach();
        looperSet.wait(lock, [this]{ return this->mLooper != nullptr; });
    }
    return mLooper;
}

Return<void> SensorManager::createEventQueue(
        const sp<IEventQueueCallback> &callback, createEventQueue_cb _hidl_cb) {
    if (callback == nullptr) {
        _hidl_cb(nullptr, Result::BAD_VALUE);
        return Void();
    }

    sp<::android::Looper> looper = getLooper();
    sp<::android::SensorEventQueue> internalQueue = mInternalManager.createEventQueue();
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
