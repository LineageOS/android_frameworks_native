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

#include "DirectReportChannel.h"
#include "SensorManager.h"
#include "utils.h"

namespace android {
namespace frameworks {
namespace sensorservice {
namespace V1_0 {
namespace implementation {

using ::android::frameworks::sensorservice::V1_0::IDirectReportChannel;
using ::android::hardware::sensors::V1_0::SensorInfo;
using ::android::hardware::hidl_vec;
using ::android::hardware::Void;
using ::android::sp;

SensorManager::SensorManager()
        : mManager{::android::SensorManager::getInstanceForPackage(
            String16(ISensorManager::descriptor))} {
}

// Methods from ::android::frameworks::sensorservice::V1_0::ISensorManager follow.
Return<void> SensorManager::getSensorList(getSensorList_cb _hidl_cb) {
    ::android::Sensor const* const* list;
    ssize_t count = mManager.getSensorList(&list);
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
    ::android::Sensor const* sensor = mManager.getDefaultSensor(static_cast<int>(type));
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
    if (size > mem.size()) {
        _hidl_cb(nullptr, Result::BAD_VALUE);
        return Void();
    }

    createDirectChannel(mManager, size, SENSOR_DIRECT_MEM_TYPE_ASHMEM,
            mem.handle(), _hidl_cb);

    return Void();
}

Return<void> SensorManager::createGrallocDirectChannel(
        const hidl_handle& buffer, uint64_t size,
        createGrallocDirectChannel_cb _hidl_cb) {

    createDirectChannel(mManager, size, SENSOR_DIRECT_MEM_TYPE_GRALLOC,
            buffer.getNativeHandle(), _hidl_cb);

    return Void();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace sensorservice
}  // namespace frameworks
}  // namespace android
