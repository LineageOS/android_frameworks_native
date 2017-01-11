/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <sys/types.h>

#include <android-base/logging.h>
#include <utils/Atomic.h>
#include <utils/Errors.h>
#include <utils/Singleton.h>

#include "SensorDevice.h"
#include "SensorService.h"

#include <sensors/convert.h>

using android::hardware::sensors::V1_0::ISensors;
using android::hardware::hidl_vec;

using Event = android::hardware::sensors::V1_0::Event;
using SensorInfo = android::hardware::sensors::V1_0::SensorInfo;
using SensorType = android::hardware::sensors::V1_0::SensorType;
using DynamicSensorInfo = android::hardware::sensors::V1_0::DynamicSensorInfo;
using SensorInfo = android::hardware::sensors::V1_0::SensorInfo;
using Result = android::hardware::sensors::V1_0::Result;

using namespace android::hardware::sensors::V1_0::implementation;

namespace android {
// ---------------------------------------------------------------------------

ANDROID_SINGLETON_STATIC_INSTANCE(SensorDevice)

static status_t StatusFromResult(Result result) {
    switch (result) {
        case Result::OK:
            return OK;
        case Result::BAD_VALUE:
            return BAD_VALUE;
        case Result::PERMISSION_DENIED:
            return PERMISSION_DENIED;
        case Result::INVALID_OPERATION:
            return INVALID_OPERATION;
        case Result::NO_MEMORY:
            return NO_MEMORY;
    }
}

SensorDevice::SensorDevice() {
    mSensors = ISensors::getService("sensors");

    if (mSensors == NULL) {
        return;
    }

    mSensors->getSensorsList(
            [&](const auto &list) {
                const size_t count = list.size();

                mActivationCount.setCapacity(count);
                Info model;
                for (size_t i=0 ; i < count; i++) {
                    sensor_t sensor;
                    convertToSensor(list[i], &sensor);
                    mSensorList.push_back(sensor);

                    mActivationCount.add(list[i].sensorHandle, model);

                    /* auto result = */mSensors->activate(
                        list[i].sensorHandle, 0 /* enabled */);
                }
            });
}

void SensorDevice::handleDynamicSensorConnection(int handle, bool connected) {
    if (connected) {
        Info model;
        mActivationCount.add(handle, model);
        /* auto result = */mSensors->activate(handle, 0 /* enabled */);
    } else {
        mActivationCount.removeItem(handle);
    }
}

std::string SensorDevice::dump() const {
    if (mSensors == NULL) return "HAL not initialized\n";

#if 0
    result.appendFormat("HAL: %s (%s), version %#010x\n",
                        mSensorModule->common.name,
                        mSensorModule->common.author,
                        getHalDeviceVersion());
#endif

    String8 result;
    mSensors->getSensorsList([&](const auto &list) {
            const size_t count = list.size();

            result.appendFormat(
                "Total %zu h/w sensors, %zu running:\n",
                count,
                mActivationCount.size());

            Mutex::Autolock _l(mLock);
            for (size_t i = 0 ; i < count ; i++) {
                const Info& info = mActivationCount.valueFor(
                    list[i].sensorHandle);

                if (info.batchParams.isEmpty()) continue;
                result.appendFormat(
                    "0x%08x) active-count = %zu; ",
                    list[i].sensorHandle,
                    info.batchParams.size());

                result.append("sampling_period(ms) = {");
                for (size_t j = 0; j < info.batchParams.size(); j++) {
                    const BatchParams& params = info.batchParams.valueAt(j);
                    result.appendFormat(
                        "%.1f%s",
                        params.batchDelay / 1e6f,
                        j < info.batchParams.size() - 1 ? ", " : "");
                }
                result.appendFormat(
                        "}, selected = %.1f ms; ",
                        info.bestBatchParams.batchDelay / 1e6f);

                result.append("batching_period(ms) = {");
                for (size_t j = 0; j < info.batchParams.size(); j++) {
                    BatchParams params = info.batchParams.valueAt(j);

                    result.appendFormat(
                            "%.1f%s",
                            params.batchTimeout / 1e6f,
                            j < info.batchParams.size() - 1 ? ", " : "");
                }

                result.appendFormat(
                        "}, selected = %.1f ms\n",
                        info.bestBatchParams.batchTimeout / 1e6f);
            }
        });

    return result.string();
}

ssize_t SensorDevice::getSensorList(sensor_t const** list) {
    *list = &mSensorList[0];

    return mSensorList.size();
}

status_t SensorDevice::initCheck() const {
    return mSensors != NULL ? NO_ERROR : NO_INIT;
}

ssize_t SensorDevice::poll(sensors_event_t* buffer, size_t count) {
    if (mSensors == NULL) return NO_INIT;

    ssize_t err;

    mSensors->poll(
            count,
            [&](auto result,
                const auto &events,
                const auto &dynamicSensorsAdded) {
                if (result == Result::OK) {
                    convertToSensorEvents(events, dynamicSensorsAdded, buffer);
                    err = (ssize_t)events.size();
                } else {
                    err = StatusFromResult(result);
                }
            });

    return err;
}

void SensorDevice::autoDisable(void *ident, int handle) {
    Info& info( mActivationCount.editValueFor(handle) );
    Mutex::Autolock _l(mLock);
    info.removeBatchParamsForIdent(ident);
}

status_t SensorDevice::activate(void* ident, int handle, int enabled) {
    if (mSensors == NULL) return NO_INIT;

    status_t err(NO_ERROR);
    bool actuateHardware = false;

    Mutex::Autolock _l(mLock);
    Info& info( mActivationCount.editValueFor(handle) );

    ALOGD_IF(DEBUG_CONNECTIONS,
             "SensorDevice::activate: ident=%p, handle=0x%08x, enabled=%d, count=%zu",
             ident, handle, enabled, info.batchParams.size());

    if (enabled) {
        ALOGD_IF(DEBUG_CONNECTIONS, "enable index=%zd", info.batchParams.indexOfKey(ident));

        if (isClientDisabledLocked(ident)) {
            ALOGE("SensorDevice::activate, isClientDisabledLocked(%p):true, handle:%d",
                    ident, handle);
            return INVALID_OPERATION;
        }

        if (info.batchParams.indexOfKey(ident) >= 0) {
          if (info.numActiveClients() == 1) {
              // This is the first connection, we need to activate the underlying h/w sensor.
              actuateHardware = true;
          }
        } else {
            // Log error. Every activate call should be preceded by a batch() call.
            ALOGE("\t >>>ERROR: activate called without batch");
        }
    } else {
        ALOGD_IF(DEBUG_CONNECTIONS, "disable index=%zd", info.batchParams.indexOfKey(ident));

        // If a connected dynamic sensor is deactivated, remove it from the
        // dictionary.
        auto it = mConnectedDynamicSensors.find(handle);
        if (it != mConnectedDynamicSensors.end()) {
            delete it->second;
            mConnectedDynamicSensors.erase(it);
        }

        if (info.removeBatchParamsForIdent(ident) >= 0) {
            if (info.numActiveClients() == 0) {
                // This is the last connection, we need to de-activate the underlying h/w sensor.
                actuateHardware = true;
            } else {
                const int halVersion = getHalDeviceVersion();
                if (halVersion >= SENSORS_DEVICE_API_VERSION_1_1) {
                    // Call batch for this sensor with the previously calculated best effort
                    // batch_rate and timeout. One of the apps has unregistered for sensor
                    // events, and the best effort batch parameters might have changed.
                    ALOGD_IF(DEBUG_CONNECTIONS,
                             "\t>>> actuating h/w batch %d %d %" PRId64 " %" PRId64, handle,
                             info.bestBatchParams.flags, info.bestBatchParams.batchDelay,
                             info.bestBatchParams.batchTimeout);
                    /* auto result = */mSensors->batch(
                            handle,
                            info.bestBatchParams.flags,
                            info.bestBatchParams.batchDelay,
                            info.bestBatchParams.batchTimeout);
                }
            }
        } else {
            // sensor wasn't enabled for this ident
        }

        if (isClientDisabledLocked(ident)) {
            return NO_ERROR;
        }
    }

    if (actuateHardware) {
        ALOGD_IF(DEBUG_CONNECTIONS, "\t>>> actuating h/w activate handle=%d enabled=%d", handle,
                 enabled);
        err = StatusFromResult(mSensors->activate(handle, enabled));
        ALOGE_IF(err, "Error %s sensor %d (%s)", enabled ? "activating" : "disabling", handle,
                 strerror(-err));

        if (err != NO_ERROR && enabled) {
            // Failure when enabling the sensor. Clean up on failure.
            info.removeBatchParamsForIdent(ident);
        }
    }

    // On older devices which do not support batch, call setDelay().
    if (getHalDeviceVersion() < SENSORS_DEVICE_API_VERSION_1_1 && info.numActiveClients() > 0) {
        ALOGD_IF(DEBUG_CONNECTIONS, "\t>>> actuating h/w setDelay %d %" PRId64, handle,
                 info.bestBatchParams.batchDelay);
        /* auto result = */mSensors->setDelay(
                handle, info.bestBatchParams.batchDelay);
    }
    return err;
}

status_t SensorDevice::batch(
        void* ident,
        int handle,
        int flags,
        int64_t samplingPeriodNs,
        int64_t maxBatchReportLatencyNs) {
    if (mSensors == NULL) return NO_INIT;

    if (samplingPeriodNs < MINIMUM_EVENTS_PERIOD) {
        samplingPeriodNs = MINIMUM_EVENTS_PERIOD;
    }

    const int halVersion = getHalDeviceVersion();
    if (halVersion < SENSORS_DEVICE_API_VERSION_1_1 && maxBatchReportLatencyNs != 0) {
        // Batch is not supported on older devices return invalid operation.
        return INVALID_OPERATION;
    }

    ALOGD_IF(DEBUG_CONNECTIONS,
             "SensorDevice::batch: ident=%p, handle=0x%08x, flags=%d, period_ns=%" PRId64 " timeout=%" PRId64,
             ident, handle, flags, samplingPeriodNs, maxBatchReportLatencyNs);

    Mutex::Autolock _l(mLock);
    Info& info(mActivationCount.editValueFor(handle));

    if (info.batchParams.indexOfKey(ident) < 0) {
        BatchParams params(flags, samplingPeriodNs, maxBatchReportLatencyNs);
        info.batchParams.add(ident, params);
    } else {
        // A batch has already been called with this ident. Update the batch parameters.
        info.setBatchParamsForIdent(ident, flags, samplingPeriodNs, maxBatchReportLatencyNs);
    }

    BatchParams prevBestBatchParams = info.bestBatchParams;
    // Find the minimum of all timeouts and batch_rates for this sensor.
    info.selectBatchParams();

    ALOGD_IF(DEBUG_CONNECTIONS,
             "\t>>> curr_period=%" PRId64 " min_period=%" PRId64
             " curr_timeout=%" PRId64 " min_timeout=%" PRId64,
             prevBestBatchParams.batchDelay, info.bestBatchParams.batchDelay,
             prevBestBatchParams.batchTimeout, info.bestBatchParams.batchTimeout);

    status_t err(NO_ERROR);
    // If the min period or min timeout has changed since the last batch call, call batch.
    if (prevBestBatchParams != info.bestBatchParams) {
        if (halVersion >= SENSORS_DEVICE_API_VERSION_1_1) {
            ALOGD_IF(DEBUG_CONNECTIONS, "\t>>> actuating h/w BATCH %d %d %" PRId64 " %" PRId64, handle,
                     info.bestBatchParams.flags, info.bestBatchParams.batchDelay,
                     info.bestBatchParams.batchTimeout);
            err = StatusFromResult(
                    mSensors->batch(
                        handle,
                        info.bestBatchParams.flags,
                        info.bestBatchParams.batchDelay,
                        info.bestBatchParams.batchTimeout));
        } else {
            // For older devices which do not support batch, call setDelay() after activate() is
            // called. Some older devices may not support calling setDelay before activate(), so
            // call setDelay in SensorDevice::activate() method.
        }
        if (err != NO_ERROR) {
            ALOGE("sensor batch failed %p %d %d %" PRId64 " %" PRId64 " err=%s",
                  mSensors.get(), handle,
                  info.bestBatchParams.flags, info.bestBatchParams.batchDelay,
                  info.bestBatchParams.batchTimeout, strerror(-err));
            info.removeBatchParamsForIdent(ident);
        }
    }
    return err;
}

status_t SensorDevice::setDelay(void* ident, int handle, int64_t samplingPeriodNs) {
    if (mSensors == NULL) return NO_INIT;
    if (samplingPeriodNs < MINIMUM_EVENTS_PERIOD) {
        samplingPeriodNs = MINIMUM_EVENTS_PERIOD;
    }
    Mutex::Autolock _l(mLock);
    if (isClientDisabledLocked(ident)) return INVALID_OPERATION;
    Info& info( mActivationCount.editValueFor(handle) );
    // If the underlying sensor is NOT in continuous mode, setDelay() should return an error.
    // Calling setDelay() in batch mode is an invalid operation.
    if (info.bestBatchParams.batchTimeout != 0) {
      return INVALID_OPERATION;
    }
    ssize_t index = info.batchParams.indexOfKey(ident);
    if (index < 0) {
        return BAD_INDEX;
    }
    BatchParams& params = info.batchParams.editValueAt(index);
    params.batchDelay = samplingPeriodNs;
    info.selectBatchParams();

    return StatusFromResult(
            mSensors->setDelay(handle, info.bestBatchParams.batchDelay));
}

int SensorDevice::getHalDeviceVersion() const {
    if (mSensors == NULL) return -1;
    return SENSORS_DEVICE_API_VERSION_1_4;
}

status_t SensorDevice::flush(void* ident, int handle) {
    if (getHalDeviceVersion() < SENSORS_DEVICE_API_VERSION_1_1) {
        return INVALID_OPERATION;
    }
    if (isClientDisabled(ident)) return INVALID_OPERATION;
    ALOGD_IF(DEBUG_CONNECTIONS, "\t>>> actuating h/w flush %d", handle);
    return StatusFromResult(mSensors->flush(handle));
}

bool SensorDevice::isClientDisabled(void* ident) {
    Mutex::Autolock _l(mLock);
    return isClientDisabledLocked(ident);
}

bool SensorDevice::isClientDisabledLocked(void* ident) {
    return mDisabledClients.indexOf(ident) >= 0;
}

void SensorDevice::enableAllSensors() {
    Mutex::Autolock _l(mLock);
    mDisabledClients.clear();
    ALOGI("cleared mDisabledClients");
    const int halVersion = getHalDeviceVersion();
    for (size_t i = 0; i< mActivationCount.size(); ++i) {
        Info& info = mActivationCount.editValueAt(i);
        if (info.batchParams.isEmpty()) continue;
        info.selectBatchParams();
        const int sensor_handle = mActivationCount.keyAt(i);
        ALOGD_IF(DEBUG_CONNECTIONS, "\t>> reenable actuating h/w sensor enable handle=%d ",
                   sensor_handle);
        status_t err(NO_ERROR);
        if (halVersion > SENSORS_DEVICE_API_VERSION_1_0) {
            err = StatusFromResult(
                    mSensors->batch(
                        sensor_handle,
                        info.bestBatchParams.flags,
                        info.bestBatchParams.batchDelay,
                        info.bestBatchParams.batchTimeout));
            ALOGE_IF(err, "Error calling batch on sensor %d (%s)", sensor_handle, strerror(-err));
        }

        if (err == NO_ERROR) {
            err = StatusFromResult(
                    mSensors->activate(sensor_handle, 1 /* enabled */));
            ALOGE_IF(err, "Error activating sensor %d (%s)", sensor_handle, strerror(-err));
        }

        if (halVersion <= SENSORS_DEVICE_API_VERSION_1_0) {
             err = StatusFromResult(
                     mSensors->setDelay(
                         sensor_handle, info.bestBatchParams.batchDelay));
             ALOGE_IF(err, "Error calling setDelay sensor %d (%s)", sensor_handle, strerror(-err));
        }
    }
}

void SensorDevice::disableAllSensors() {
    Mutex::Autolock _l(mLock);
   for (size_t i = 0; i< mActivationCount.size(); ++i) {
        const Info& info = mActivationCount.valueAt(i);
        // Check if this sensor has been activated previously and disable it.
        if (info.batchParams.size() > 0) {
           const int sensor_handle = mActivationCount.keyAt(i);
           ALOGD_IF(DEBUG_CONNECTIONS, "\t>> actuating h/w sensor disable handle=%d ",
                   sensor_handle);
           /* auto result = */mSensors->activate(
                   sensor_handle, 0 /* enabled */);

           // Add all the connections that were registered for this sensor to the disabled
           // clients list.
           for (size_t j = 0; j < info.batchParams.size(); ++j) {
               mDisabledClients.add(info.batchParams.keyAt(j));
               ALOGI("added %p to mDisabledClients", info.batchParams.keyAt(j));
           }
        }
    }
}

status_t SensorDevice::injectSensorData(
        const sensors_event_t *injected_sensor_event) {
    ALOGD_IF(DEBUG_CONNECTIONS,
            "sensor_event handle=%d ts=%" PRId64 " data=%.2f, %.2f, %.2f %.2f %.2f %.2f",
            injected_sensor_event->sensor,
            injected_sensor_event->timestamp, injected_sensor_event->data[0],
            injected_sensor_event->data[1], injected_sensor_event->data[2],
            injected_sensor_event->data[3], injected_sensor_event->data[4],
            injected_sensor_event->data[5]);

    if (getHalDeviceVersion() < SENSORS_DEVICE_API_VERSION_1_4) {
        return INVALID_OPERATION;
    }

    Event ev;
    convertFromSensorEvent(*injected_sensor_event, &ev);

    return StatusFromResult(mSensors->injectSensorData(ev));
}

status_t SensorDevice::setMode(uint32_t mode) {
     if (getHalDeviceVersion() < SENSORS_DEVICE_API_VERSION_1_4) {
          return INVALID_OPERATION;
     }

     return StatusFromResult(
             mSensors->setOperationMode(
                 static_cast<hardware::sensors::V1_0::OperationMode>(mode)));
}

// ---------------------------------------------------------------------------

int SensorDevice::Info::numActiveClients() {
    SensorDevice& device(SensorDevice::getInstance());
    int num = 0;
    for (size_t i = 0; i < batchParams.size(); ++i) {
        if (!device.isClientDisabledLocked(batchParams.keyAt(i))) {
            ++num;
        }
    }
    return num;
}

status_t SensorDevice::Info::setBatchParamsForIdent(void* ident, int flags,
                                                    int64_t samplingPeriodNs,
                                                    int64_t maxBatchReportLatencyNs) {
    ssize_t index = batchParams.indexOfKey(ident);
    if (index < 0) {
        ALOGE("Info::setBatchParamsForIdent(ident=%p, period_ns=%" PRId64 " timeout=%" PRId64 ") failed (%s)",
              ident, samplingPeriodNs, maxBatchReportLatencyNs, strerror(-index));
        return BAD_INDEX;
    }
    BatchParams& params = batchParams.editValueAt(index);
    params.flags = flags;
    params.batchDelay = samplingPeriodNs;
    params.batchTimeout = maxBatchReportLatencyNs;
    return NO_ERROR;
}

void SensorDevice::Info::selectBatchParams() {
    BatchParams bestParams(0, -1, -1);
    SensorDevice& device(SensorDevice::getInstance());

    for (size_t i = 0; i < batchParams.size(); ++i) {
        if (device.isClientDisabledLocked(batchParams.keyAt(i))) continue;
        BatchParams params = batchParams.valueAt(i);
        if (bestParams.batchDelay == -1 || params.batchDelay < bestParams.batchDelay) {
            bestParams.batchDelay = params.batchDelay;
        }
        if (bestParams.batchTimeout == -1 || params.batchTimeout < bestParams.batchTimeout) {
            bestParams.batchTimeout = params.batchTimeout;
        }
    }
    bestBatchParams = bestParams;
}

ssize_t SensorDevice::Info::removeBatchParamsForIdent(void* ident) {
    ssize_t idx = batchParams.removeItem(ident);
    if (idx >= 0) {
        selectBatchParams();
    }
    return idx;
}

void SensorDevice::notifyConnectionDestroyed(void* ident) {
    Mutex::Autolock _l(mLock);
    mDisabledClients.remove(ident);
}

void SensorDevice::convertToSensorEvent(
        const Event &src, sensors_event_t *dst) {
    ::android::hardware::sensors::V1_0::implementation::convertToSensorEvent(
            src, dst);

    if (src.sensorType == SensorType::SENSOR_TYPE_DYNAMIC_SENSOR_META) {
        const DynamicSensorInfo &dyn = src.u.dynamic;

        dst->dynamic_sensor_meta.connected = dyn.connected;
        dst->dynamic_sensor_meta.handle = dyn.sensorHandle;
        if (dyn.connected) {
            auto it = mConnectedDynamicSensors.find(dyn.sensorHandle);
            CHECK(it != mConnectedDynamicSensors.end());

            dst->dynamic_sensor_meta.sensor = it->second;

            memcpy(dst->dynamic_sensor_meta.uuid,
                   dyn.uuid.data(),
                   sizeof(dst->dynamic_sensor_meta.uuid));
        }
    }
}

void SensorDevice::convertToSensorEvents(
        const hidl_vec<Event> &src,
        const hidl_vec<SensorInfo> &dynamicSensorsAdded,
        sensors_event_t *dst) {
    // Allocate a sensor_t structure for each dynamic sensor added and insert
    // it into the dictionary of connected dynamic sensors keyed by handle.
    for (size_t i = 0; i < dynamicSensorsAdded.size(); ++i) {
        const SensorInfo &info = dynamicSensorsAdded[i];

        auto it = mConnectedDynamicSensors.find(info.sensorHandle);
        CHECK(it == mConnectedDynamicSensors.end());

        sensor_t *sensor = new sensor_t;
        convertToSensor(info, sensor);

        mConnectedDynamicSensors.insert(
                std::make_pair(sensor->handle, sensor));
    }

    for (size_t i = 0; i < src.size(); ++i) {
        convertToSensorEvent(src[i], &dst[i]);
    }
}

// ---------------------------------------------------------------------------
}; // namespace android

