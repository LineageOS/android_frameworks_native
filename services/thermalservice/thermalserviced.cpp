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

#define LOG_TAG "thermalserviced"
#include <log/log.h>

#include "ThermalService.h"
#include "libthermalcallback/ThermalCallback.h"
#include "libthermalcallback/ThermalChangedCallback.h"
#include "thermalserviced.h"

#include <android/hardware/thermal/1.1/IThermal.h>
#include <android/hardware/thermal/2.0/IThermal.h>
#include <android/hardware/thermal/2.0/types.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <hidl/HidlTransportSupport.h>

using namespace android;
using IThermal1_1 = ::android::hardware::thermal::V1_1::IThermal;
using IThermal2_0 = ::android::hardware::thermal::V2_0::IThermal;
using ::android::hardware::configureRpcThreadpool;
using ::android::hardware::hidl_death_recipient;
using ::android::hardware::Return;
using ::android::hardware::thermal::V1_0::ThermalStatus;
using ::android::hardware::thermal::V1_0::ThermalStatusCode;
using ::android::hardware::thermal::V1_1::IThermalCallback;
using ::android::hardware::thermal::V1_1::implementation::ThermalCallback;
using ::android::hardware::thermal::V2_0::IThermalChangedCallback;
using ::android::hardware::thermal::V2_0::TemperatureType;
using ::android::hidl::base::V1_0::IBase;
using ::android::os::ThermalService;

namespace {

// Our thermalserviced main object
ThermalServiceDaemon* gThermalServiceDaemon;

// Thermal HAL 1.1 client
sp<IThermal1_1> gThermalHal1_1 = nullptr;
// Thermal HAL 2.0 client
sp<IThermal2_0> gThermalHal2_0 = nullptr;

// Binder death notifier informing of Thermal HAL death.
struct ThermalServiceDeathRecipient : hidl_death_recipient {
    virtual void serviceDied(
        uint64_t cookie __unused, const wp<IBase>& who __unused) {
        SLOGE("IThermal HAL died");
        gThermalHal1_1 = nullptr;
        gThermalHal2_0 = nullptr;
        gThermalServiceDaemon->getThermalHal();
    }
};

}  // anonymous namespace

void ThermalServiceDaemon::thermalServiceStartup() {
    // Binder IThermal1_1Service startup
    mThermalService = new android::os::ThermalService;
    mThermalService->publish(mThermalService);
    // Register IThermalService object to ThermalHAL callback
    if (mThermalCallback_2_0 != nullptr) {
        mThermalCallback_2_0->registerThermalService(mThermalService);
    } else if (mThermalCallback_1_1 != nullptr) {
        mThermalCallback_1_1->registerThermalService(mThermalService);
    }
    IPCThreadState::self()->joinThreadPool();
}

// Lookup Thermal HAL, register death notifier, register our
// ThermalCallback with the Thermal HAL.
void ThermalServiceDaemon::getThermalHal() {
    static sp<ThermalServiceDeathRecipient> gThermalHalDied = nullptr;
    // Binder death notifier for Thermal HAL
    if (gThermalHalDied == nullptr) {
        gThermalHalDied = new ThermalServiceDeathRecipient();
    }

    gThermalHal2_0 = IThermal2_0::getService();
    if (gThermalHal2_0 == nullptr) {
        SLOGW("Unable to get Thermal HAL V2.0, fallback to 1.1");
        gThermalHal1_1 = IThermal1_1::getService();
        if (gThermalHal1_1 == nullptr) {
            SLOGW("Unable to get Thermal HAL V1.1, vendor thermal event "
                  "notification not available");
            return;
        }
        if (gThermalHalDied != nullptr) {
            gThermalHal1_1->linkToDeath(gThermalHalDied, 0x451F /* cookie */);
        }

        if (mThermalCallback_1_1 != nullptr) {
            Return<void> ret = gThermalHal1_1->registerThermalCallback(mThermalCallback_1_1);
            if (!ret.isOk()) {
                SLOGE("registerThermalCallback failed, status: %s", ret.description().c_str());
            }
        }
    } else {
        if (gThermalHalDied != nullptr) {
            gThermalHal2_0->linkToDeath(gThermalHalDied, 0x451F /* cookie */);
        }

        if (mThermalCallback_2_0 != nullptr) {
            Return<void> ret =
                    gThermalHal2_0
                            ->registerThermalChangedCallback(mThermalCallback_2_0, false,
                                                             TemperatureType::SKIN, // not used
                                                             [](ThermalStatus status) {
                                                                 if (ThermalStatusCode::SUCCESS !=
                                                                     status.code) {
                                                                     SLOGE("registerThermalChangedC"
                                                                           "allback failed, "
                                                                           "status: %s",
                                                                           status.debugMessage
                                                                                   .c_str());
                                                                 }
                                                             });
            if (!ret.isOk()) {
                SLOGE("registerThermalChangedCallback failed, status: %s",
                      ret.description().c_str());
            }
        }
    }
}

ThermalServiceDaemon::~ThermalServiceDaemon() {
    if (mThermalCallback_2_0 != nullptr && gThermalHal2_0 != nullptr) {
        Return<void> ret =
                gThermalHal2_0
                        ->unregisterThermalChangedCallback(
                            mThermalCallback_2_0,
                            [](ThermalStatus status) {
                                if (ThermalStatusCode::SUCCESS !=
                                    status.code) {
                                    SLOGE("unregisterThermalChangedCallback failed, status: %s",
                                          status.debugMessage
                                          .c_str());
                                }
                            });
        if (!ret.isOk()) {
            SLOGE("unregisterThermalChangedCallback failed, status: %s", ret.description().c_str());
        }
    }
}

void ThermalServiceDaemon::thermalCallbackStartup() {
    // HIDL IThermal Callback startup
    // Need at least 2 threads in thread pool since we wait for dead HAL
    // to come back on the binder death notification thread and we need
    // another thread for the incoming service now available call.
    configureRpcThreadpool(2, false /* callerWillJoin */);
    mThermalCallback_1_1 = new ThermalCallback();
    mThermalCallback_2_0 = new ThermalChangedCallback();
    // Lookup Thermal HAL 1.1 and 2.0 to register our Callback.
    getThermalHal();
}

int main(int /*argc*/, char** /*argv*/) {
    gThermalServiceDaemon = new ThermalServiceDaemon();
    gThermalServiceDaemon->thermalCallbackStartup();
    gThermalServiceDaemon->thermalServiceStartup();
    /* NOTREACHED */
}
