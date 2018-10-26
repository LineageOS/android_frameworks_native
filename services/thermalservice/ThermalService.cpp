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

#include "ThermalService.h"
#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android/os/IThermalEventListener.h>
#include <android/os/IThermalService.h>
#include <android/os/Temperature.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>
#include <utils/Errors.h>
#include <utils/Mutex.h>
#include <utils/String16.h>

namespace android {
namespace os {

/**
 * Dump thermal service
 * @param fd file descriptor for dumping
 * @param args not used
 */
status_t ThermalService::dump(int fd, const Vector<String16>& /* args */) {
    status_t ret = OK;
    std::string result;
    const IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    if ((uid != AID_SHELL) &&
        !PermissionCache::checkPermission(String16("android.permission.DUMP"), pid, uid)) {
        result = android::base::
                StringPrintf("Permission Denial: can't dump ThermalService from pid=%d, uid=%d\n",
                             pid, uid);
        ret = PERMISSION_DENIED;
    } else {
        Mutex::Autolock _l(mListenersLock);
        result = android::base::StringPrintf("ThermalEventListener registered: %d\n",
                                             (int)mListeners.size());
    }
    if (!android::base::WriteStringToFd(result, fd)) {
        SLOGE("Failed to dump fd: %d", fd);
        ret = FDS_NOT_ALLOWED;
    }
    return ret;
}

/**
 * Notify registered listeners of a thermal throttling start/stop event.
 * @param temperature the temperature at which the event was generated
 */
binder::Status ThermalService::notifyThrottling(
    const bool isThrottling, const Temperature& temperature) {
    Mutex::Autolock _l(mListenersLock);

    mThrottled = isThrottling;
    mThrottleTemperature = temperature;

    for (size_t i = 0; i < mListeners.size(); i++) {
      mListeners[i]->notifyThrottling(isThrottling, temperature);
    }
    return binder::Status::ok();
}

/**
 * Query whether the system is currently thermal throttling.
 * @return true if currently thermal throttling, else false
 */
binder::Status ThermalService::isThrottling(bool* _aidl_return) {
    Mutex::Autolock _l(mListenersLock);
    *_aidl_return = mThrottled;
    return binder::Status::ok();
}

/**
 * Register a new thermal event listener.
 * @param listener the client's IThermalEventListener instance to which
 *                 notifications are to be sent
 */
binder::Status ThermalService::registerThermalEventListener(
    const sp<IThermalEventListener>& listener) {
    {
        if (listener == NULL) {
            return binder::Status::ok();
        }
        Mutex::Autolock _l(mListenersLock);
        // check whether this is a duplicate
        for (size_t i = 0; i < mListeners.size(); i++) {
            if (IInterface::asBinder(mListeners[i]) ==
                IInterface::asBinder(listener)) {
                return binder::Status::ok();
            }
        }

        mListeners.add(listener);
        IInterface::asBinder(listener)->linkToDeath(this);
    }

    return binder::Status::ok();
}

/**
 * Unregister a previously-registered thermal event listener.
 * @param listener the client's IThermalEventListener instance to which
 *                 notifications are to no longer be sent
 */
binder::Status ThermalService::unregisterThermalEventListener(
    const sp<IThermalEventListener>& listener) {
    if (listener == NULL) {
        return binder::Status::ok();
    }
    Mutex::Autolock _l(mListenersLock);
    for (size_t i = 0; i < mListeners.size(); i++) {
        if (IInterface::asBinder(mListeners[i]) ==
            IInterface::asBinder(listener)) {
            IInterface::asBinder(mListeners[i])->unlinkToDeath(this);
            mListeners.removeAt(i);
            break;
        }
    }

    return binder::Status::ok();
}

void ThermalService::binderDied(const wp<IBinder>& who) {
    Mutex::Autolock _l(mListenersLock);

    for (size_t i = 0; i < mListeners.size(); i++) {
        if (IInterface::asBinder(mListeners[i]) == who) {
            mListeners.removeAt(i);
            break;
        }
    }
}

/**
 * Publish the supplied ThermalService to servicemanager.
 */
void ThermalService::publish(
    const sp<ThermalService>& service) {
    defaultServiceManager()->addService(String16("thermalservice"),
                                        service);
}

}  // namespace os
}  // namespace android
