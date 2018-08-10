/*
 * Copyright 2018 The Android Open Source Project
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

#include "DispSyncSource.h"

#include <utils/Mutex.h>
#include <utils/Trace.h>

#include "DispSync.h"
#include "EventThread.h"

namespace android {

DispSyncSource::DispSyncSource(DispSync* dispSync, nsecs_t phaseOffset, bool traceVsync,
                               const char* name)
      : mName(name),
        mValue(0),
        mTraceVsync(traceVsync),
        mVsyncOnLabel(String8::format("VsyncOn-%s", name)),
        mVsyncEventLabel(String8::format("VSYNC-%s", name)),
        mDispSync(dispSync),
        mCallbackMutex(),
        mVsyncMutex(),
        mPhaseOffset(phaseOffset),
        mEnabled(false) {}

void DispSyncSource::setVSyncEnabled(bool enable) {
    Mutex::Autolock lock(mVsyncMutex);
    if (enable) {
        status_t err = mDispSync->addEventListener(mName, mPhaseOffset,
                                                   static_cast<DispSync::Callback*>(this));
        if (err != NO_ERROR) {
            ALOGE("error registering vsync callback: %s (%d)", strerror(-err), err);
        }
        // ATRACE_INT(mVsyncOnLabel.string(), 1);
    } else {
        status_t err = mDispSync->removeEventListener(static_cast<DispSync::Callback*>(this));
        if (err != NO_ERROR) {
            ALOGE("error unregistering vsync callback: %s (%d)", strerror(-err), err);
        }
        // ATRACE_INT(mVsyncOnLabel.string(), 0);
    }
    mEnabled = enable;
}

void DispSyncSource::setCallback(VSyncSource::Callback* callback) {
    Mutex::Autolock lock(mCallbackMutex);
    mCallback = callback;
}

void DispSyncSource::setPhaseOffset(nsecs_t phaseOffset) {
    Mutex::Autolock lock(mVsyncMutex);

    // Normalize phaseOffset to [0, period)
    auto period = mDispSync->getPeriod();
    phaseOffset %= period;
    if (phaseOffset < 0) {
        // If we're here, then phaseOffset is in (-period, 0). After this
        // operation, it will be in (0, period)
        phaseOffset += period;
    }
    mPhaseOffset = phaseOffset;

    // If we're not enabled, we don't need to mess with the listeners
    if (!mEnabled) {
        return;
    }

    status_t err =
            mDispSync->changePhaseOffset(static_cast<DispSync::Callback*>(this), mPhaseOffset);
    if (err != NO_ERROR) {
        ALOGE("error changing vsync offset: %s (%d)", strerror(-err), err);
    }
}

void DispSyncSource::onDispSyncEvent(nsecs_t when) {
    VSyncSource::Callback* callback;
    {
        Mutex::Autolock lock(mCallbackMutex);
        callback = mCallback;

        if (mTraceVsync) {
            mValue = (mValue + 1) % 2;
            ATRACE_INT(mVsyncEventLabel.string(), mValue);
        }
    }

    if (callback != nullptr) {
        callback->onVSyncEvent(when);
    }
}

} // namespace android