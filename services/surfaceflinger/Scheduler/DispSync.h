/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <stddef.h>

#include <utils/Mutex.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

#include <ui/FenceTime.h>

#include <memory>

namespace android {

class FenceTime;

class DispSync {
public:
    class Callback {
    public:
        Callback() = default;
        virtual ~Callback() = default;
        virtual void onDispSyncEvent(nsecs_t when, nsecs_t expectedVSyncTimestamp) = 0;

    protected:
        Callback(Callback const&) = delete;
        Callback& operator=(Callback const&) = delete;
    };

    DispSync() = default;
    virtual ~DispSync() = default;

    virtual void reset() = 0;
    virtual bool addPresentFence(const std::shared_ptr<FenceTime>&) = 0;
    virtual void beginResync() = 0;
    virtual bool addResyncSample(nsecs_t timestamp, std::optional<nsecs_t> hwcVsyncPeriod,
                                 bool* periodFlushed) = 0;
    virtual void endResync() = 0;
    virtual void setPeriod(nsecs_t period) = 0;
    virtual nsecs_t getPeriod() = 0;
    virtual status_t addEventListener(const char* name, nsecs_t phase, Callback* callback,
                                      nsecs_t lastCallbackTime) = 0;
    virtual status_t removeEventListener(Callback* callback, nsecs_t* outLastCallback) = 0;
    virtual status_t changePhaseOffset(Callback* callback, nsecs_t phase) = 0;
    virtual nsecs_t computeNextRefresh(int periodOffset, nsecs_t now) const = 0;
    virtual void setIgnorePresentFences(bool ignore) = 0;
    virtual nsecs_t expectedPresentTime(nsecs_t now) = 0;

    virtual void dump(std::string& result) const = 0;

protected:
    DispSync(DispSync const&) = delete;
    DispSync& operator=(DispSync const&) = delete;
};

} // namespace android
