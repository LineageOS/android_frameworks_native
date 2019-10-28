/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <android/os/BnServiceManager.h>
#include <android/os/IServiceCallback.h>

#include "Access.h"

namespace android {

using os::IServiceCallback;

class ServiceManager : public os::BnServiceManager, public IBinder::DeathRecipient {
public:
    ServiceManager(std::unique_ptr<Access>&& access);
    ~ServiceManager();

    // getService will try to start any services it cannot find
    binder::Status getService(const std::string& name, sp<IBinder>* outBinder) override;
    binder::Status checkService(const std::string& name, sp<IBinder>* outBinder) override;
    binder::Status addService(const std::string& name, const sp<IBinder>& binder,
                              bool allowIsolated, int32_t dumpPriority) override;
    binder::Status listServices(int32_t dumpPriority, std::vector<std::string>* outList) override;
    binder::Status registerForNotifications(const std::string& name,
                                            const sp<IServiceCallback>& callback) override;
    binder::Status unregisterForNotifications(const std::string& name,
                                              const sp<IServiceCallback>& callback) override;
    binder::Status isDeclared(const std::string& name, bool* outReturn) override;

    void binderDied(const wp<IBinder>& who) override;

protected:
    virtual void tryStartService(const std::string& name);

private:
    struct Service {
        sp<IBinder> binder; // not null
        bool allowIsolated;
        int32_t dumpPriority;
    };

    using CallbackMap = std::map<std::string, std::vector<sp<IServiceCallback>>>;
    using ServiceMap = std::map<std::string, Service>;

    // removes a callback from mNameToCallback, removing it if the vector is empty
    // this updates iterator to the next location
    void removeCallback(const wp<IBinder>& who,
                        CallbackMap::iterator* it,
                        bool* found);
    sp<IBinder> tryGetService(const std::string& name, bool startIfNotFound);

    CallbackMap mNameToCallback;
    ServiceMap mNameToService;

    std::unique_ptr<Access> mAccess;
};

}  // namespace android
