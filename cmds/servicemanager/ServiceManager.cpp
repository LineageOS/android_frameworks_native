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

#include "ServiceManager.h"

#include <android-base/logging.h>
#include <cutils/android_filesystem_config.h>
#include <cutils/multiuser.h>

using ::android::binder::Status;

namespace android {

ServiceManager::ServiceManager(std::unique_ptr<Access>&& access) : mAccess(std::move(access)) {}

Status ServiceManager::getService(const std::string& name, sp<IBinder>* outBinder) {
    // Servicemanager is single-threaded and cannot block. This method exists for legacy reasons.
    return checkService(name, outBinder);
}

Status ServiceManager::checkService(const std::string& name, sp<IBinder>* outBinder) {
    auto ctx = mAccess->getCallingContext();

    auto it = mNameToService.find(name);
    if (it == mNameToService.end()) {
        *outBinder = nullptr;
        return Status::ok();
    }

    const Service& service = it->second;

    if (!service.allowIsolated) {
        uid_t appid = multiuser_get_app_id(ctx.uid);
        bool isIsolated = appid >= AID_ISOLATED_START && appid <= AID_ISOLATED_END;

        if (isIsolated) {
            *outBinder = nullptr;
            return Status::ok();
        }
    }

    if (!mAccess->canFind(ctx, name)) {
        // returns ok and null for legacy reasons
        *outBinder = nullptr;
        return Status::ok();
    }

    *outBinder = service.binder;
    return Status::ok();
}

bool isValidServiceName(const std::string& name) {
    if (name.size() == 0) return false;
    if (name.size() > 127) return false;

    for (char c : name) {
        if (c == '_' || c == '-' || c == '.') continue;
        if (c >= 'a' && c <= 'z') continue;
        if (c >= 'A' && c <= 'Z') continue;
        if (c >= '0' && c <= '9') continue;
        return false;
    }

    return true;
}

Status ServiceManager::addService(const std::string& name, const sp<IBinder>& binder, bool allowIsolated, int32_t dumpPriority) {
    auto ctx = mAccess->getCallingContext();

    // apps cannot add services
    if (multiuser_get_app_id(ctx.uid) >= AID_APP) {
        return Status::fromExceptionCode(Status::EX_SECURITY);
    }

    if (!mAccess->canAdd(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY);
    }

    if (binder == nullptr) {
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT);
    }

    if (!isValidServiceName(name)) {
        LOG(ERROR) << "Invalid service name: " << name;
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT);
    }

    if (OK != binder->linkToDeath(this)) {
        LOG(ERROR) << "Could not linkToDeath when adding " << name;
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    }

    auto it = mNameToService.find(name);
    if (it != mNameToService.end()) {
        if (OK != it->second.binder->unlinkToDeath(this)) {
            LOG(WARNING) << "Could not unlinkToDeath when adding " << name;
        }
    }

    mNameToService[name] = Service {
        .binder = binder,
        .allowIsolated = allowIsolated,
        .dumpPriority = dumpPriority,
    };

    return Status::ok();
}

Status ServiceManager::listServices(int32_t dumpPriority, std::vector<std::string>* outList) {
    if (!mAccess->canList(mAccess->getCallingContext())) {
        return Status::fromExceptionCode(Status::EX_SECURITY);
    }

    size_t toReserve = 0;
    for (auto const& [name, service] : mNameToService) {
        (void) name;

        if (service.dumpPriority & dumpPriority) ++toReserve;
    }

    CHECK(outList->empty());

    outList->reserve(toReserve);
    for (auto const& [name, service] : mNameToService) {
        (void) service;

        if (service.dumpPriority & dumpPriority) {
            outList->push_back(name);
        }
    }

    return Status::ok();
}

void ServiceManager::binderDied(const wp<IBinder>& who) {
    for (auto it = mNameToService.begin(); it != mNameToService.end();) {
        if (who == it->second.binder) {
            it = mNameToService.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace android
