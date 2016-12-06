/**
 * Copyright (c) 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "installd"

#include <vector>
#include <fstream>

#include <android-base/stringprintf.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <cutils/log.h>
#include <cutils/properties.h>
#include <private/android_filesystem_config.h>
#include <utils/Errors.h>
#include <utils/String16.h>

#include "InstalldNativeService.h"

#include "commands.h"

using android::base::StringPrintf;

namespace android {
namespace installd {

namespace {

constexpr const char* kDump = "android.permission.DUMP";

binder::Status checkPermission(const char* permission) {
    pid_t pid;
    uid_t uid;

    if (checkCallingPermission(String16(permission), reinterpret_cast<int32_t*>(&pid),
            reinterpret_cast<int32_t*>(&uid))) {
        return binder::Status::ok();
    } else {
        auto err = StringPrintf("UID %d / PID %d lacks permission %s", uid, pid, permission);
        return binder::Status::fromExceptionCode(binder::Status::EX_SECURITY, String8(err.c_str()));
    }
}

binder::Status checkUid(uid_t expectedUid) {
    uid_t uid = IPCThreadState::self()->getCallingUid();
    if (uid == expectedUid) {
        return binder::Status::ok();
    } else {
        auto err = StringPrintf("UID %d is not expected UID %d", uid, expectedUid);
        return binder::Status::fromExceptionCode(binder::Status::EX_SECURITY, String8(err.c_str()));
    }
}

#define ENFORCE_UID(uid) {                                  \
    binder::Status status = checkUid((uid));                \
    if (!status.isOk()) {                                   \
        return status;                                      \
    }                                                       \
}

}  // namespace

status_t InstalldNativeService::start() {
    IPCThreadState::self()->disableBackgroundScheduling(true);
    status_t ret = BinderService<InstalldNativeService>::publish();
    if (ret != android::OK) {
        return ret;
    }
    sp<ProcessState> ps(ProcessState::self());
    ps->startThreadPool();
    ps->giveThreadPoolName();
    return android::OK;
}

status_t InstalldNativeService::dump(int fd, const Vector<String16> & /* args */) {
    const binder::Status dump_permission = checkPermission(kDump);
    if (!dump_permission.isOk()) {
        const String8 msg(dump_permission.toString8());
        write(fd, msg.string(), msg.size());
        return PERMISSION_DENIED;
    }

    std::string msg = "installd is happy\n";
    write(fd, msg.c_str(), strlen(msg.c_str()));
    return NO_ERROR;
}

static binder::Status translateStatus(int ret) {
    if (ret != 0) {
        auto err = StringPrintf("Failed with error %d", ret);
        return binder::Status::fromServiceSpecificError(ret, String8(err.c_str()));
    } else {
        return binder::Status::ok();
    }
}

binder::Status InstalldNativeService::createAppData(const std::unique_ptr<std::string>& uuid,
        const std::string& pkgname, int32_t userid, int32_t flags, int32_t appid,
        const std::string& seinfo, int32_t targetSdkVersion) {
    ENFORCE_UID(AID_SYSTEM);
    const char* _uuid = uuid ? (*uuid).c_str() : nullptr;
    return translateStatus(create_app_data(_uuid, pkgname.c_str(), userid, flags, appid,
            seinfo.c_str(), targetSdkVersion));
}

}  // namespace installd
}  // namespace android
