/*
** Copyright 2008, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include "InstalldNativeService.h"

#include <errno.h>
#include <inttypes.h>
#include <regex>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/fs.h>
#include <cutils/log.h>               // TODO: Move everything to base/logging.
#include <cutils/properties.h>
#include <cutils/sched_policy.h>
#include <diskusage/dirsize.h>
#include <logwrap/logwrap.h>
#include <private/android_filesystem_config.h>
#include <selinux/android.h>
#include <system/thread_defs.h>

#include "dexopt.h"
#include "globals.h"
#include "installd_deps.h"
#include "otapreopt_utils.h"
#include "utils.h"

#ifndef LOG_TAG
#define LOG_TAG "installd"
#endif

using android::base::StringPrintf;

namespace android {
namespace installd {

static constexpr const char* kCpPath = "/system/bin/cp";
static constexpr const char* kXattrDefault = "user.default";

static constexpr const char* PKG_LIB_POSTFIX = "/lib";
static constexpr const char* CACHE_DIR_POSTFIX = "/cache";
static constexpr const char* CODE_CACHE_DIR_POSTFIX = "/code_cache";

static constexpr const char* IDMAP_PREFIX = "/data/resource-cache/";
static constexpr const char* IDMAP_SUFFIX = "@idmap";

// NOTE: keep in sync with StorageManager
static constexpr int FLAG_STORAGE_DE = 1 << 0;
static constexpr int FLAG_STORAGE_CE = 1 << 1;

// NOTE: keep in sync with Installer
static constexpr int FLAG_CLEAR_CACHE_ONLY = 1 << 8;
static constexpr int FLAG_CLEAR_CODE_CACHE_ONLY = 1 << 9;


#define MIN_RESTRICTED_HOME_SDK_VERSION 24 // > M
namespace {

constexpr const char* kDump = "android.permission.DUMP";

static binder::Status ok() {
    return binder::Status::ok();
}

static binder::Status exception(uint32_t code) {
    return binder::Status::fromExceptionCode(code);
}

static binder::Status exception(uint32_t code, const std::string& msg) {
    return binder::Status::fromExceptionCode(code, String8(msg.c_str()));
}

static binder::Status error() {
    return binder::Status::fromServiceSpecificError(errno);
}

static binder::Status error(const std::string& msg) {
    PLOG(ERROR) << msg;
    return binder::Status::fromServiceSpecificError(errno, String8(msg.c_str()));
}

static binder::Status error(uint32_t code, const std::string& msg) {
    LOG(ERROR) << msg << " (" << code << ")";
    return binder::Status::fromServiceSpecificError(code, String8(msg.c_str()));
}

binder::Status checkPermission(const char* permission) {
    pid_t pid;
    uid_t uid;

    if (checkCallingPermission(String16(permission), reinterpret_cast<int32_t*>(&pid),
            reinterpret_cast<int32_t*>(&uid))) {
        return ok();
    } else {
        return exception(binder::Status::EX_SECURITY,
                StringPrintf("UID %d / PID %d lacks permission %s", uid, pid, permission));
    }
}

binder::Status checkUid(uid_t expectedUid) {
    uid_t uid = IPCThreadState::self()->getCallingUid();
    if (uid == expectedUid || uid == AID_ROOT) {
        return ok();
    } else {
        return exception(binder::Status::EX_SECURITY,
                StringPrintf("UID %d is not expected UID %d", uid, expectedUid));
    }
}

binder::Status checkArgumentUuid(const std::unique_ptr<std::string>& uuid) {
    if (!uuid || is_valid_filename(*uuid)) {
        return ok();
    } else {
        return exception(binder::Status::EX_ILLEGAL_ARGUMENT,
                StringPrintf("UUID %s is malformed", uuid->c_str()));
    }
}

binder::Status checkArgumentPackageName(const std::string& packageName) {
    if (is_valid_package_name(packageName.c_str())) {
        return ok();
    } else {
        return exception(binder::Status::EX_ILLEGAL_ARGUMENT,
                StringPrintf("Package name %s is malformed", packageName.c_str()));
    }
}

#define ENFORCE_UID(uid) {                                  \
    binder::Status status = checkUid((uid));                \
    if (!status.isOk()) {                                   \
        return status;                                      \
    }                                                       \
}

#define CHECK_ARGUMENT_UUID(uuid) {                         \
    binder::Status status = checkArgumentUuid((uuid));      \
    if (!status.isOk()) {                                   \
        return status;                                      \
    }                                                       \
}

#define CHECK_ARGUMENT_PACKAGE_NAME(packageName) {          \
    binder::Status status =                                 \
            checkArgumentPackageName((packageName));        \
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

/**
 * Perform restorecon of the given path, but only perform recursive restorecon
 * if the label of that top-level file actually changed.  This can save us
 * significant time by avoiding no-op traversals of large filesystem trees.
 */
static int restorecon_app_data_lazy(const std::string& path, const std::string& seInfo, uid_t uid) {
    int res = 0;
    char* before = nullptr;
    char* after = nullptr;

    // Note that SELINUX_ANDROID_RESTORECON_DATADATA flag is set by
    // libselinux. Not needed here.

    if (lgetfilecon(path.c_str(), &before) < 0) {
        PLOG(ERROR) << "Failed before getfilecon for " << path;
        goto fail;
    }
    if (selinux_android_restorecon_pkgdir(path.c_str(), seInfo.c_str(), uid, 0) < 0) {
        PLOG(ERROR) << "Failed top-level restorecon for " << path;
        goto fail;
    }
    if (lgetfilecon(path.c_str(), &after) < 0) {
        PLOG(ERROR) << "Failed after getfilecon for " << path;
        goto fail;
    }

    // If the initial top-level restorecon above changed the label, then go
    // back and restorecon everything recursively
    if (strcmp(before, after)) {
        LOG(DEBUG) << "Detected label change from " << before << " to " << after << " at " << path
                << "; running recursive restorecon";
        if (selinux_android_restorecon_pkgdir(path.c_str(), seInfo.c_str(), uid,
                SELINUX_ANDROID_RESTORECON_RECURSE) < 0) {
            PLOG(ERROR) << "Failed recursive restorecon for " << path;
            goto fail;
        }
    }

    goto done;
fail:
    res = -1;
done:
    free(before);
    free(after);
    return res;
}

static int restorecon_app_data_lazy(const std::string& parent, const char* name,
        const std::string& seInfo, uid_t uid) {
    return restorecon_app_data_lazy(StringPrintf("%s/%s", parent.c_str(), name), seInfo, uid);
}

static int prepare_app_dir(const std::string& path, mode_t target_mode, uid_t uid) {
    if (fs_prepare_dir_strict(path.c_str(), target_mode, uid, uid) != 0) {
        PLOG(ERROR) << "Failed to prepare " << path;
        return -1;
    }
    return 0;
}

static int prepare_app_dir(const std::string& parent, const char* name, mode_t target_mode,
        uid_t uid) {
    return prepare_app_dir(StringPrintf("%s/%s", parent.c_str(), name), target_mode, uid);
}

binder::Status InstalldNativeService::createAppData(const std::unique_ptr<std::string>& uuid,
        const std::string& packageName, int32_t userId, int32_t flags, int32_t appId,
        const std::string& seInfo, int32_t targetSdkVersion) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* uuid_ = uuid ? uuid->c_str() : nullptr;
    const char* pkgname = packageName.c_str();

    uid_t uid = multiuser_get_uid(userId, appId);
    mode_t target_mode = targetSdkVersion >= MIN_RESTRICTED_HOME_SDK_VERSION ? 0700 : 0751;
    if (flags & FLAG_STORAGE_CE) {
        auto path = create_data_user_ce_package_path(uuid_, userId, pkgname);
        if (prepare_app_dir(path, target_mode, uid) ||
                prepare_app_dir(path, "cache", 0771, uid) ||
                prepare_app_dir(path, "code_cache", 0771, uid)) {
            return error("Failed to prepare " + path);
        }

        // Consider restorecon over contents if label changed
        if (restorecon_app_data_lazy(path, seInfo, uid) ||
                restorecon_app_data_lazy(path, "cache", seInfo, uid) ||
                restorecon_app_data_lazy(path, "code_cache", seInfo, uid)) {
            return error("Failed to restorecon " + path);
        }

        // Remember inode numbers of cache directories so that we can clear
        // contents while CE storage is locked
        if (write_path_inode(path, "cache", kXattrInodeCache) ||
                write_path_inode(path, "code_cache", kXattrInodeCodeCache)) {
            return error("Failed to write_path_inode for " + path);
        }
    }
    if (flags & FLAG_STORAGE_DE) {
        auto path = create_data_user_de_package_path(uuid_, userId, pkgname);
        if (prepare_app_dir(path, target_mode, uid)) {
            return error("Failed to prepare " + path);
        }

        // Consider restorecon over contents if label changed
        if (restorecon_app_data_lazy(path, seInfo, uid)) {
            return error("Failed to restorecon " + path);
        }

        if (property_get_bool("dalvik.vm.usejitprofiles", false)) {
            const std::string profile_path = create_data_user_profile_package_path(userId, pkgname);
            // read-write-execute only for the app user.
            if (fs_prepare_dir_strict(profile_path.c_str(), 0700, uid, uid) != 0) {
                return error("Failed to prepare " + profile_path);
            }
            std::string profile_file = create_primary_profile(profile_path);
            // read-write only for the app user.
            if (fs_prepare_file_strict(profile_file.c_str(), 0600, uid, uid) != 0) {
                return error("Failed to prepare " + profile_path);
            }
            const std::string ref_profile_path = create_data_ref_profile_package_path(pkgname);
            // dex2oat/profman runs under the shared app gid and it needs to read/write reference
            // profiles.
            int shared_app_gid = multiuser_get_shared_app_gid(uid);
            if ((shared_app_gid != -1) && fs_prepare_dir_strict(
                    ref_profile_path.c_str(), 0700, shared_app_gid, shared_app_gid) != 0) {
                return error("Failed to prepare " + ref_profile_path);
            }
        }
    }
    return ok();
}

binder::Status InstalldNativeService::migrateAppData(const std::unique_ptr<std::string>& uuid,
        const std::string& packageName, int32_t userId, int32_t flags) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* uuid_ = uuid ? uuid->c_str() : nullptr;
    const char* pkgname = packageName.c_str();

    // This method only exists to upgrade system apps that have requested
    // forceDeviceEncrypted, so their default storage always lives in a
    // consistent location.  This only works on non-FBE devices, since we
    // never want to risk exposing data on a device with real CE/DE storage.

    auto ce_path = create_data_user_ce_package_path(uuid_, userId, pkgname);
    auto de_path = create_data_user_de_package_path(uuid_, userId, pkgname);

    // If neither directory is marked as default, assume CE is default
    if (getxattr(ce_path.c_str(), kXattrDefault, nullptr, 0) == -1
            && getxattr(de_path.c_str(), kXattrDefault, nullptr, 0) == -1) {
        if (setxattr(ce_path.c_str(), kXattrDefault, nullptr, 0, 0) != 0) {
            return error("Failed to mark default storage " + ce_path);
        }
    }

    // Migrate default data location if needed
    auto target = (flags & FLAG_STORAGE_DE) ? de_path : ce_path;
    auto source = (flags & FLAG_STORAGE_DE) ? ce_path : de_path;

    if (getxattr(target.c_str(), kXattrDefault, nullptr, 0) == -1) {
        LOG(WARNING) << "Requested default storage " << target
                << " is not active; migrating from " << source;
        if (delete_dir_contents_and_dir(target) != 0) {
            return error("Failed to delete " + target);
        }
        if (rename(source.c_str(), target.c_str()) != 0) {
            return error("Failed to rename " + source + " to " + target);
        }
    }

    return ok();
}


binder::Status InstalldNativeService::clearAppProfiles(const std::string& packageName) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* pkgname = packageName.c_str();
    binder::Status res = ok();
    if (!clear_reference_profile(pkgname)) {
        res = error("Failed to clear reference profile for " + packageName);
    }
    if (!clear_current_profiles(pkgname)) {
        res = error("Failed to clear current profiles for " + packageName);
    }
    return res;
}

binder::Status InstalldNativeService::clearAppData(const std::unique_ptr<std::string>& uuid,
        const std::string& packageName, int32_t userId, int32_t flags, int64_t ceDataInode) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* uuid_ = uuid ? uuid->c_str() : nullptr;
    const char* pkgname = packageName.c_str();

    binder::Status res = ok();
    if (flags & FLAG_STORAGE_CE) {
        auto path = create_data_user_ce_package_path(uuid_, userId, pkgname, ceDataInode);
        if (flags & FLAG_CLEAR_CACHE_ONLY) {
            path = read_path_inode(path, "cache", kXattrInodeCache);
        } else if (flags & FLAG_CLEAR_CODE_CACHE_ONLY) {
            path = read_path_inode(path, "code_cache", kXattrInodeCodeCache);
        }
        if (access(path.c_str(), F_OK) == 0) {
            if (delete_dir_contents(path) != 0) {
                res = error("Failed to delete contents of " + path);
            }
        }
    }
    if (flags & FLAG_STORAGE_DE) {
        std::string suffix = "";
        bool only_cache = false;
        if (flags & FLAG_CLEAR_CACHE_ONLY) {
            suffix = CACHE_DIR_POSTFIX;
            only_cache = true;
        } else if (flags & FLAG_CLEAR_CODE_CACHE_ONLY) {
            suffix = CODE_CACHE_DIR_POSTFIX;
            only_cache = true;
        }

        auto path = create_data_user_de_package_path(uuid_, userId, pkgname) + suffix;
        if (access(path.c_str(), F_OK) == 0) {
            if (delete_dir_contents(path) != 0) {
                res = error("Failed to delete contents of " + path);
            }
        }
        if (!only_cache) {
            if (!clear_current_profile(pkgname, userId)) {
                res = error("Failed to clear current profile for " + packageName);
            }
        }
    }
    return res;
}

static int destroy_app_reference_profile(const char *pkgname) {
    return delete_dir_contents_and_dir(
        create_data_ref_profile_package_path(pkgname),
        /*ignore_if_missing*/ true);
}

static int destroy_app_current_profiles(const char *pkgname, userid_t userid) {
    return delete_dir_contents_and_dir(
        create_data_user_profile_package_path(userid, pkgname),
        /*ignore_if_missing*/ true);
}

binder::Status InstalldNativeService::destroyAppProfiles(const std::string& packageName) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* pkgname = packageName.c_str();
    binder::Status res = ok();
    std::vector<userid_t> users = get_known_users(/*volume_uuid*/ nullptr);
    for (auto user : users) {
        if (destroy_app_current_profiles(pkgname, user) != 0) {
            res = error("Failed to destroy current profiles for " + packageName);
        }
    }
    if (destroy_app_reference_profile(pkgname) != 0) {
        res = error("Failed to destroy reference profile for " + packageName);
    }
    return res;
}

binder::Status InstalldNativeService::destroyAppData(const std::unique_ptr<std::string>& uuid,
        const std::string& packageName, int32_t userId, int32_t flags, int64_t ceDataInode) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* uuid_ = uuid ? uuid->c_str() : nullptr;
    const char* pkgname = packageName.c_str();

    binder::Status res = ok();
    if (flags & FLAG_STORAGE_CE) {
        auto path = create_data_user_ce_package_path(uuid_, userId, pkgname, ceDataInode);
        if (delete_dir_contents_and_dir(path) != 0) {
            res = error("Failed to delete " + path);
        }
    }
    if (flags & FLAG_STORAGE_DE) {
        auto path = create_data_user_de_package_path(uuid_, userId, pkgname);
        if (delete_dir_contents_and_dir(path) != 0) {
            res = error("Failed to delete " + path);
        }
        destroy_app_current_profiles(pkgname, userId);
        // TODO(calin): If the package is still installed by other users it's probably
        // beneficial to keep the reference profile around.
        // Verify if it's ok to do that.
        destroy_app_reference_profile(pkgname);
    }
    return res;
}

binder::Status InstalldNativeService::moveCompleteApp(const std::unique_ptr<std::string>& fromUuid,
        const std::unique_ptr<std::string>& toUuid, const std::string& packageName,
        const std::string& dataAppName, int32_t appId, const std::string& seInfo,
        int32_t targetSdkVersion) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(fromUuid);
    CHECK_ARGUMENT_UUID(toUuid);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* from_uuid = fromUuid ? fromUuid->c_str() : nullptr;
    const char* to_uuid = toUuid ? toUuid->c_str() : nullptr;
    const char* package_name = packageName.c_str();
    const char* data_app_name = dataAppName.c_str();

    binder::Status res = ok();
    std::vector<userid_t> users = get_known_users(from_uuid);

    // Copy app
    {
        auto from = create_data_app_package_path(from_uuid, data_app_name);
        auto to = create_data_app_package_path(to_uuid, data_app_name);
        auto to_parent = create_data_app_path(to_uuid);

        char *argv[] = {
            (char*) kCpPath,
            (char*) "-F", /* delete any existing destination file first (--remove-destination) */
            (char*) "-p", /* preserve timestamps, ownership, and permissions */
            (char*) "-R", /* recurse into subdirectories (DEST must be a directory) */
            (char*) "-P", /* Do not follow symlinks [default] */
            (char*) "-d", /* don't dereference symlinks */
            (char*) from.c_str(),
            (char*) to_parent.c_str()
        };

        LOG(DEBUG) << "Copying " << from << " to " << to;
        int rc = android_fork_execvp(ARRAY_SIZE(argv), argv, NULL, false, true);
        if (rc != 0) {
            res = error(rc, "Failed copying " + from + " to " + to);
            goto fail;
        }

        if (selinux_android_restorecon(to.c_str(), SELINUX_ANDROID_RESTORECON_RECURSE) != 0) {
            res = error("Failed to restorecon " + to);
            goto fail;
        }
    }

    // Copy private data for all known users
    for (auto user : users) {

        // Data source may not exist for all users; that's okay
        auto from_ce = create_data_user_ce_package_path(from_uuid, user, package_name);
        if (access(from_ce.c_str(), F_OK) != 0) {
            LOG(INFO) << "Missing source " << from_ce;
            continue;
        }

        if (!createAppData(toUuid, packageName, user, FLAG_STORAGE_CE | FLAG_STORAGE_DE, appId,
                seInfo, targetSdkVersion).isOk()) {
            res = error("Failed to create package target");
            goto fail;
        }

        char *argv[] = {
            (char*) kCpPath,
            (char*) "-F", /* delete any existing destination file first (--remove-destination) */
            (char*) "-p", /* preserve timestamps, ownership, and permissions */
            (char*) "-R", /* recurse into subdirectories (DEST must be a directory) */
            (char*) "-P", /* Do not follow symlinks [default] */
            (char*) "-d", /* don't dereference symlinks */
            nullptr,
            nullptr
        };

        {
            auto from = create_data_user_de_package_path(from_uuid, user, package_name);
            auto to = create_data_user_de_path(to_uuid, user);
            argv[6] = (char*) from.c_str();
            argv[7] = (char*) to.c_str();

            LOG(DEBUG) << "Copying " << from << " to " << to;
            int rc = android_fork_execvp(ARRAY_SIZE(argv), argv, NULL, false, true);
            if (rc != 0) {
                res = error(rc, "Failed copying " + from + " to " + to);
                goto fail;
            }
        }
        {
            auto from = create_data_user_ce_package_path(from_uuid, user, package_name);
            auto to = create_data_user_ce_path(to_uuid, user);
            argv[6] = (char*) from.c_str();
            argv[7] = (char*) to.c_str();

            LOG(DEBUG) << "Copying " << from << " to " << to;
            int rc = android_fork_execvp(ARRAY_SIZE(argv), argv, NULL, false, true);
            if (rc != 0) {
                res = error(rc, "Failed copying " + from + " to " + to);
                goto fail;
            }
        }

        if (!restoreconAppData(toUuid, packageName, user, FLAG_STORAGE_CE | FLAG_STORAGE_DE,
                appId, seInfo).isOk()) {
            res = error("Failed to restorecon");
            goto fail;
        }
    }

    // We let the framework scan the new location and persist that before
    // deleting the data in the old location; this ordering ensures that
    // we can recover from things like battery pulls.
    return ok();

fail:
    // Nuke everything we might have already copied
    {
        auto to = create_data_app_package_path(to_uuid, data_app_name);
        if (delete_dir_contents(to.c_str(), 1, NULL) != 0) {
            LOG(WARNING) << "Failed to rollback " << to;
        }
    }
    for (auto user : users) {
        {
            auto to = create_data_user_de_package_path(to_uuid, user, package_name);
            if (delete_dir_contents(to.c_str(), 1, NULL) != 0) {
                LOG(WARNING) << "Failed to rollback " << to;
            }
        }
        {
            auto to = create_data_user_ce_package_path(to_uuid, user, package_name);
            if (delete_dir_contents(to.c_str(), 1, NULL) != 0) {
                LOG(WARNING) << "Failed to rollback " << to;
            }
        }
    }
    return res;
}

binder::Status InstalldNativeService::createUserData(const std::unique_ptr<std::string>& uuid,
        int32_t userId, int32_t userSerial ATTRIBUTE_UNUSED, int32_t flags) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);

    const char* uuid_ = uuid ? uuid->c_str() : nullptr;
    if (flags & FLAG_STORAGE_DE) {
        if (uuid_ == nullptr) {
            if (ensure_config_user_dirs(userId) != 0) {
                return error(StringPrintf("Failed to ensure dirs for %d", userId));
            }
        }
    }
    return ok();
}

binder::Status InstalldNativeService::destroyUserData(const std::unique_ptr<std::string>& uuid,
        int32_t userId, int32_t flags) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);

    const char* uuid_ = uuid ? uuid->c_str() : nullptr;
    binder::Status res = ok();
    if (flags & FLAG_STORAGE_DE) {
        auto path = create_data_user_de_path(uuid_, userId);
        if (delete_dir_contents_and_dir(path, true) != 0) {
            res = error("Failed to delete " + path);
        }
        if (uuid_ == nullptr) {
            path = create_data_misc_legacy_path(userId);
            if (delete_dir_contents_and_dir(path, true) != 0) {
                res = error("Failed to delete " + path);
            }
            path = create_data_user_profiles_path(userId);
            if (delete_dir_contents_and_dir(path, true) != 0) {
                res = error("Failed to delete " + path);
            }
        }
    }
    if (flags & FLAG_STORAGE_CE) {
        auto path = create_data_user_ce_path(uuid_, userId);
        if (delete_dir_contents_and_dir(path, true) != 0) {
            res = error("Failed to delete " + path);
        }
        path = create_data_media_path(uuid_, userId);
        if (delete_dir_contents_and_dir(path, true) != 0) {
            res = error("Failed to delete " + path);
        }
    }
    return res;
}

/* Try to ensure free_size bytes of storage are available.
 * Returns 0 on success.
 * This is rather simple-minded because doing a full LRU would
 * be potentially memory-intensive, and without atime it would
 * also require that apps constantly modify file metadata even
 * when just reading from the cache, which is pretty awful.
 */
binder::Status InstalldNativeService::freeCache(const std::unique_ptr<std::string>& uuid,
        int64_t freeStorageSize) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);

    const char* uuid_ = uuid ? uuid->c_str() : nullptr;
    cache_t* cache;
    int64_t avail;

    auto data_path = create_data_path(uuid_);

    avail = data_disk_free(data_path);
    if (avail < 0) {
        return error("Failed to determine free space for " + data_path);
    }

    ALOGI("free_cache(%" PRId64 ") avail %" PRId64 "\n", freeStorageSize, avail);
    if (avail >= freeStorageSize) {
        return ok();
    }

    cache = start_cache_collection();

    auto users = get_known_users(uuid_);
    for (auto user : users) {
        add_cache_files(cache, create_data_user_ce_path(uuid_, user));
        add_cache_files(cache, create_data_user_de_path(uuid_, user));
        add_cache_files(cache,
                StringPrintf("%s/Android/data", create_data_media_path(uuid_, user).c_str()));
    }

    clear_cache_files(data_path, cache, freeStorageSize);
    finish_cache_collection(cache);

    avail = data_disk_free(data_path);
    if (avail >= freeStorageSize) {
        return ok();
    } else {
        return error(StringPrintf("Failed to free up %" PRId64 " on %s; final free space %" PRId64,
                freeStorageSize, data_path.c_str(), avail));
    }
}

binder::Status InstalldNativeService::rmdex(const std::string& codePath,
        const std::string& instructionSet) {
    ENFORCE_UID(AID_SYSTEM);
    char dex_path[PKG_PATH_MAX];

    const char* path = codePath.c_str();
    const char* instruction_set = instructionSet.c_str();

    if (validate_apk_path(path) && validate_system_app_path(path)) {
        return error("Invalid path " + codePath);
    }

    if (!create_cache_path(dex_path, path, instruction_set)) {
        return error("Failed to create cache path for " + codePath);
    }

    ALOGV("unlink %s\n", dex_path);
    if (unlink(dex_path) < 0) {
        return error(StringPrintf("Failed to unlink %s", dex_path));
    } else {
        return ok();
    }
}

static void add_app_data_size(std::string& path, int64_t *codesize, int64_t *datasize,
        int64_t *cachesize) {
    DIR *d;
    int dfd;
    struct dirent *de;
    struct stat s;

    d = opendir(path.c_str());
    if (d == nullptr) {
        PLOG(WARNING) << "Failed to open " << path;
        return;
    }
    dfd = dirfd(d);
    while ((de = readdir(d))) {
        const char *name = de->d_name;

        int64_t statsize = 0;
        if (fstatat(dfd, name, &s, AT_SYMLINK_NOFOLLOW) == 0) {
            statsize = stat_size(&s);
        }

        if (de->d_type == DT_DIR) {
            int subfd;
            int64_t dirsize = 0;
            /* always skip "." and ".." */
            if (name[0] == '.') {
                if (name[1] == 0) continue;
                if ((name[1] == '.') && (name[2] == 0)) continue;
            }
            subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
            if (subfd >= 0) {
                dirsize = calculate_dir_size(subfd);
                close(subfd);
            }
            // TODO: check xattrs!
            if (!strcmp(name, "cache") || !strcmp(name, "code_cache")) {
                *datasize += statsize;
                *cachesize += dirsize;
            } else {
                *datasize += dirsize + statsize;
            }
        } else if (de->d_type == DT_LNK && !strcmp(name, "lib")) {
            *codesize += statsize;
        } else {
            *datasize += statsize;
        }
    }
    closedir(d);
}

binder::Status InstalldNativeService::getAppSize(const std::unique_ptr<std::string>& uuid,
        const std::string& packageName, int32_t userId, int32_t flags, int64_t ceDataInode,
        const std::string& codePath, std::vector<int64_t>* _aidl_return) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* uuid_ = uuid ? uuid->c_str() : nullptr;
    const char* pkgname = packageName.c_str();
    const char* code_path = codePath.c_str();

    DIR *d;
    int dfd;
    int64_t codesize = 0;
    int64_t datasize = 0;
    int64_t cachesize = 0;
    int64_t asecsize = 0;

    d = opendir(code_path);
    if (d != nullptr) {
        dfd = dirfd(d);
        codesize += calculate_dir_size(dfd);
        closedir(d);
    }

    if (flags & FLAG_STORAGE_CE) {
        auto path = create_data_user_ce_package_path(uuid_, userId, pkgname, ceDataInode);
        add_app_data_size(path, &codesize, &datasize, &cachesize);
    }
    if (flags & FLAG_STORAGE_DE) {
        auto path = create_data_user_de_package_path(uuid_, userId, pkgname);
        add_app_data_size(path, &codesize, &datasize, &cachesize);
    }

    std::vector<int64_t> res;
    res.push_back(codesize);
    res.push_back(datasize);
    res.push_back(cachesize);
    res.push_back(asecsize);
    *_aidl_return = res;
    return ok();
}

binder::Status InstalldNativeService::getAppDataInode(const std::unique_ptr<std::string>& uuid,
        const std::string& packageName, int32_t userId, int32_t flags, int64_t* _aidl_return) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* uuid_ = uuid ? uuid->c_str() : nullptr;
    const char* pkgname = packageName.c_str();

    if (flags & FLAG_STORAGE_CE) {
        auto path = create_data_user_ce_package_path(uuid_, userId, pkgname);
        if (get_path_inode(path, reinterpret_cast<ino_t*>(_aidl_return)) == 0) {
            return ok();
        } else {
            return error("Failed to get_path_inode for " + path);
        }
    }
    return exception(binder::Status::EX_UNSUPPORTED_OPERATION);
}

// Dumps the contents of a profile file, using pkgname's dex files for pretty
// printing the result.
binder::Status InstalldNativeService::dumpProfiles(int32_t uid, const std::string& packageName,
        const std::string& codePaths, bool* _aidl_return) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* pkgname = packageName.c_str();
    const char* code_paths = codePaths.c_str();

    *_aidl_return = dump_profiles(uid, pkgname, code_paths);
    return ok();
}

// TODO: Consider returning error codes.
binder::Status InstalldNativeService::mergeProfiles(int32_t uid, const std::string& packageName,
        bool* _aidl_return) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* pkgname = packageName.c_str();
    *_aidl_return = analyse_profiles(uid, pkgname);
    return ok();
}

binder::Status InstalldNativeService::dexopt(const std::string& apkPath, int32_t uid,
        const std::unique_ptr<std::string>& packageName, const std::string& instructionSet,
        int32_t dexoptNeeded, const std::unique_ptr<std::string>& outputPath, int32_t dexFlags,
        const std::string& compilerFilter, const std::unique_ptr<std::string>& uuid,
        const std::unique_ptr<std::string>& sharedLibraries) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);
    if (packageName && *packageName != "*") {
        CHECK_ARGUMENT_PACKAGE_NAME(*packageName);
    }

    const char* apk_path = apkPath.c_str();
    const char* pkgname = packageName ? packageName->c_str() : "*";
    const char* instruction_set = instructionSet.c_str();
    const char* oat_dir = outputPath ? outputPath->c_str() : nullptr;
    const char* compiler_filter = compilerFilter.c_str();
    const char* volume_uuid = uuid ? uuid->c_str() : nullptr;
    const char* shared_libraries = sharedLibraries ? sharedLibraries->c_str() : nullptr;

    int res = android::installd::dexopt(apk_path, uid, pkgname, instruction_set, dexoptNeeded,
            oat_dir, dexFlags, compiler_filter, volume_uuid, shared_libraries);
    return res ? error(res, "Failed to dexopt") : ok();
}

binder::Status InstalldNativeService::markBootComplete(const std::string& instructionSet) {
    ENFORCE_UID(AID_SYSTEM);
    const char* instruction_set = instructionSet.c_str();

    char boot_marker_path[PKG_PATH_MAX];
    sprintf(boot_marker_path,
          "%s/%s/%s/.booting",
          android_data_dir.path,
          DALVIK_CACHE,
          instruction_set);

    ALOGV("mark_boot_complete : %s", boot_marker_path);
    if (unlink(boot_marker_path) != 0) {
        return error(StringPrintf("Failed to unlink %s", boot_marker_path));
    }
    return ok();
}

void mkinnerdirs(char* path, int basepos, mode_t mode, int uid, int gid,
        struct stat* statbuf)
{
    while (path[basepos] != 0) {
        if (path[basepos] == '/') {
            path[basepos] = 0;
            if (lstat(path, statbuf) < 0) {
                ALOGV("Making directory: %s\n", path);
                if (mkdir(path, mode) == 0) {
                    chown(path, uid, gid);
                } else {
                    ALOGW("Unable to make directory %s: %s\n", path, strerror(errno));
                }
            }
            path[basepos] = '/';
            basepos++;
        }
        basepos++;
    }
}

binder::Status InstalldNativeService::linkNativeLibraryDirectory(
        const std::unique_ptr<std::string>& uuid, const std::string& packageName,
        const std::string& nativeLibPath32, int32_t userId) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    const char* uuid_ = uuid ? uuid->c_str() : nullptr;
    const char* pkgname = packageName.c_str();
    const char* asecLibDir = nativeLibPath32.c_str();
    struct stat s, libStat;
    binder::Status res = ok();

    auto _pkgdir = create_data_user_ce_package_path(uuid_, userId, pkgname);
    auto _libsymlink = _pkgdir + PKG_LIB_POSTFIX;

    const char* pkgdir = _pkgdir.c_str();
    const char* libsymlink = _libsymlink.c_str();

    if (stat(pkgdir, &s) < 0) {
        return error("Failed to stat " + _pkgdir);
    }

    if (chown(pkgdir, AID_INSTALL, AID_INSTALL) < 0) {
        return error("Failed to chown " + _pkgdir);
    }

    if (chmod(pkgdir, 0700) < 0) {
        res = error("Failed to chmod " + _pkgdir);
        goto out;
    }

    if (lstat(libsymlink, &libStat) < 0) {
        if (errno != ENOENT) {
            res = error("Failed to stat " + _libsymlink);
            goto out;
        }
    } else {
        if (S_ISDIR(libStat.st_mode)) {
            if (delete_dir_contents(libsymlink, 1, NULL) < 0) {
                res = error("Failed to delete " + _libsymlink);
                goto out;
            }
        } else if (S_ISLNK(libStat.st_mode)) {
            if (unlink(libsymlink) < 0) {
                res = error("Failed to unlink " + _libsymlink);
                goto out;
            }
        }
    }

    if (symlink(asecLibDir, libsymlink) < 0) {
        res = error("Failed to symlink " + _libsymlink + " to " + nativeLibPath32);
        goto out;
    }

out:
    if (chmod(pkgdir, s.st_mode) < 0) {
        auto msg = "Failed to cleanup chmod " + _pkgdir;
        if (res.isOk()) {
            res = error(msg);
        } else {
            PLOG(ERROR) << msg;
        }
    }

    if (chown(pkgdir, s.st_uid, s.st_gid) < 0) {
        auto msg = "Failed to cleanup chown " + _pkgdir;
        if (res.isOk()) {
            res = error(msg);
        } else {
            PLOG(ERROR) << msg;
        }
    }

    return res;
}

static void run_idmap(const char *target_apk, const char *overlay_apk, int idmap_fd)
{
    static const char *IDMAP_BIN = "/system/bin/idmap";
    static const size_t MAX_INT_LEN = 32;
    char idmap_str[MAX_INT_LEN];

    snprintf(idmap_str, sizeof(idmap_str), "%d", idmap_fd);

    execl(IDMAP_BIN, IDMAP_BIN, "--fd", target_apk, overlay_apk, idmap_str, (char*)NULL);
    ALOGE("execl(%s) failed: %s\n", IDMAP_BIN, strerror(errno));
}

// Transform string /a/b/c.apk to (prefix)/a@b@c.apk@(suffix)
// eg /a/b/c.apk to /data/resource-cache/a@b@c.apk@idmap
static int flatten_path(const char *prefix, const char *suffix,
        const char *overlay_path, char *idmap_path, size_t N)
{
    if (overlay_path == NULL || idmap_path == NULL) {
        return -1;
    }
    const size_t len_overlay_path = strlen(overlay_path);
    // will access overlay_path + 1 further below; requires absolute path
    if (len_overlay_path < 2 || *overlay_path != '/') {
        return -1;
    }
    const size_t len_idmap_root = strlen(prefix);
    const size_t len_suffix = strlen(suffix);
    if (SIZE_MAX - len_idmap_root < len_overlay_path ||
            SIZE_MAX - (len_idmap_root + len_overlay_path) < len_suffix) {
        // additions below would cause overflow
        return -1;
    }
    if (N < len_idmap_root + len_overlay_path + len_suffix) {
        return -1;
    }
    memset(idmap_path, 0, N);
    snprintf(idmap_path, N, "%s%s%s", prefix, overlay_path + 1, suffix);
    char *ch = idmap_path + len_idmap_root;
    while (*ch != '\0') {
        if (*ch == '/') {
            *ch = '@';
        }
        ++ch;
    }
    return 0;
}

binder::Status InstalldNativeService::idmap(const std::string& targetApkPath,
        const std::string& overlayApkPath, int32_t uid) {
    ENFORCE_UID(AID_SYSTEM);
    const char* target_apk = targetApkPath.c_str();
    const char* overlay_apk = overlayApkPath.c_str();
    ALOGV("idmap target_apk=%s overlay_apk=%s uid=%d\n", target_apk, overlay_apk, uid);

    int idmap_fd = -1;
    char idmap_path[PATH_MAX];

    if (flatten_path(IDMAP_PREFIX, IDMAP_SUFFIX, overlay_apk,
                idmap_path, sizeof(idmap_path)) == -1) {
        ALOGE("idmap cannot generate idmap path for overlay %s\n", overlay_apk);
        goto fail;
    }

    unlink(idmap_path);
    idmap_fd = open(idmap_path, O_RDWR | O_CREAT | O_EXCL, 0644);
    if (idmap_fd < 0) {
        ALOGE("idmap cannot open '%s' for output: %s\n", idmap_path, strerror(errno));
        goto fail;
    }
    if (fchown(idmap_fd, AID_SYSTEM, uid) < 0) {
        ALOGE("idmap cannot chown '%s'\n", idmap_path);
        goto fail;
    }
    if (fchmod(idmap_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) < 0) {
        ALOGE("idmap cannot chmod '%s'\n", idmap_path);
        goto fail;
    }

    pid_t pid;
    pid = fork();
    if (pid == 0) {
        /* child -- drop privileges before continuing */
        if (setgid(uid) != 0) {
            ALOGE("setgid(%d) failed during idmap\n", uid);
            exit(1);
        }
        if (setuid(uid) != 0) {
            ALOGE("setuid(%d) failed during idmap\n", uid);
            exit(1);
        }
        if (flock(idmap_fd, LOCK_EX | LOCK_NB) != 0) {
            ALOGE("flock(%s) failed during idmap: %s\n", idmap_path, strerror(errno));
            exit(1);
        }

        run_idmap(target_apk, overlay_apk, idmap_fd);
        exit(1); /* only if exec call to idmap failed */
    } else {
        int status = wait_child(pid);
        if (status != 0) {
            ALOGE("idmap failed, status=0x%04x\n", status);
            goto fail;
        }
    }

    close(idmap_fd);
    return ok();
fail:
    if (idmap_fd >= 0) {
        close(idmap_fd);
        unlink(idmap_path);
    }
    return error();
}

binder::Status InstalldNativeService::restoreconAppData(const std::unique_ptr<std::string>& uuid,
        const std::string& packageName, int32_t userId, int32_t flags, int32_t appId,
        const std::string& seInfo) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_UUID(uuid);
    CHECK_ARGUMENT_PACKAGE_NAME(packageName);

    binder::Status res = ok();

    // SELINUX_ANDROID_RESTORECON_DATADATA flag is set by libselinux. Not needed here.
    unsigned int seflags = SELINUX_ANDROID_RESTORECON_RECURSE;
    const char* uuid_ = uuid ? uuid->c_str() : nullptr;
    const char* pkgName = packageName.c_str();
    const char* seinfo = seInfo.c_str();

    uid_t uid = multiuser_get_uid(userId, appId);
    if (flags & FLAG_STORAGE_CE) {
        auto path = create_data_user_ce_package_path(uuid_, userId, pkgName);
        if (selinux_android_restorecon_pkgdir(path.c_str(), seinfo, uid, seflags) < 0) {
            res = error("restorecon failed for " + path);
        }
    }
    if (flags & FLAG_STORAGE_DE) {
        auto path = create_data_user_de_package_path(uuid_, userId, pkgName);
        if (selinux_android_restorecon_pkgdir(path.c_str(), seinfo, uid, seflags) < 0) {
            res = error("restorecon failed for " + path);
        }
    }
    return res;
}

binder::Status InstalldNativeService::createOatDir(const std::string& oatDir,
        const std::string& instructionSet) {
    ENFORCE_UID(AID_SYSTEM);
    const char* oat_dir = oatDir.c_str();
    const char* instruction_set = instructionSet.c_str();
    char oat_instr_dir[PKG_PATH_MAX];

    if (validate_apk_path(oat_dir)) {
        return error("Invalid path " + oatDir);
    }
    if (fs_prepare_dir(oat_dir, S_IRWXU | S_IRWXG | S_IXOTH, AID_SYSTEM, AID_INSTALL)) {
        return error("Failed to prepare " + oatDir);
    }
    if (selinux_android_restorecon(oat_dir, 0)) {
        return error("Failed to restorecon " + oatDir);
    }
    snprintf(oat_instr_dir, PKG_PATH_MAX, "%s/%s", oat_dir, instruction_set);
    if (fs_prepare_dir(oat_instr_dir, S_IRWXU | S_IRWXG | S_IXOTH, AID_SYSTEM, AID_INSTALL)) {
        return error(StringPrintf("Failed to prepare %s", oat_instr_dir));
    }
    return ok();
}

binder::Status InstalldNativeService::rmPackageDir(const std::string& packageDir) {
    ENFORCE_UID(AID_SYSTEM);
    if (validate_apk_path(packageDir.c_str())) {
        return error("Invalid path " + packageDir);
    }
    if (delete_dir_contents_and_dir(packageDir) != 0) {
        return error("Failed to delete " + packageDir);
    }
    return ok();
}

binder::Status InstalldNativeService::linkFile(const std::string& relativePath,
        const std::string& fromBase, const std::string& toBase) {
    ENFORCE_UID(AID_SYSTEM);
    const char* relative_path = relativePath.c_str();
    const char* from_base = fromBase.c_str();
    const char* to_base = toBase.c_str();
    char from_path[PKG_PATH_MAX];
    char to_path[PKG_PATH_MAX];
    snprintf(from_path, PKG_PATH_MAX, "%s/%s", from_base, relative_path);
    snprintf(to_path, PKG_PATH_MAX, "%s/%s", to_base, relative_path);

    if (validate_apk_path_subdirs(from_path)) {
        return error(StringPrintf("Invalid from path %s", from_path));
    }

    if (validate_apk_path_subdirs(to_path)) {
        return error(StringPrintf("Invalid to path %s", to_path));
    }

    if (link(from_path, to_path) < 0) {
        return error(StringPrintf("Failed to link from %s to %s", from_path, to_path));
    }

    return ok();
}

binder::Status InstalldNativeService::moveAb(const std::string& apkPath,
        const std::string& instructionSet, const std::string& outputPath) {
    ENFORCE_UID(AID_SYSTEM);

    const char* apk_path = apkPath.c_str();
    const char* instruction_set = instructionSet.c_str();
    const char* oat_dir = outputPath.c_str();

    bool success = move_ab(apk_path, instruction_set, oat_dir);
    return success ? ok() : error();
}

binder::Status InstalldNativeService::deleteOdex(const std::string& apkPath,
        const std::string& instructionSet, const std::string& outputPath) {
    ENFORCE_UID(AID_SYSTEM);

    const char* apk_path = apkPath.c_str();
    const char* instruction_set = instructionSet.c_str();
    const char* oat_dir = outputPath.c_str();

    bool res = delete_odex(apk_path, instruction_set, oat_dir);
    return res ? ok() : error();
}

}  // namespace installd
}  // namespace android
