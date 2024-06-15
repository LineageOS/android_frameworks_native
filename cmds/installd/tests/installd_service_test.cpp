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

#include <sstream>
#include <string>

#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>
#include <cutils/properties.h>
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include <android/content/pm/IPackageManagerNative.h>
#include <binder/IServiceManager.h>
#include "InstalldNativeService.h"
#include "binder/Status.h"
#include "binder_test_utils.h"
#include "dexopt.h"
#include "globals.h"
#include "unique_file.h"
#include "utils.h"

using android::base::StringPrintf;
using android::base::unique_fd;
using android::os::ParcelFileDescriptor;
using std::filesystem::is_empty;

namespace android {
std::string get_package_name(uid_t uid) {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<content::pm::IPackageManagerNative> package_mgr;
    if (sm.get() == nullptr) {
        LOG(INFO) << "Cannot find service manager";
    } else {
        sp<IBinder> binder = sm->getService(String16("package_native"));
        if (binder.get() == nullptr) {
            LOG(INFO) << "Cannot find package_native";
        } else {
            package_mgr = interface_cast<content::pm::IPackageManagerNative>(binder);
        }
    }
    // find package name
    std::string pkg;
    if (package_mgr != nullptr) {
        std::vector<std::string> names;
        binder::Status status = package_mgr->getNamesForUids({(int)uid}, &names);
        if (!status.isOk()) {
            LOG(INFO) << "getNamesForUids failed: %s", status.exceptionMessage().c_str();
        } else {
            if (!names[0].empty()) {
                pkg = names[0].c_str();
            }
        }
    }
    return pkg;
}
namespace installd {

static constexpr const char* kTestUuid = "TEST";
static const std::string kTestPath = "/data/local/tmp";
static constexpr const uid_t kNobodyUid = 9999;
static constexpr const uid_t kSystemUid = 1000;
static constexpr const int32_t kTestUserId = 0;
static constexpr const uid_t kTestAppId = 19999;
static constexpr const int FLAG_STORAGE_SDK = InstalldNativeService::FLAG_STORAGE_SDK;
static constexpr const int FLAG_CLEAR_CACHE_ONLY = InstalldNativeService::FLAG_CLEAR_CACHE_ONLY;
static constexpr const int FLAG_CLEAR_CODE_CACHE_ONLY =
        InstalldNativeService::FLAG_CLEAR_CODE_CACHE_ONLY;

const gid_t kTestAppUid = multiuser_get_uid(kTestUserId, kTestAppId);
const gid_t kTestCacheGid = multiuser_get_cache_gid(kTestUserId, kTestAppId);
const uid_t kTestSdkSandboxUid = multiuser_get_sdk_sandbox_uid(kTestUserId, kTestAppId);

#define FLAG_FORCE InstalldNativeService::FLAG_FORCE

int get_property(const char *key, char *value, const char *default_value) {
    return property_get(key, value, default_value);
}

bool calculate_oat_file_path(char path[PKG_PATH_MAX], const char *oat_dir, const char *apk_path,
        const char *instruction_set) {
    return calculate_oat_file_path_default(path, oat_dir, apk_path, instruction_set);
}

bool calculate_odex_file_path(char path[PKG_PATH_MAX], const char *apk_path,
        const char *instruction_set) {
    return calculate_odex_file_path_default(path, apk_path, instruction_set);
}

bool create_cache_path(char path[PKG_PATH_MAX], const char *src, const char *instruction_set) {
    return create_cache_path_default(path, src, instruction_set);
}

bool force_compile_without_image() {
    return false;
}

static std::string get_full_path(const std::string& path) {
    return StringPrintf("%s/%s", kTestPath.c_str(), path.c_str());
}

static void mkdir(const std::string& path, uid_t owner, gid_t group, mode_t mode) {
    const std::string fullPath = get_full_path(path);
    EXPECT_EQ(::mkdir(fullPath.c_str(), mode), 0);
    EXPECT_EQ(::chown(fullPath.c_str(), owner, group), 0);
    EXPECT_EQ(::chmod(fullPath.c_str(), mode), 0);
}

static int create(const std::string& path, uid_t owner, gid_t group, mode_t mode) {
    int fd = ::open(get_full_path(path).c_str(), O_RDWR | O_CREAT, mode);
    EXPECT_NE(fd, -1);
    EXPECT_EQ(::fchown(fd, owner, group), 0);
    EXPECT_EQ(::fchmod(fd, mode), 0);
    return fd;
}

static void create_with_content(const std::string& path, uid_t owner, gid_t group, mode_t mode,
                                const std::string& content) {
    int fd = ::open(path.c_str(), O_RDWR | O_CREAT, mode);
    EXPECT_NE(fd, -1);
    EXPECT_TRUE(android::base::WriteStringToFd(content, fd));
    EXPECT_EQ(::fchown(fd, owner, group), 0);
    EXPECT_EQ(::fchmod(fd, mode), 0);
    close(fd);
}

static void touch(const std::string& path, uid_t owner, gid_t group, mode_t mode) {
    EXPECT_EQ(::close(create(path.c_str(), owner, group, mode)), 0);
}

static int stat_gid(const char* path) {
    struct stat buf;
    EXPECT_EQ(::stat(get_full_path(path).c_str(), &buf), 0);
    return buf.st_gid;
}

static int stat_mode(const char* path) {
    struct stat buf;
    EXPECT_EQ(::stat(get_full_path(path).c_str(), &buf), 0);
    return buf.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO | S_ISGID);
}

static bool exists(const std::string& path) {
    return ::access(get_full_path(path).c_str(), F_OK) == 0;
}

template <class Pred>
static bool find_file(const char* path, Pred&& pred) {
    bool result = false;
    auto d = opendir(path);
    if (d == nullptr) {
        return result;
    }
    struct dirent* de;
    while ((de = readdir(d))) {
        const char* name = de->d_name;
        if (pred(name, de->d_type == DT_DIR)) {
            result = true;
            break;
        }
    }
    closedir(d);
    return result;
}

static bool exists_renamed_deleted_dir(const std::string& rootDirectory) {
    return find_file((kTestPath + rootDirectory).c_str(), [](const std::string& name, bool is_dir) {
        return is_dir && is_renamed_deleted_dir(name);
    });
}

static void unlink_path(const std::string& path) {
    if (unlink(path.c_str()) < 0) {
        PLOG(DEBUG) << "Failed to unlink " + path;
    }
}

class ServiceTest : public testing::Test {
protected:
    InstalldNativeService* service;
    std::optional<std::string> testUuid;

    virtual void SetUp() {
        setenv("ANDROID_LOG_TAGS", "*:v", 1);
        android::base::InitLogging(nullptr);

        service = new InstalldNativeService();
        testUuid = kTestUuid;
        system("rm -rf /data/local/tmp/user");
        system("rm -rf /data/local/tmp/misc_ce");
        system("rm -rf /data/local/tmp/misc_de");
        system("mkdir -p /data/local/tmp/user/0");
        system("mkdir -p /data/local/tmp/misc_ce/0/sdksandbox");
        system("mkdir -p /data/local/tmp/misc_de/0/sdksandbox");
        init_globals_from_data_and_root();
    }

    virtual void TearDown() {
        delete service;
        system("rm -rf /data/local/tmp/user");
        system("rm -rf /data/local/tmp/misc_ce");
        system("rm -rf /data/local/tmp/misc_de");
    }
};

TEST_F(ServiceTest, FixupAppData_Upgrade) {
    LOG(INFO) << "FixupAppData_Upgrade";

    mkdir("user/0/com.example", 10000, 10000, 0700);
    mkdir("user/0/com.example/normal", 10000, 10000, 0700);
    mkdir("user/0/com.example/cache", 10000, 10000, 0700);
    touch("user/0/com.example/cache/file", 10000, 10000, 0700);

    service->fixupAppData(testUuid, 0);

    EXPECT_EQ(10000, stat_gid("user/0/com.example/normal"));
    EXPECT_EQ(20000, stat_gid("user/0/com.example/cache"));
    EXPECT_EQ(20000, stat_gid("user/0/com.example/cache/file"));

    EXPECT_EQ(0700, stat_mode("user/0/com.example/normal"));
    EXPECT_EQ(02771, stat_mode("user/0/com.example/cache"));
    EXPECT_EQ(0700, stat_mode("user/0/com.example/cache/file"));
}

TEST_F(ServiceTest, FixupAppData_Moved) {
    LOG(INFO) << "FixupAppData_Moved";

    mkdir("user/0/com.example", 10000, 10000, 0700);
    mkdir("user/0/com.example/foo", 10000, 10000, 0700);
    touch("user/0/com.example/foo/file", 10000, 20000, 0700);
    mkdir("user/0/com.example/bar", 10000, 20000, 0700);
    touch("user/0/com.example/bar/file", 10000, 20000, 0700);

    service->fixupAppData(testUuid, 0);

    EXPECT_EQ(10000, stat_gid("user/0/com.example/foo"));
    EXPECT_EQ(20000, stat_gid("user/0/com.example/foo/file"));
    EXPECT_EQ(10000, stat_gid("user/0/com.example/bar"));
    EXPECT_EQ(10000, stat_gid("user/0/com.example/bar/file"));

    service->fixupAppData(testUuid, FLAG_FORCE);

    EXPECT_EQ(10000, stat_gid("user/0/com.example/foo"));
    EXPECT_EQ(10000, stat_gid("user/0/com.example/foo/file"));
    EXPECT_EQ(10000, stat_gid("user/0/com.example/bar"));
    EXPECT_EQ(10000, stat_gid("user/0/com.example/bar/file"));
}

TEST_F(ServiceTest, DestroyUserData) {
    LOG(INFO) << "DestroyUserData";

    mkdir("user/0/com.example", 10000, 10000, 0700);
    mkdir("user/0/com.example/foo", 10000, 10000, 0700);
    touch("user/0/com.example/foo/file", 10000, 20000, 0700);
    mkdir("user/0/com.example/bar", 10000, 20000, 0700);
    touch("user/0/com.example/bar/file", 10000, 20000, 0700);

    EXPECT_TRUE(exists("user/0/com.example/foo"));
    EXPECT_TRUE(exists("user/0/com.example/foo/file"));
    EXPECT_TRUE(exists("user/0/com.example/bar"));
    EXPECT_TRUE(exists("user/0/com.example/bar/file"));

    service->destroyUserData(testUuid, 0, FLAG_STORAGE_DE | FLAG_STORAGE_CE);

    EXPECT_FALSE(exists("user/0/com.example/foo"));
    EXPECT_FALSE(exists("user/0/com.example/foo/file"));
    EXPECT_FALSE(exists("user/0/com.example/bar"));
    EXPECT_FALSE(exists("user/0/com.example/bar/file"));

    EXPECT_FALSE(exists_renamed_deleted_dir("/user/0"));
}

TEST_F(ServiceTest, DestroyAppData) {
    LOG(INFO) << "DestroyAppData";

    mkdir("user/0/com.example", 10000, 10000, 0700);
    mkdir("user/0/com.example/foo", 10000, 10000, 0700);
    touch("user/0/com.example/foo/file", 10000, 20000, 0700);
    mkdir("user/0/com.example/bar", 10000, 20000, 0700);
    touch("user/0/com.example/bar/file", 10000, 20000, 0700);

    EXPECT_TRUE(exists("user/0/com.example/foo"));
    EXPECT_TRUE(exists("user/0/com.example/foo/file"));
    EXPECT_TRUE(exists("user/0/com.example/bar"));
    EXPECT_TRUE(exists("user/0/com.example/bar/file"));

    service->destroyAppData(testUuid, "com.example", 0, FLAG_STORAGE_DE | FLAG_STORAGE_CE, 0);

    EXPECT_FALSE(exists("user/0/com.example/foo"));
    EXPECT_FALSE(exists("user/0/com.example/foo/file"));
    EXPECT_FALSE(exists("user/0/com.example/bar"));
    EXPECT_FALSE(exists("user/0/com.example/bar/file"));

    EXPECT_FALSE(exists_renamed_deleted_dir("/user/0"));
}

TEST_F(ServiceTest, CleanupInvalidPackageDirs) {
    LOG(INFO) << "CleanupInvalidPackageDirs";

    std::string rootDirectoryPrefix[] = {"user/0", "misc_ce/0/sdksandbox", "misc_de/0/sdksandbox"};
    for (auto& prefix : rootDirectoryPrefix) {
        mkdir(prefix + "/5b14b6458a44==deleted==", 10000, 10000, 0700);
        mkdir(prefix + "/5b14b6458a44==deleted==/foo", 10000, 10000, 0700);
        touch(prefix + "/5b14b6458a44==deleted==/foo/file", 10000, 20000, 0700);
        mkdir(prefix + "/5b14b6458a44==deleted==/bar", 10000, 20000, 0700);
        touch(prefix + "/5b14b6458a44==deleted==/bar/file", 10000, 20000, 0700);

        auto fd = create(prefix + "/5b14b6458a44==deleted==/bar/opened_file", 10000, 20000, 0700);

        mkdir(prefix + "/b14b6458a44NOTdeleted", 10000, 10000, 0700);
        mkdir(prefix + "/b14b6458a44NOTdeleted/foo", 10000, 10000, 0700);
        touch(prefix + "/b14b6458a44NOTdeleted/foo/file", 10000, 20000, 0700);
        mkdir(prefix + "/b14b6458a44NOTdeleted/bar", 10000, 20000, 0700);
        touch(prefix + "/b14b6458a44NOTdeleted/bar/file", 10000, 20000, 0700);

        mkdir(prefix + "/com.example", 10000, 10000, 0700);
        mkdir(prefix + "/com.example/foo", 10000, 10000, 0700);
        touch(prefix + "/com.example/foo/file", 10000, 20000, 0700);
        mkdir(prefix + "/com.example/bar", 10000, 20000, 0700);
        touch(prefix + "/com.example/bar/file", 10000, 20000, 0700);

        mkdir(prefix + "/==deleted==", 10000, 10000, 0700);
        mkdir(prefix + "/==deleted==/foo", 10000, 10000, 0700);
        touch(prefix + "/==deleted==/foo/file", 10000, 20000, 0700);
        mkdir(prefix + "/==deleted==/bar", 10000, 20000, 0700);
        touch(prefix + "/==deleted==/bar/file", 10000, 20000, 0700);

        EXPECT_TRUE(exists(prefix + "/5b14b6458a44==deleted==/foo"));
        EXPECT_TRUE(exists(prefix + "/5b14b6458a44==deleted==/foo/file"));
        EXPECT_TRUE(exists(prefix + "/5b14b6458a44==deleted==/bar"));
        EXPECT_TRUE(exists(prefix + "/5b14b6458a44==deleted==/bar/file"));
        EXPECT_TRUE(exists(prefix + "/5b14b6458a44==deleted==/bar/opened_file"));

        EXPECT_TRUE(exists(prefix + "/b14b6458a44NOTdeleted/foo"));
        EXPECT_TRUE(exists(prefix + "/b14b6458a44NOTdeleted/foo/file"));
        EXPECT_TRUE(exists(prefix + "/b14b6458a44NOTdeleted/bar"));
        EXPECT_TRUE(exists(prefix + "/b14b6458a44NOTdeleted/bar/file"));

        EXPECT_TRUE(exists(prefix + "/com.example/foo"));
        EXPECT_TRUE(exists(prefix + "/com.example/foo/file"));
        EXPECT_TRUE(exists(prefix + "/com.example/bar"));
        EXPECT_TRUE(exists(prefix + "/com.example/bar/file"));

        EXPECT_TRUE(exists(prefix + "/==deleted==/foo"));
        EXPECT_TRUE(exists(prefix + "/==deleted==/foo/file"));
        EXPECT_TRUE(exists(prefix + "/==deleted==/bar"));
        EXPECT_TRUE(exists(prefix + "/==deleted==/bar/file"));

        EXPECT_TRUE(exists_renamed_deleted_dir("/" + prefix));

        service->cleanupInvalidPackageDirs(testUuid, 0, FLAG_STORAGE_CE | FLAG_STORAGE_DE);

        EXPECT_EQ(::close(fd), 0);

        EXPECT_FALSE(exists(prefix + "/5b14b6458a44==deleted==/foo"));
        EXPECT_FALSE(exists(prefix + "/5b14b6458a44==deleted==/foo/file"));
        EXPECT_FALSE(exists(prefix + "/5b14b6458a44==deleted==/bar"));
        EXPECT_FALSE(exists(prefix + "/5b14b6458a44==deleted==/bar/file"));
        EXPECT_FALSE(exists(prefix + "/5b14b6458a44==deleted==/bar/opened_file"));

        EXPECT_TRUE(exists(prefix + "/b14b6458a44NOTdeleted/foo"));
        EXPECT_TRUE(exists(prefix + "/b14b6458a44NOTdeleted/foo/file"));
        EXPECT_TRUE(exists(prefix + "/b14b6458a44NOTdeleted/bar"));
        EXPECT_TRUE(exists(prefix + "/b14b6458a44NOTdeleted/bar/file"));

        EXPECT_TRUE(exists(prefix + "/com.example/foo"));
        EXPECT_TRUE(exists(prefix + "/com.example/foo/file"));
        EXPECT_TRUE(exists(prefix + "/com.example/bar"));
        EXPECT_TRUE(exists(prefix + "/com.example/bar/file"));

        EXPECT_FALSE(exists(prefix + "/==deleted==/foo"));
        EXPECT_FALSE(exists(prefix + "/==deleted==/foo/file"));
        EXPECT_FALSE(exists(prefix + "/==deleted==/bar"));
        EXPECT_FALSE(exists(prefix + "/==deleted==/bar/file"));

        EXPECT_FALSE(exists_renamed_deleted_dir(prefix));
    }
}

TEST_F(ServiceTest, HashSecondaryDex) {
    LOG(INFO) << "HashSecondaryDex";

    mkdir("user/0/com.example", 10000, 10000, 0700);
    mkdir("user/0/com.example/foo", 10000, 10000, 0700);
    touch("user/0/com.example/foo/file", 10000, 20000, 0700);

    std::vector<uint8_t> result;
    std::string dexPath = get_full_path("user/0/com.example/foo/file");
    EXPECT_BINDER_SUCCESS(service->hashSecondaryDexFile(
        dexPath, "com.example", 10000, testUuid, FLAG_STORAGE_CE, &result));

    EXPECT_EQ(result.size(), 32U);

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (auto b : result) {
        output << std::setw(2) << +b;
    }

    // This is the SHA256 of an empty string (sha256sum /dev/null)
    EXPECT_EQ(output.str(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(ServiceTest, HashSecondaryDex_NoSuch) {
    LOG(INFO) << "HashSecondaryDex_NoSuch";

    std::vector<uint8_t> result;
    std::string dexPath = get_full_path("user/0/com.example/foo/file");
    EXPECT_BINDER_SUCCESS(service->hashSecondaryDexFile(
        dexPath, "com.example", 10000, testUuid, FLAG_STORAGE_CE, &result));

    EXPECT_EQ(result.size(), 0U);
}

TEST_F(ServiceTest, HashSecondaryDex_Unreadable) {
    LOG(INFO) << "HashSecondaryDex_Unreadable";

    mkdir("user/0/com.example", 10000, 10000, 0700);
    mkdir("user/0/com.example/foo", 10000, 10000, 0700);
    touch("user/0/com.example/foo/file", 10000, 20000, 0300);

    std::vector<uint8_t> result;
    std::string dexPath = get_full_path("user/0/com.example/foo/file");
    EXPECT_BINDER_SUCCESS(service->hashSecondaryDexFile(
        dexPath, "com.example", 10000, testUuid, FLAG_STORAGE_CE, &result));

    EXPECT_EQ(result.size(), 0U);
}

TEST_F(ServiceTest, HashSecondaryDex_WrongApp) {
    LOG(INFO) << "HashSecondaryDex_WrongApp";

    mkdir("user/0/com.example", 10000, 10000, 0700);
    mkdir("user/0/com.example/foo", 10000, 10000, 0700);
    touch("user/0/com.example/foo/file", 10000, 20000, 0700);

    std::vector<uint8_t> result;
    std::string dexPath = get_full_path("user/0/com.example/foo/file");
    EXPECT_BINDER_FAIL(service->hashSecondaryDexFile(
        dexPath, "com.wrong", 10000, testUuid, FLAG_STORAGE_CE, &result));
}

TEST_F(ServiceTest, CalculateOat) {
    char buf[PKG_PATH_MAX];

    EXPECT_TRUE(calculate_oat_file_path(buf, "/path/to/oat", "/path/to/file.apk", "isa"));
    EXPECT_EQ("/path/to/oat/isa/file.odex", std::string(buf));

    EXPECT_FALSE(calculate_oat_file_path(buf, "/path/to/oat", "/path/to/file", "isa"));
    EXPECT_FALSE(calculate_oat_file_path(buf, "/path/to/oat", "file", "isa"));
}

TEST_F(ServiceTest, CalculateOdex) {
    char buf[PKG_PATH_MAX];

    EXPECT_TRUE(calculate_odex_file_path(buf, "/path/to/file.apk", "isa"));
    EXPECT_EQ("/path/to/oat/isa/file.odex", std::string(buf));
}

TEST_F(ServiceTest, CalculateCache) {
    char buf[PKG_PATH_MAX];

    EXPECT_TRUE(create_cache_path(buf, "/path/to/file.apk", "isa"));
    EXPECT_EQ("/data/dalvik-cache/isa/path@to@file.apk@classes.dex", std::string(buf));
}
TEST_F(ServiceTest, GetAppSizeManualForMedia) {
    struct stat s;

    std::string externalPicDir =
            StringPrintf("%s/Pictures", create_data_media_path(nullptr, 0).c_str());
    if (stat(externalPicDir.c_str(), &s) == 0) {
        // fetch the appId from the uid of the external storage owning app
        int32_t externalStorageAppId = multiuser_get_app_id(s.st_uid);
        // Fetch Package Name for the external storage owning app uid
        std::string pkg = get_package_name(s.st_uid);

        std::vector<int64_t> externalStorageSize, externalStorageSizeAfterAddingExternalFile;
        std::vector<int64_t> ceDataInodes;

        std::vector<std::string> codePaths;
        std::vector<std::string> packageNames;
        // set up parameters
        packageNames.push_back(pkg);
        ceDataInodes.push_back(0);
        // initialise the mounts
        service->invalidateMounts();
        // call the getAppSize to get the current size of the external storage owning app
        service->getAppSize(std::nullopt, packageNames, 0, InstalldNativeService::FLAG_USE_QUOTA,
                            externalStorageAppId, ceDataInodes, codePaths, &externalStorageSize);
        // add a file with 20MB size to the external storage
        std::string externalFileLocation =
                StringPrintf("%s/Pictures/%s", getenv("EXTERNAL_STORAGE"), "External.jpg");
        std::string externalFileContentCommand =
                StringPrintf("dd if=/dev/zero of=%s bs=1M count=20", externalFileLocation.c_str());
        system(externalFileContentCommand.c_str());
        // call the getAppSize again to get the new size of the external storage owning app
        service->getAppSize(std::nullopt, packageNames, 0, InstalldNativeService::FLAG_USE_QUOTA,
                            externalStorageAppId, ceDataInodes, codePaths,
                            &externalStorageSizeAfterAddingExternalFile);
        // check that the size before adding the file and after should be the same, as the app size
        // is not changed.
        for (size_t i = 0; i < externalStorageSize.size(); i++) {
            ASSERT_TRUE(externalStorageSize[i] == externalStorageSizeAfterAddingExternalFile[i]);
        }
        // remove the external file
        std::string removeCommand = StringPrintf("rm -f %s", externalFileLocation.c_str());
        system(removeCommand.c_str());
    }
}

TEST_F(ServiceTest, GetAppSizeWrongSizes) {
    int32_t externalStorageAppId = -1;
    std::vector<int64_t> externalStorageSize;

    std::vector<std::string> codePaths;
    std::vector<std::string> packageNames = {"package1", "package2"};
    std::vector<int64_t> ceDataInodes = {0};

    EXPECT_BINDER_FAIL(service->getAppSize(std::nullopt, packageNames, 0,
                                           InstalldNativeService::FLAG_USE_QUOTA,
                                           externalStorageAppId, ceDataInodes, codePaths,
                                           &externalStorageSize));
}

class FsverityTest : public ServiceTest {
protected:
    binder::Status createFsveritySetupAuthToken(const std::string& path, int open_mode,
                                                sp<IFsveritySetupAuthToken>* _aidl_return) {
        unique_fd ufd(open(path.c_str(), open_mode));
        EXPECT_GE(ufd.get(), 0) << "open failed: " << strerror(errno);
        ParcelFileDescriptor rfd(std::move(ufd));
        return service->createFsveritySetupAuthToken(std::move(rfd), kTestAppId, _aidl_return);
    }
};

TEST_F(FsverityTest, enableFsverity) {
    const std::string path = kTestPath + "/foo";
    create_with_content(path, kTestAppUid, kTestAppUid, 0600, "content");
    UniqueFile raii(/*fd=*/-1, path, &unlink_path);

    // Expect to fs-verity setup to succeed
    sp<IFsveritySetupAuthToken> authToken;
    binder::Status status = createFsveritySetupAuthToken(path, O_RDWR, &authToken);
    EXPECT_TRUE(status.isOk());
    EXPECT_TRUE(authToken != nullptr);

    // Verity auth token works to enable fs-verity
    int32_t errno_local;
    status = service->enableFsverity(authToken, path, "fake.package.name", &errno_local);
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(errno_local, 0);
}

TEST_F(FsverityTest, enableFsverity_nullAuthToken) {
    const std::string path = kTestPath + "/foo";
    create_with_content(path, kTestAppUid, kTestAppUid, 0600, "content");
    UniqueFile raii(/*fd=*/-1, path, &unlink_path);

    // Verity null auth token fails
    sp<IFsveritySetupAuthToken> authToken;
    int32_t errno_local;
    binder::Status status =
            service->enableFsverity(authToken, path, "fake.package.name", &errno_local);
    EXPECT_FALSE(status.isOk());
}

TEST_F(FsverityTest, enableFsverity_differentFile) {
    const std::string path = kTestPath + "/foo";
    create_with_content(path, kTestAppUid, kTestAppUid, 0600, "content");
    UniqueFile raii(/*fd=*/-1, path, &unlink_path);

    // Expect to fs-verity setup to succeed
    sp<IFsveritySetupAuthToken> authToken;
    binder::Status status = createFsveritySetupAuthToken(path, O_RDWR, &authToken);
    EXPECT_TRUE(status.isOk());
    EXPECT_TRUE(authToken != nullptr);

    // Verity auth token does not work for a different file
    const std::string anotherPath = kTestPath + "/bar";
    ASSERT_TRUE(android::base::WriteStringToFile("content", anotherPath));
    UniqueFile raii2(/*fd=*/-1, anotherPath, &unlink_path);
    int32_t errno_local;
    status = service->enableFsverity(authToken, anotherPath, "fake.package.name", &errno_local);
    EXPECT_TRUE(status.isOk());
    EXPECT_NE(errno_local, 0);
}

TEST_F(FsverityTest, enableFsverity_errnoBeforeAuthenticated) {
    const std::string path = kTestPath + "/foo";
    create_with_content(path, kTestAppUid, kTestAppUid, 0600, "content");
    UniqueFile raii(/*fd=*/-1, path, &unlink_path);

    // Expect to fs-verity setup to succeed
    sp<IFsveritySetupAuthToken> authToken;
    binder::Status status = createFsveritySetupAuthToken(path, O_RDWR, &authToken);
    EXPECT_TRUE(status.isOk());
    EXPECT_TRUE(authToken != nullptr);

    // Verity errno before the fd authentication is constant (EPERM)
    int32_t errno_local;
    status = service->enableFsverity(authToken, path + "-non-exist", "fake.package.name",
                                     &errno_local);
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(errno_local, EPERM);
}

TEST_F(FsverityTest, createFsveritySetupAuthToken_ReadonlyFdDoesNotAuthenticate) {
    const std::string path = kTestPath + "/foo";
    create_with_content(path, kTestAppUid, kTestAppUid, 0600, "content");
    UniqueFile raii(/*fd=*/-1, path, &unlink_path);

    // Expect the fs-verity setup to fail
    sp<IFsveritySetupAuthToken> authToken;
    binder::Status status = createFsveritySetupAuthToken(path, O_RDONLY, &authToken);
    EXPECT_FALSE(status.isOk());
}

TEST_F(FsverityTest, createFsveritySetupAuthToken_UnownedFile) {
    const std::string path = kTestPath + "/foo";
    // Simulate world-writable file owned by another app
    create_with_content(path, kTestAppUid + 1, kTestAppUid + 1, 0666, "content");
    UniqueFile raii(/*fd=*/-1, path, &unlink_path);

    // Expect the fs-verity setup to fail
    sp<IFsveritySetupAuthToken> authToken;
    binder::Status status = createFsveritySetupAuthToken(path, O_RDWR, &authToken);
    EXPECT_FALSE(status.isOk());
}

static bool mkdirs(const std::string& path, mode_t mode) {
    struct stat sb;
    if (stat(path.c_str(), &sb) != -1 && S_ISDIR(sb.st_mode)) {
        return true;
    }

    if (!mkdirs(android::base::Dirname(path), mode)) {
        return false;
    }

    if (::mkdir(path.c_str(), mode) != 0) {
        PLOG(DEBUG) << "Failed to create folder " << path;
        return false;
    }
    return true;
}

class AppDataSnapshotTest : public testing::Test {
private:
    std::string rollback_ce_base_dir;
    std::string rollback_de_base_dir;

protected:
    InstalldNativeService* service;

    std::string fake_package_ce_path;
    std::string fake_package_de_path;

    virtual void SetUp() {
        setenv("ANDROID_LOG_TAGS", "*:v", 1);
        android::base::InitLogging(nullptr);

        service = new InstalldNativeService();
        ASSERT_TRUE(mkdirs("/data/local/tmp/user/0", 0700));

        init_globals_from_data_and_root();

        rollback_ce_base_dir = create_data_misc_ce_rollback_base_path("TEST", 0);
        rollback_de_base_dir = create_data_misc_de_rollback_base_path("TEST", 0);

        fake_package_ce_path = create_data_user_ce_package_path("TEST", 0, "com.foo");
        fake_package_de_path = create_data_user_de_package_path("TEST", 0, "com.foo");

        ASSERT_TRUE(mkdirs(rollback_ce_base_dir, 0700));
        ASSERT_TRUE(mkdirs(rollback_de_base_dir, 0700));
        ASSERT_TRUE(mkdirs(fake_package_ce_path, 0700));
        ASSERT_TRUE(mkdirs(fake_package_de_path, 0700));
    }

    virtual void TearDown() {
        ASSERT_EQ(0, delete_dir_contents_and_dir(rollback_ce_base_dir, true));
        ASSERT_EQ(0, delete_dir_contents_and_dir(rollback_de_base_dir, true));
        ASSERT_EQ(0, delete_dir_contents(fake_package_ce_path, true));
        ASSERT_EQ(0, delete_dir_contents(fake_package_de_path, true));

        delete service;
        ASSERT_EQ(0, delete_dir_contents_and_dir("/data/local/tmp/user/0", true));
    }
};

TEST_F(AppDataSnapshotTest, CreateAppDataSnapshot) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0, 37);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0, 37);

  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_CE", fake_package_ce_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_DE", fake_package_de_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  // Request a snapshot of the CE content but not the DE content.
  int64_t ce_snapshot_inode;
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_optional<std::string>("TEST"),
          "com.foo", 0, 37, FLAG_STORAGE_CE, &ce_snapshot_inode));
  struct stat buf;
  memset(&buf, 0, sizeof(buf));
  ASSERT_EQ(0, stat((rollback_ce_dir + "/com.foo").c_str(), &buf));
  ASSERT_EQ(ce_snapshot_inode, (int64_t) buf.st_ino);

  std::string ce_content, de_content;
  // At this point, we should have the CE content but not the DE content.
  ASSERT_TRUE(android::base::ReadFileToString(
      rollback_ce_dir + "/com.foo/file1", &ce_content, false /* follow_symlinks */));
  ASSERT_FALSE(android::base::ReadFileToString(
      rollback_de_dir + "/com.foo/file1", &de_content, false /* follow_symlinks */));
  ASSERT_EQ("TEST_CONTENT_CE", ce_content);

  // Modify the CE content, so we can assert later that it's reflected
  // in the snapshot.
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_CE_MODIFIED", fake_package_ce_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  // Request a snapshot of the DE content but not the CE content.
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_optional<std::string>("TEST"),
          "com.foo", 0, 37, FLAG_STORAGE_DE, &ce_snapshot_inode));
  // Only DE content snapshot was requested.
  ASSERT_EQ(ce_snapshot_inode, 0);

  // At this point, both the CE as well as the DE content should be fully
  // populated.
  ASSERT_TRUE(android::base::ReadFileToString(
      rollback_ce_dir + "/com.foo/file1", &ce_content, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::ReadFileToString(
      rollback_de_dir + "/com.foo/file1", &de_content, false /* follow_symlinks */));
  ASSERT_EQ("TEST_CONTENT_CE", ce_content);
  ASSERT_EQ("TEST_CONTENT_DE", de_content);

  // Modify the DE content, so we can assert later that it's reflected
  // in our final snapshot.
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_DE_MODIFIED", fake_package_de_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  // Request a snapshot of both the CE as well as the DE content.
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_optional<std::string>("TEST"),
          "com.foo", 0, 37, FLAG_STORAGE_DE | FLAG_STORAGE_CE, nullptr));

  ASSERT_TRUE(android::base::ReadFileToString(
      rollback_ce_dir + "/com.foo/file1", &ce_content, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::ReadFileToString(
      rollback_de_dir + "/com.foo/file1", &de_content, false /* follow_symlinks */));
  ASSERT_EQ("TEST_CONTENT_CE_MODIFIED", ce_content);
  ASSERT_EQ("TEST_CONTENT_DE_MODIFIED", de_content);
}

TEST_F(AppDataSnapshotTest, CreateAppDataSnapshot_TwoSnapshotsWithTheSameId) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0, 67);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0, 67);

  auto another_fake_package_ce_path = create_data_user_ce_package_path("TEST", 0, "com.bar");
  auto another_fake_package_de_path = create_data_user_de_package_path("TEST", 0, "com.bar");

  // Since this test sets up data for another package, some bookkeeping is required.
  auto deleter = [&]() {
      ASSERT_EQ(0, delete_dir_contents_and_dir(another_fake_package_ce_path, true));
      ASSERT_EQ(0, delete_dir_contents_and_dir(another_fake_package_de_path, true));
  };
  auto scope_guard = android::base::make_scope_guard(deleter);

  ASSERT_TRUE(mkdirs(another_fake_package_ce_path, 0700));
  ASSERT_TRUE(mkdirs(another_fake_package_de_path, 0700));

  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_CE", fake_package_ce_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_DE", fake_package_de_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "ANOTHER_TEST_CONTENT_CE", another_fake_package_ce_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "ANOTHER_TEST_CONTENT_DE", another_fake_package_de_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  // Request snapshot for the package com.foo.
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_optional<std::string>("TEST"),
          "com.foo", 0, 67, FLAG_STORAGE_DE | FLAG_STORAGE_CE, nullptr));
  // Now request snapshot with the same id for the package com.bar
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_optional<std::string>("TEST"),
          "com.bar", 0, 67, FLAG_STORAGE_DE | FLAG_STORAGE_CE, nullptr));

  // Check that both snapshots have correct data in them.
  std::string com_foo_ce_content, com_foo_de_content;
  std::string com_bar_ce_content, com_bar_de_content;
  ASSERT_TRUE(android::base::ReadFileToString(
      rollback_ce_dir + "/com.foo/file1", &com_foo_ce_content, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::ReadFileToString(
      rollback_de_dir + "/com.foo/file1", &com_foo_de_content, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::ReadFileToString(
      rollback_ce_dir + "/com.bar/file1", &com_bar_ce_content, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::ReadFileToString(
      rollback_de_dir + "/com.bar/file1", &com_bar_de_content, false /* follow_symlinks */));
  ASSERT_EQ("TEST_CONTENT_CE", com_foo_ce_content);
  ASSERT_EQ("TEST_CONTENT_DE", com_foo_de_content);
  ASSERT_EQ("ANOTHER_TEST_CONTENT_CE", com_bar_ce_content);
  ASSERT_EQ("ANOTHER_TEST_CONTENT_DE", com_bar_de_content);
}

TEST_F(AppDataSnapshotTest, CreateAppDataSnapshot_AppDataAbsent) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0, 73);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0, 73);

  // Similuating app data absence.
  ASSERT_EQ(0, delete_dir_contents_and_dir(fake_package_ce_path, true));
  ASSERT_EQ(0, delete_dir_contents_and_dir(fake_package_de_path, true));

  int64_t ce_snapshot_inode;
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_optional<std::string>("TEST"),
          "com.foo", 0, 73, FLAG_STORAGE_CE, &ce_snapshot_inode));
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_optional<std::string>("TEST"),
          "com.foo", 0, 73, FLAG_STORAGE_DE, nullptr));
  // No CE content snapshot was performed.
  ASSERT_EQ(ce_snapshot_inode, 0);

  // The snapshot calls must succeed but there should be no snapshot
  // created.
  struct stat sb;
  ASSERT_EQ(-1, stat((rollback_ce_dir + "/com.foo").c_str(), &sb));
  ASSERT_EQ(-1, stat((rollback_de_dir + "/com.foo").c_str(), &sb));
}

TEST_F(AppDataSnapshotTest, CreateAppDataSnapshot_ClearsExistingSnapshot) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_package_path("TEST", 0, 13, "com.foo");
  auto rollback_de_dir = create_data_misc_de_rollback_package_path("TEST", 0, 13, "com.foo");

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 0700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 0700));

  // Simulate presence of an existing snapshot
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_CE", rollback_ce_dir + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_DE", rollback_de_dir + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  // Create app data.
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_2_CE", fake_package_ce_path + "/file2",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_2_DE", fake_package_de_path + "/file2",
          0700, 10000, 20000, false /* follow_symlinks */));

  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_optional<std::string>("TEST"),
          "com.foo", 0, 13, FLAG_STORAGE_DE | FLAG_STORAGE_CE, nullptr));

  // Previous snapshot (with data for file1) must be cleared.
  struct stat sb;
  ASSERT_EQ(-1, stat((rollback_ce_dir + "/file1").c_str(), &sb));
  ASSERT_EQ(-1, stat((rollback_de_dir + "/file1").c_str(), &sb));
  // New snapshot (with data for file2) must be present.
  ASSERT_NE(-1, stat((rollback_ce_dir + "/file2").c_str(), &sb));
  ASSERT_NE(-1, stat((rollback_de_dir + "/file2").c_str(), &sb));
}

TEST_F(AppDataSnapshotTest, SnapshotAppData_WrongVolumeUuid) {
  // Setup rollback folders to make sure that fails due to wrong volumeUuid being
  // passed, not because of some other reason.
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0, 17);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0, 17);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 0700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 0700));

  EXPECT_BINDER_FAIL(service->snapshotAppData(std::make_optional<std::string>("FOO"),
          "com.foo", 0, 17, FLAG_STORAGE_DE, nullptr));
}

TEST_F(AppDataSnapshotTest, CreateAppDataSnapshot_ClearsCache) {
  auto fake_package_ce_cache_path = fake_package_ce_path + "/cache";
  auto fake_package_ce_code_cache_path = fake_package_ce_path + "/code_cache";
  auto fake_package_de_cache_path = fake_package_de_path + "/cache";
  auto fake_package_de_code_cache_path = fake_package_de_path + "/code_cache";

  ASSERT_TRUE(mkdirs(fake_package_ce_cache_path, 0700));
  ASSERT_TRUE(mkdirs(fake_package_ce_code_cache_path, 0700));
  ASSERT_TRUE(mkdirs(fake_package_de_cache_path, 0700));
  ASSERT_TRUE(mkdirs(fake_package_de_code_cache_path, 0700));

  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_CE", fake_package_ce_cache_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_CE", fake_package_ce_code_cache_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_DE", fake_package_de_cache_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_DE", fake_package_de_code_cache_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_optional<std::string>("TEST"),
          "com.foo", 0, 23, FLAG_STORAGE_CE | FLAG_STORAGE_DE, nullptr));
  // The snapshot call must clear cache.
  struct stat sb;
  ASSERT_EQ(-1, stat((fake_package_ce_cache_path + "/file1").c_str(), &sb));
  ASSERT_EQ(-1, stat((fake_package_ce_code_cache_path + "/file1").c_str(), &sb));
  ASSERT_EQ(-1, stat((fake_package_de_cache_path + "/file1").c_str(), &sb));
  ASSERT_EQ(-1, stat((fake_package_de_code_cache_path + "/file1").c_str(), &sb));
}

TEST_F(AppDataSnapshotTest, RestoreAppDataSnapshot) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0, 239);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0, 239);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 0700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 0700));

  // Write contents to the rollback location. We'll write the same files to the
  // app data location and make sure the restore has overwritten them.
  ASSERT_TRUE(mkdirs(rollback_ce_dir + "/com.foo/", 0700));
  ASSERT_TRUE(mkdirs(rollback_de_dir + "/com.foo/", 0700));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "CE_RESTORE_CONTENT", rollback_ce_dir + "/com.foo/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "DE_RESTORE_CONTENT", rollback_de_dir + "/com.foo/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_CE", fake_package_ce_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_DE", fake_package_de_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  ASSERT_BINDER_SUCCESS(service->restoreAppDataSnapshot(std::make_optional<std::string>("TEST"),
          "com.foo", 10000, "", 0, 239, FLAG_STORAGE_DE | FLAG_STORAGE_CE));

  std::string ce_content, de_content;
  ASSERT_TRUE(android::base::ReadFileToString(
      fake_package_ce_path + "/file1", &ce_content, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::ReadFileToString(
      fake_package_de_path + "/file1", &de_content, false /* follow_symlinks */));
  ASSERT_EQ("CE_RESTORE_CONTENT", ce_content);
  ASSERT_EQ("DE_RESTORE_CONTENT", de_content);
}

TEST_F(AppDataSnapshotTest, CreateSnapshotThenDestroyIt) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0, 57);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0, 57);

  // Prepare data for snapshot.
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_CE", fake_package_ce_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_DE", fake_package_de_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  int64_t ce_snapshot_inode;
  // Request a snapshot of both the CE as well as the DE content.
  ASSERT_TRUE(service->snapshotAppData(std::make_optional<std::string>("TEST"),
          "com.foo", 0, 57, FLAG_STORAGE_DE | FLAG_STORAGE_CE, &ce_snapshot_inode).isOk());
  // Because CE data snapshot was requested, ce_snapshot_inode can't be null.
  ASSERT_NE(0, ce_snapshot_inode);
  // Check snapshot is there.
  struct stat sb;
  ASSERT_EQ(0, stat((rollback_ce_dir + "/com.foo").c_str(), &sb));
  ASSERT_EQ(0, stat((rollback_de_dir + "/com.foo").c_str(), &sb));


  ASSERT_TRUE(service->destroyAppDataSnapshot(std::make_optional<std::string>("TEST"),
          "com.foo", 0, ce_snapshot_inode, 57, FLAG_STORAGE_DE | FLAG_STORAGE_CE).isOk());
  // Check snapshot is deleted.
  ASSERT_EQ(-1, stat((rollback_ce_dir + "/com.foo").c_str(), &sb));
  ASSERT_EQ(-1, stat((rollback_de_dir + "/com.foo").c_str(), &sb));
}

TEST_F(AppDataSnapshotTest, DestroyAppDataSnapshot_CeSnapshotInodeIsZero) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0, 1543);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0, 1543);

  // Create a snapshot
  ASSERT_TRUE(mkdirs(rollback_ce_dir + "/com.foo/", 0700));
  ASSERT_TRUE(mkdirs(rollback_de_dir + "/com.foo/", 0700));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "CE_RESTORE_CONTENT", rollback_ce_dir + "/com.foo/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "DE_RESTORE_CONTENT", rollback_de_dir + "/com.foo/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  ASSERT_TRUE(service->destroyAppDataSnapshot(std::make_optional<std::string>("TEST"),
          "com.foo", 0, 0, 1543, FLAG_STORAGE_DE | FLAG_STORAGE_CE).isOk());

  // Check snapshot is deleted.
  struct stat sb;
  ASSERT_EQ(-1, stat((rollback_ce_dir + "/com.foo").c_str(), &sb));
  ASSERT_EQ(-1, stat((rollback_de_dir + "/com.foo").c_str(), &sb));

  // Check that deleting already deleted snapshot is no-op.
  ASSERT_TRUE(service->destroyAppDataSnapshot(std::make_optional<std::string>("TEST"),
          "com.foo", 0, 0, 1543, FLAG_STORAGE_DE | FLAG_STORAGE_CE).isOk());
}

TEST_F(AppDataSnapshotTest, DestroyAppDataSnapshot_WrongVolumeUuid) {
  // Setup rollback data to make sure that test fails due to wrong volumeUuid
  // being passed, not because of some other reason.
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0, 43);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0, 43);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 0700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 0700));

  ASSERT_FALSE(service->destroyAppDataSnapshot(std::make_optional<std::string>("BAR"),
          "com.foo", 0, 0, 43, FLAG_STORAGE_DE).isOk());
}

TEST_F(AppDataSnapshotTest, DestroyCeSnapshotsNotSpecified) {
  auto rollback_ce_dir_in_1 = create_data_misc_ce_rollback_path("TEST", 0, 1543);
  auto rollback_ce_dir_in_2 = create_data_misc_ce_rollback_path("TEST", 0, 77);
  auto rollback_ce_dir_out_1 = create_data_misc_ce_rollback_path("TEST", 0, 1500);
  auto rollback_ce_dir_out_2 = create_data_misc_ce_rollback_path("TEST", 0, 2);

  // Create snapshots
  ASSERT_TRUE(mkdirs(rollback_ce_dir_in_1 + "/com.foo/", 0700));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "CE_RESTORE_CONTENT", rollback_ce_dir_in_1 + "/com.foo/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  ASSERT_TRUE(mkdirs(rollback_ce_dir_in_2 + "/com.foo/", 0700));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "CE_RESTORE_CONTENT", rollback_ce_dir_in_2 + "/com.foo/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  ASSERT_TRUE(mkdirs(rollback_ce_dir_out_1 + "/com.foo/", 0700));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "CE_RESTORE_CONTENT", rollback_ce_dir_out_1 + "/com.foo/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  ASSERT_TRUE(mkdirs(rollback_ce_dir_out_2 + "/com.foo/", 0700));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "CE_RESTORE_CONTENT", rollback_ce_dir_out_2 + "/com.foo/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  ASSERT_TRUE(service->destroyCeSnapshotsNotSpecified(
          std::make_optional<std::string>("TEST"), 0, { 1543, 77 }).isOk());

  // Check only snapshots not specified are deleted.
  struct stat sb;
  ASSERT_EQ(0, stat((rollback_ce_dir_in_1 + "/com.foo").c_str(), &sb));
  ASSERT_EQ(0, stat((rollback_ce_dir_in_2 + "/com.foo").c_str(), &sb));
  ASSERT_EQ(-1, stat((rollback_ce_dir_out_1 + "/com.foo").c_str(), &sb));
  ASSERT_EQ(ENOENT, errno);
  ASSERT_EQ(-1, stat((rollback_ce_dir_out_2 + "/com.foo").c_str(), &sb));
  ASSERT_EQ(ENOENT, errno);
}

TEST_F(AppDataSnapshotTest, RestoreAppDataSnapshot_WrongVolumeUuid) {
  // Setup rollback data to make sure that fails due to wrong volumeUuid being
  // passed, not because of some other reason.
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0, 41);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0, 41);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 0700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 0700));

  EXPECT_BINDER_FAIL(service->restoreAppDataSnapshot(std::make_optional<std::string>("BAR"),
          "com.foo", 10000, "", 0, 41, FLAG_STORAGE_DE));
}

class SdkSandboxDataTest : public testing::Test {
public:
    void CheckFileAccess(const std::string& path, uid_t uid, gid_t gid, mode_t mode) {
        const auto fullPath = "/data/local/tmp/" + path;
        ASSERT_TRUE(exists(fullPath.c_str())) << "For path: " << fullPath;
        struct stat st;
        ASSERT_EQ(0, stat(fullPath.c_str(), &st));
        ASSERT_EQ(uid, st.st_uid) << "For path: " << fullPath;
        ASSERT_EQ(gid, st.st_gid) << "For path: " << fullPath;
        ASSERT_EQ(mode, st.st_mode) << "For path: " << fullPath;
    }

    bool exists(const char* path) { return ::access(path, F_OK) == 0; }

    // Creates a default CreateAppDataArgs object
    android::os::CreateAppDataArgs createAppDataArgs(const std::string& packageName) {
        android::os::CreateAppDataArgs args;
        args.uuid = kTestUuid;
        args.packageName = packageName;
        args.userId = kTestUserId;
        args.appId = kTestAppId;
        args.seInfo = "default";
        args.flags = FLAG_STORAGE_CE | FLAG_STORAGE_DE | FLAG_STORAGE_SDK;
        return args;
    }

    android::os::ReconcileSdkDataArgs reconcileSdkDataArgs(
            const std::string& packageName, const std::vector<std::string>& subDirNames) {
        android::os::ReconcileSdkDataArgs args;
        args.uuid = kTestUuid;
        args.packageName = packageName;
        for (const auto& subDirName : subDirNames) {
            args.subDirNames.push_back(subDirName);
        }
        args.userId = kTestUserId;
        args.appId = kTestAppId;
        args.previousAppId = -1;
        args.seInfo = "default";
        args.flags = FLAG_STORAGE_CE | FLAG_STORAGE_DE;
        return args;
    }

protected:
    InstalldNativeService* service;

    virtual void SetUp() {
        setenv("ANDROID_LOG_TAGS", "*:v", 1);
        android::base::InitLogging(nullptr);

        service = new InstalldNativeService();
        clearAppData();
        ASSERT_TRUE(mkdirs("/data/local/tmp/user/0", 0700));
        ASSERT_TRUE(mkdirs("/data/local/tmp/user_de/0", 0700));
        ASSERT_TRUE(mkdirs("/data/local/tmp/misc_ce/0/sdksandbox", 0700));
        ASSERT_TRUE(mkdirs("/data/local/tmp/misc_de/0/sdksandbox", 0700));

        init_globals_from_data_and_root();
    }

    virtual void TearDown() {
        delete service;
        clearAppData();
    }

private:
    void clearAppData() {
        ASSERT_EQ(0, delete_dir_contents_and_dir("/data/local/tmp/user", true));
        ASSERT_EQ(0, delete_dir_contents_and_dir("/data/local/tmp/user_de", true));
        ASSERT_EQ(0, delete_dir_contents_and_dir("/data/local/tmp/misc_ce", true));
        ASSERT_EQ(0, delete_dir_contents_and_dir("/data/local/tmp/misc_de", true));
    }
};

TEST_F(SdkSandboxDataTest, CreateAppData_CreatesSdkPackageData) {
    android::os::CreateAppDataResult result;
    android::os::CreateAppDataArgs args = createAppDataArgs("com.foo");

    // Create the app user data.
    ASSERT_BINDER_SUCCESS(service->createAppData(args, &result));

    const std::string fooCePath = "misc_ce/0/sdksandbox/com.foo";
    CheckFileAccess(fooCePath, kSystemUid, kSystemUid, S_IFDIR | 0751);

    const std::string fooDePath = "misc_de/0/sdksandbox/com.foo";
    CheckFileAccess(fooDePath, kSystemUid, kSystemUid, S_IFDIR | 0751);
}

TEST_F(SdkSandboxDataTest, CreateAppData_CreatesSdkPackageData_WithoutSdkFlag) {
    android::os::CreateAppDataResult result;
    android::os::CreateAppDataArgs args = createAppDataArgs("com.foo");
    args.flags = FLAG_STORAGE_CE | FLAG_STORAGE_DE;

    // Create the app user data.
    ASSERT_BINDER_SUCCESS(service->createAppData(args, &result));

    ASSERT_FALSE(exists("/data/local/tmp/misc_ce/0/sdksandbox/com.foo"));
    ASSERT_FALSE(exists("/data/local/tmp/misc_de/0/sdksandbox/com.foo"));
}

TEST_F(SdkSandboxDataTest, CreateAppData_CreatesSdkPackageData_WithoutSdkFlagDeletesExisting) {
    android::os::CreateAppDataResult result;
    android::os::CreateAppDataArgs args = createAppDataArgs("com.foo");
    // Create the app user data.
    ASSERT_BINDER_SUCCESS(service->createAppData(args, &result));
    ASSERT_TRUE(exists("/data/local/tmp/misc_ce/0/sdksandbox/com.foo"));
    ASSERT_TRUE(exists("/data/local/tmp/misc_de/0/sdksandbox/com.foo"));

    args.flags = FLAG_STORAGE_CE | FLAG_STORAGE_DE;
    ASSERT_BINDER_SUCCESS(service->createAppData(args, &result));
    ASSERT_FALSE(exists("/data/local/tmp/misc_ce/0/sdksandbox/com.foo"));
    ASSERT_FALSE(exists("/data/local/tmp/misc_de/0/sdksandbox/com.foo"));
}

TEST_F(SdkSandboxDataTest, CreateAppData_CreatesSdkPackageData_WithoutDeFlag) {
    android::os::CreateAppDataResult result;
    android::os::CreateAppDataArgs args = createAppDataArgs("com.foo");
    args.flags = FLAG_STORAGE_CE | FLAG_STORAGE_SDK;

    // Create the app user data.
    ASSERT_BINDER_SUCCESS(service->createAppData(args, &result));

    // Only CE paths should exist
    CheckFileAccess("misc_ce/0/sdksandbox/com.foo", kSystemUid, kSystemUid, S_IFDIR | 0751);

    // DE paths should not exist
    ASSERT_FALSE(exists("/data/local/tmp/misc_de/0/sdksandbox/com.foo"));
}

TEST_F(SdkSandboxDataTest, CreateAppData_CreatesSdkPackageData_WithoutCeFlag) {
    android::os::CreateAppDataResult result;
    android::os::CreateAppDataArgs args = createAppDataArgs("com.foo");
    args.flags = FLAG_STORAGE_DE | FLAG_STORAGE_SDK;

    // Create the app user data.
    ASSERT_BINDER_SUCCESS(service->createAppData(args, &result));

    // CE paths should not exist
    ASSERT_FALSE(exists("/data/local/tmp/misc_ce/0/sdksandbox/com.foo"));

    // Only DE paths should exist
    CheckFileAccess("misc_de/0/sdksandbox/com.foo", kSystemUid, kSystemUid, S_IFDIR | 0751);
}

TEST_F(SdkSandboxDataTest, ReconcileSdkData) {
    android::os::ReconcileSdkDataArgs args =
            reconcileSdkDataArgs("com.foo", {"bar@random1", "baz@random2"});

    // Create the sdk data.
    ASSERT_BINDER_SUCCESS(service->reconcileSdkData(args));

    const std::string barCePath = "misc_ce/0/sdksandbox/com.foo/bar@random1";
    CheckFileAccess(barCePath, kTestSdkSandboxUid, kNobodyUid, S_IFDIR | S_ISGID | 0700);
    CheckFileAccess(barCePath + "/cache", kTestSdkSandboxUid, kTestCacheGid,
                    S_IFDIR | S_ISGID | 0771);
    CheckFileAccess(barCePath + "/code_cache", kTestSdkSandboxUid, kTestCacheGid,
                    S_IFDIR | S_ISGID | 0771);

    const std::string bazCePath = "misc_ce/0/sdksandbox/com.foo/baz@random2";
    CheckFileAccess(bazCePath, kTestSdkSandboxUid, kNobodyUid, S_IFDIR | S_ISGID | 0700);
    CheckFileAccess(bazCePath + "/cache", kTestSdkSandboxUid, kTestCacheGid,
                    S_IFDIR | S_ISGID | 0771);
    CheckFileAccess(bazCePath + "/code_cache", kTestSdkSandboxUid, kTestCacheGid,
                    S_IFDIR | S_ISGID | 0771);

    const std::string barDePath = "misc_de/0/sdksandbox/com.foo/bar@random1";
    CheckFileAccess(barDePath, kTestSdkSandboxUid, kNobodyUid, S_IFDIR | S_ISGID | 0700);
    CheckFileAccess(barDePath + "/cache", kTestSdkSandboxUid, kTestCacheGid,
                    S_IFDIR | S_ISGID | 0771);
    CheckFileAccess(barDePath + "/code_cache", kTestSdkSandboxUid, kTestCacheGid,
                    S_IFDIR | S_ISGID | 0771);

    const std::string bazDePath = "misc_de/0/sdksandbox/com.foo/baz@random2";
    CheckFileAccess(bazDePath, kTestSdkSandboxUid, kNobodyUid, S_IFDIR | S_ISGID | 0700);
    CheckFileAccess(bazDePath + "/cache", kTestSdkSandboxUid, kTestCacheGid,
                    S_IFDIR | S_ISGID | 0771);
    CheckFileAccess(bazDePath + "/code_cache", kTestSdkSandboxUid, kTestCacheGid,
                    S_IFDIR | S_ISGID | 0771);
}

TEST_F(SdkSandboxDataTest, ReconcileSdkData_ExtraCodeDirectoriesAreDeleted) {
    android::os::ReconcileSdkDataArgs args =
            reconcileSdkDataArgs("com.foo", {"bar@random1", "baz@random2"});

    // Create the sdksandbox data.
    ASSERT_BINDER_SUCCESS(service->reconcileSdkData(args));

    // Retry with different package name
    args.subDirNames[0] = "bar.diff@random1";

    // Create the sdksandbox data again
    ASSERT_BINDER_SUCCESS(service->reconcileSdkData(args));

    // New directoris should exist
    CheckFileAccess("misc_ce/0/sdksandbox/com.foo/bar.diff@random1", kTestSdkSandboxUid, kNobodyUid,
                    S_IFDIR | S_ISGID | 0700);
    CheckFileAccess("misc_ce/0/sdksandbox/com.foo/baz@random2", kTestSdkSandboxUid, kNobodyUid,
                    S_IFDIR | S_ISGID | 0700);
    // Directory for old unreferred sdksandbox package name should be removed
    ASSERT_FALSE(exists("/data/local/tmp/misc_ce/0/sdksandbox/com.foo/bar@random1"));
}

class DestroyAppDataTest : public SdkSandboxDataTest {};

TEST_F(DestroyAppDataTest, DestroySdkSandboxDataDirectories_WithCeAndDeFlag) {
    android::os::CreateAppDataResult result;
    android::os::CreateAppDataArgs args = createAppDataArgs("com.foo");
    args.packageName = "com.foo";
    // Create the app user data.
    ASSERT_BINDER_SUCCESS(service->createAppData(args, &result));
    // Destroy the app user data.
    ASSERT_BINDER_SUCCESS(service->destroyAppData(args.uuid, args.packageName, args.userId,
                                                  args.flags, result.ceDataInode));
    ASSERT_FALSE(exists("/data/local/tmp/misc_ce/0/sdksandbox/com.foo"));
    ASSERT_FALSE(exists("/data/local/tmp/misc_de/0/sdksandbox/com.foo"));
}

TEST_F(DestroyAppDataTest, DestroySdkSandboxDataDirectories_WithoutDeFlag) {
    android::os::CreateAppDataResult result;
    android::os::CreateAppDataArgs args = createAppDataArgs("com.foo");
    args.packageName = "com.foo";
    // Create the app user data.
    ASSERT_BINDER_SUCCESS(service->createAppData(args, &result));
    // Destroy the app user data.
    ASSERT_BINDER_SUCCESS(service->destroyAppData(args.uuid, args.packageName, args.userId,
                                                  FLAG_STORAGE_CE, result.ceDataInode));
    ASSERT_TRUE(exists("/data/local/tmp/misc_de/0/sdksandbox/com.foo"));
    ASSERT_FALSE(exists("/data/local/tmp/misc_ce/0/sdksandbox/com.foo"));
}

TEST_F(DestroyAppDataTest, DestroySdkSandboxDataDirectories_WithoutCeFlag) {
    android::os::CreateAppDataResult result;
    android::os::CreateAppDataArgs args = createAppDataArgs("com.foo");
    args.packageName = "com.foo";
    // Create the app user data.
    ASSERT_BINDER_SUCCESS(service->createAppData(args, &result));
    // Destroy the app user data.
    ASSERT_BINDER_SUCCESS(service->destroyAppData(args.uuid, args.packageName, args.userId,
                                                  FLAG_STORAGE_DE, result.ceDataInode));
    ASSERT_TRUE(exists("/data/local/tmp/misc_ce/0/sdksandbox/com.foo"));
    ASSERT_FALSE(exists("/data/local/tmp/misc_de/0/sdksandbox/com.foo"));
}

class ClearAppDataTest : public SdkSandboxDataTest {
public:
    void createTestSdkData(const std::string& packageName, std::vector<std::string> sdkNames) {
        const auto& cePackagePath = "/data/local/tmp/misc_ce/0/sdksandbox/" + packageName;
        const auto& dePackagePath = "/data/local/tmp/misc_de/0/sdksandbox/" + packageName;
        ASSERT_TRUE(mkdirs(cePackagePath, 0700));
        ASSERT_TRUE(mkdirs(dePackagePath, 0700));
        const std::vector<std::string> packagePaths = {cePackagePath, dePackagePath};
        for (const auto& packagePath : packagePaths) {
            for (auto sdkName : sdkNames) {
                ASSERT_TRUE(mkdirs(packagePath + "/" + sdkName + "/cache", 0700));
                ASSERT_TRUE(mkdirs(packagePath + "/" + sdkName + "/code_cache", 0700));
                std::ofstream{packagePath + "/" + sdkName + "/cache/cachedTestData.txt"};
                std::ofstream{packagePath + "/" + sdkName + "/code_cache/cachedTestData.txt"};
            }
        }
    }
};

TEST_F(ClearAppDataTest, ClearSdkSandboxDataDirectories_WithCeAndClearCacheFlag) {
    createTestSdkData("com.foo", {"shared", "sdk1", "sdk2"});
    // Clear the app user data.
    ASSERT_BINDER_SUCCESS(service->clearAppData(kTestUuid, "com.foo", 0,
                                                FLAG_STORAGE_CE | FLAG_CLEAR_CACHE_ONLY, -1));

    const std::string packagePath = kTestPath + "/misc_ce/0/sdksandbox/com.foo";
    ASSERT_TRUE(is_empty(packagePath + "/shared/cache"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk1/cache"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk2/cache"));
}

TEST_F(ClearAppDataTest, ClearSdkSandboxDataDirectories_WithCeAndClearCodeCacheFlag) {
    createTestSdkData("com.foo", {"shared", "sdk1", "sdk2"});
    // Clear the app user data.
    ASSERT_BINDER_SUCCESS(service->clearAppData(kTestUuid, "com.foo", 0,
                                                FLAG_STORAGE_CE | FLAG_CLEAR_CODE_CACHE_ONLY, -1));

    const std::string packagePath = kTestPath + "/misc_ce/0/sdksandbox/com.foo";
    ASSERT_TRUE(is_empty(packagePath + "/shared/code_cache"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk1/code_cache"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk2/code_cache"));
}

TEST_F(ClearAppDataTest, ClearSdkSandboxDataDirectories_WithDeAndClearCacheFlag) {
    createTestSdkData("com.foo", {"shared", "sdk1", "sdk2"});
    // Clear the app user data
    ASSERT_BINDER_SUCCESS(
            service->clearAppData(kTestUuid, "com.foo", 0,
                                  FLAG_STORAGE_DE | (InstalldNativeService::FLAG_CLEAR_CACHE_ONLY),
                                  -1));

    const std::string packagePath = kTestPath + "/misc_de/0/sdksandbox/com.foo";
    ASSERT_TRUE(is_empty(packagePath + "/shared/cache"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk1/cache"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk2/cache"));
}

TEST_F(ClearAppDataTest, ClearSdkSandboxDataDirectories_WithDeAndClearCodeCacheFlag) {
    createTestSdkData("com.foo", {"shared", "sdk1", "sdk2"});
    // Clear the app user data.
    ASSERT_BINDER_SUCCESS(service->clearAppData(kTestUuid, "com.foo", 0,
                                                FLAG_STORAGE_DE | FLAG_CLEAR_CODE_CACHE_ONLY, -1));

    const std::string packagePath = kTestPath + "/misc_de/0/sdksandbox/com.foo";
    ASSERT_TRUE(is_empty(packagePath + "/shared/code_cache"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk1/code_cache"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk2/code_cache"));
}

TEST_F(ClearAppDataTest, ClearSdkSandboxDataDirectories_WithCeAndWithoutAnyCacheFlag) {
    createTestSdkData("com.foo", {"shared", "sdk1", "sdk2"});
    // Clear the app user data.
    ASSERT_BINDER_SUCCESS(service->clearAppData(kTestUuid, "com.foo", 0, FLAG_STORAGE_CE, -1));

    const std::string packagePath = kTestPath + "/misc_ce/0/sdksandbox/com.foo";
    ASSERT_TRUE(is_empty(packagePath + "/shared"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk1"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk2"));
}

TEST_F(ClearAppDataTest, ClearSdkSandboxDataDirectories_WithDeAndWithoutAnyCacheFlag) {
    createTestSdkData("com.foo", {"shared", "sdk1", "sdk2"});
    // Clear the app user data.
    ASSERT_BINDER_SUCCESS(service->clearAppData(kTestUuid, "com.foo", 0, FLAG_STORAGE_DE, -1));

    const std::string packagePath = kTestPath + "/misc_de/0/sdksandbox/com.foo";
    ASSERT_TRUE(is_empty(packagePath + "/shared"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk1"));
    ASSERT_TRUE(is_empty(packagePath + "/sdk2"));
}

class DestroyUserDataTest : public SdkSandboxDataTest {};

TEST_F(DestroyUserDataTest, DestroySdkData_WithCeFlag) {
    android::os::CreateAppDataResult result;
    android::os::CreateAppDataArgs args = createAppDataArgs("com.foo");
    args.packageName = "com.foo";
    // Create the app user data.
    ASSERT_BINDER_SUCCESS(service->createAppData(args, &result));
    // Destroy user data
    ASSERT_BINDER_SUCCESS(service->destroyUserData(args.uuid, args.userId, FLAG_STORAGE_CE));
    ASSERT_FALSE(exists("/data/local/tmp/misc_ce/0/sdksandbox"));
    ASSERT_TRUE(exists("/data/local/tmp/misc_de/0/sdksandbox"));
}

TEST_F(DestroyUserDataTest, DestroySdkData_WithDeFlag) {
    android::os::CreateAppDataResult result;
    android::os::CreateAppDataArgs args = createAppDataArgs("com.foo");
    args.packageName = "com.foo";
    // Create the app user data.
    ASSERT_BINDER_SUCCESS(service->createAppData(args, &result));
    // Destroy user data
    ASSERT_BINDER_SUCCESS(service->destroyUserData(args.uuid, args.userId, FLAG_STORAGE_DE));
    ASSERT_TRUE(exists("/data/local/tmp/misc_ce/0/sdksandbox"));
    ASSERT_FALSE(exists("/data/local/tmp/misc_de/0/sdksandbox"));
}

}  // namespace installd
}  // namespace android
