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
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>
#include <cutils/properties.h>
#include <gtest/gtest.h>

#include "binder_test_utils.h"
#include "InstalldNativeService.h"
#include "dexopt.h"
#include "globals.h"
#include "utils.h"

using android::base::StringPrintf;

namespace android {
namespace installd {

constexpr const char* kTestUuid = "TEST";

static constexpr int FLAG_FORCE = 1 << 16;

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

static std::string get_full_path(const char* path) {
    return StringPrintf("/data/local/tmp/user/0/%s", path);
}

static void mkdir(const char* path, uid_t owner, gid_t group, mode_t mode) {
    const std::string fullPath = get_full_path(path);
    ::mkdir(fullPath.c_str(), mode);
    ::chown(fullPath.c_str(), owner, group);
    ::chmod(fullPath.c_str(), mode);
}

static void touch(const char* path, uid_t owner, gid_t group, mode_t mode) {
    int fd = ::open(get_full_path(path).c_str(), O_RDWR | O_CREAT, mode);
    ::fchown(fd, owner, group);
    ::fchmod(fd, mode);
    ::close(fd);
}

static int stat_gid(const char* path) {
    struct stat buf;
    ::stat(get_full_path(path).c_str(), &buf);
    return buf.st_gid;
}

static int stat_mode(const char* path) {
    struct stat buf;
    ::stat(get_full_path(path).c_str(), &buf);
    return buf.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO | S_ISGID);
}

class ServiceTest : public testing::Test {
protected:
    InstalldNativeService* service;
    std::unique_ptr<std::string> testUuid;

    virtual void SetUp() {
        setenv("ANDROID_LOG_TAGS", "*:v", 1);
        android::base::InitLogging(nullptr);

        service = new InstalldNativeService();
        testUuid = std::make_unique<std::string>();
        *testUuid = std::string(kTestUuid);
        system("mkdir -p /data/local/tmp/user/0");

        init_globals_from_data_and_root();
    }

    virtual void TearDown() {
        delete service;
        system("rm -rf /data/local/tmp/user");
    }
};

TEST_F(ServiceTest, FixupAppData_Upgrade) {
    LOG(INFO) << "FixupAppData_Upgrade";

    mkdir("com.example", 10000, 10000, 0700);
    mkdir("com.example/normal", 10000, 10000, 0700);
    mkdir("com.example/cache", 10000, 10000, 0700);
    touch("com.example/cache/file", 10000, 10000, 0700);

    service->fixupAppData(testUuid, 0);

    EXPECT_EQ(10000, stat_gid("com.example/normal"));
    EXPECT_EQ(20000, stat_gid("com.example/cache"));
    EXPECT_EQ(20000, stat_gid("com.example/cache/file"));

    EXPECT_EQ(0700, stat_mode("com.example/normal"));
    EXPECT_EQ(02771, stat_mode("com.example/cache"));
    EXPECT_EQ(0700, stat_mode("com.example/cache/file"));
}

TEST_F(ServiceTest, FixupAppData_Moved) {
    LOG(INFO) << "FixupAppData_Moved";

    mkdir("com.example", 10000, 10000, 0700);
    mkdir("com.example/foo", 10000, 10000, 0700);
    touch("com.example/foo/file", 10000, 20000, 0700);
    mkdir("com.example/bar", 10000, 20000, 0700);
    touch("com.example/bar/file", 10000, 20000, 0700);

    service->fixupAppData(testUuid, 0);

    EXPECT_EQ(10000, stat_gid("com.example/foo"));
    EXPECT_EQ(20000, stat_gid("com.example/foo/file"));
    EXPECT_EQ(10000, stat_gid("com.example/bar"));
    EXPECT_EQ(10000, stat_gid("com.example/bar/file"));

    service->fixupAppData(testUuid, FLAG_FORCE);

    EXPECT_EQ(10000, stat_gid("com.example/foo"));
    EXPECT_EQ(10000, stat_gid("com.example/foo/file"));
    EXPECT_EQ(10000, stat_gid("com.example/bar"));
    EXPECT_EQ(10000, stat_gid("com.example/bar/file"));
}

TEST_F(ServiceTest, HashSecondaryDex) {
    LOG(INFO) << "HashSecondaryDex";

    mkdir("com.example", 10000, 10000, 0700);
    mkdir("com.example/foo", 10000, 10000, 0700);
    touch("com.example/foo/file", 10000, 20000, 0700);

    std::vector<uint8_t> result;
    std::string dexPath = get_full_path("com.example/foo/file");
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
    std::string dexPath = get_full_path("com.example/foo/file");
    EXPECT_BINDER_SUCCESS(service->hashSecondaryDexFile(
        dexPath, "com.example", 10000, testUuid, FLAG_STORAGE_CE, &result));

    EXPECT_EQ(result.size(), 0U);
}

TEST_F(ServiceTest, HashSecondaryDex_Unreadable) {
    LOG(INFO) << "HashSecondaryDex_Unreadable";

    mkdir("com.example", 10000, 10000, 0700);
    mkdir("com.example/foo", 10000, 10000, 0700);
    touch("com.example/foo/file", 10000, 20000, 0300);

    std::vector<uint8_t> result;
    std::string dexPath = get_full_path("com.example/foo/file");
    EXPECT_BINDER_SUCCESS(service->hashSecondaryDexFile(
        dexPath, "com.example", 10000, testUuid, FLAG_STORAGE_CE, &result));

    EXPECT_EQ(result.size(), 0U);
}

TEST_F(ServiceTest, HashSecondaryDex_WrongApp) {
    LOG(INFO) << "HashSecondaryDex_WrongApp";

    mkdir("com.example", 10000, 10000, 0700);
    mkdir("com.example/foo", 10000, 10000, 0700);
    touch("com.example/foo/file", 10000, 20000, 0700);

    std::vector<uint8_t> result;
    std::string dexPath = get_full_path("com.example/foo/file");
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

static bool mkdirs(const std::string& path, mode_t mode) {
    struct stat sb;
    if (stat(path.c_str(), &sb) != -1 && S_ISDIR(sb.st_mode)) {
        return true;
    }

    if (!mkdirs(android::base::Dirname(path), mode)) {
        return false;
    }

    return (::mkdir(path.c_str(), mode) != -1);
}

TEST_F(ServiceTest, CreateAppDataSnapshot) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 700));

  auto fake_package_ce_path = create_data_user_ce_package_path("TEST", 0, "com.foo");
  auto fake_package_de_path = create_data_user_de_package_path("TEST", 0, "com.foo");

  ASSERT_TRUE(mkdirs(fake_package_ce_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_de_path, 700));

  auto deleter = [&rollback_ce_dir, &rollback_de_dir,
          &fake_package_ce_path, &fake_package_de_path]() {
      delete_dir_contents(rollback_ce_dir, true);
      delete_dir_contents(rollback_de_dir, true);
      delete_dir_contents(fake_package_ce_path, true);
      delete_dir_contents(fake_package_de_path, true);
      rmdir(rollback_ce_dir.c_str());
      rmdir(rollback_de_dir.c_str());
  };
  auto scope_guard = android::base::make_scope_guard(deleter);

  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_CE", fake_package_ce_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_DE", fake_package_de_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  // Request a snapshot of the CE content but not the DE content.
  int64_t ce_snapshot_inode;
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_unique<std::string>("TEST"),
          "com.foo", 0, FLAG_STORAGE_CE, &ce_snapshot_inode));
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
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_unique<std::string>("TEST"),
          "com.foo", 0, FLAG_STORAGE_DE, &ce_snapshot_inode));
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
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_unique<std::string>("TEST"),
          "com.foo", 0, FLAG_STORAGE_DE | FLAG_STORAGE_CE, nullptr));

  ASSERT_TRUE(android::base::ReadFileToString(
      rollback_ce_dir + "/com.foo/file1", &ce_content, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::ReadFileToString(
      rollback_de_dir + "/com.foo/file1", &de_content, false /* follow_symlinks */));
  ASSERT_EQ("TEST_CONTENT_CE_MODIFIED", ce_content);
  ASSERT_EQ("TEST_CONTENT_DE_MODIFIED", de_content);
}

TEST_F(ServiceTest, CreateAppDataSnapshot_AppDataAbsent) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 700));

  auto deleter = [&rollback_ce_dir, &rollback_de_dir]() {
      delete_dir_contents(rollback_ce_dir, true);
      delete_dir_contents(rollback_de_dir, true);
      rmdir(rollback_ce_dir.c_str());
      rmdir(rollback_de_dir.c_str());
  };

  auto scope_guard = android::base::make_scope_guard(deleter);

  int64_t ce_snapshot_inode;
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_unique<std::string>("TEST"),
          "com.foo", 0, FLAG_STORAGE_CE, &ce_snapshot_inode));
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_unique<std::string>("TEST"),
          "com.foo", 0, FLAG_STORAGE_DE, nullptr));
  // No CE content snapshot was performed.
  ASSERT_EQ(ce_snapshot_inode, 0);

  // The snapshot calls must succeed but there should be no snapshot
  // created.
  struct stat sb;
  ASSERT_EQ(-1, stat((rollback_ce_dir + "/com.foo").c_str(), &sb));
  ASSERT_EQ(-1, stat((rollback_de_dir + "/com.foo").c_str(), &sb));
}

TEST_F(ServiceTest, CreateAppDataSnapshot_ClearsExistingSnapshot) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 700));

  auto fake_package_ce_path = create_data_user_ce_package_path("TEST", 0, "com.foo");
  auto fake_package_de_path = create_data_user_de_package_path("TEST", 0, "com.foo");

  ASSERT_TRUE(mkdirs(fake_package_ce_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_de_path, 700));

  auto deleter = [&rollback_ce_dir, &rollback_de_dir,
          &fake_package_ce_path, &fake_package_de_path]() {
      delete_dir_contents(rollback_ce_dir, true);
      delete_dir_contents(rollback_de_dir, true);
      delete_dir_contents(fake_package_ce_path, true);
      delete_dir_contents(fake_package_de_path, true);
      rmdir(rollback_ce_dir.c_str());
      rmdir(rollback_de_dir.c_str());
  };
  auto scope_guard = android::base::make_scope_guard(deleter);

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

  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_unique<std::string>("TEST"),
          "com.foo", 0, FLAG_STORAGE_DE | FLAG_STORAGE_CE, nullptr));

  // Previous snapshot (with data for file1) must be cleared.
  struct stat sb;
  ASSERT_EQ(-1, stat((rollback_ce_dir + "/com.foo/file1").c_str(), &sb));
  ASSERT_EQ(-1, stat((rollback_de_dir + "/com.foo/file1").c_str(), &sb));
}

TEST_F(ServiceTest, SnapshotAppData_WrongVolumeUuid) {
  // Setup app data to make sure that fails due to wrong volumeUuid being
  // passed, not because of some other reason.
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 700));

  auto deleter = [&rollback_ce_dir, &rollback_de_dir]() {
      delete_dir_contents(rollback_ce_dir, true);
      delete_dir_contents(rollback_de_dir, true);
      rmdir(rollback_ce_dir.c_str());
      rmdir(rollback_de_dir.c_str());
  };
  auto scope_guard = android::base::make_scope_guard(deleter);

  EXPECT_BINDER_FAIL(service->snapshotAppData(std::make_unique<std::string>("FOO"),
          "com.foo", 0, FLAG_STORAGE_DE, nullptr));
}

TEST_F(ServiceTest, CreateAppDataSnapshot_ClearsCache) {
  auto fake_package_ce_path = create_data_user_ce_package_path("TEST", 0, "com.foo");
  auto fake_package_de_path = create_data_user_de_package_path("TEST", 0, "com.foo");
  auto fake_package_ce_cache_path = read_path_inode(fake_package_ce_path,
      "cache", kXattrInodeCache);
  auto fake_package_ce_code_cache_path = read_path_inode(fake_package_ce_path,
      "code_cache", kXattrInodeCache);
  auto fake_package_de_cache_path = fake_package_de_path + "/cache";
  auto fake_package_de_code_cache_path = fake_package_de_path + "/code_cache";

  ASSERT_TRUE(mkdirs(fake_package_ce_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_de_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_ce_cache_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_ce_code_cache_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_de_cache_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_de_code_cache_path, 700));

  auto deleter = [&fake_package_ce_path, &fake_package_de_path,
          &fake_package_ce_cache_path, &fake_package_ce_code_cache_path,
          &fake_package_de_cache_path, &fake_package_de_code_cache_path]() {
      delete_dir_contents(fake_package_ce_path, true);
      delete_dir_contents(fake_package_de_path, true);
      delete_dir_contents(fake_package_ce_cache_path, true);
      delete_dir_contents(fake_package_ce_code_cache_path, true);
      delete_dir_contents(fake_package_de_cache_path, true);
      delete_dir_contents(fake_package_de_code_cache_path, true);
      rmdir(fake_package_ce_cache_path.c_str());
      rmdir(fake_package_ce_code_cache_path.c_str());
      rmdir(fake_package_de_cache_path.c_str());
      rmdir(fake_package_de_code_cache_path.c_str());
  };
  auto scope_guard = android::base::make_scope_guard(deleter);

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
  ASSERT_BINDER_SUCCESS(service->snapshotAppData(std::make_unique<std::string>("TEST"),
          "com.foo", 0, FLAG_STORAGE_CE | FLAG_STORAGE_DE, nullptr));
  // The snapshot call must clear cache.
  struct stat sb;
  ASSERT_EQ(-1, stat((fake_package_ce_cache_path + "/file1").c_str(), &sb));
  ASSERT_EQ(-1, stat((fake_package_ce_code_cache_path + "/file1").c_str(), &sb));
  ASSERT_EQ(-1, stat((fake_package_de_cache_path + "/file1").c_str(), &sb));
  ASSERT_EQ(-1, stat((fake_package_de_code_cache_path + "/file1").c_str(), &sb));
}

TEST_F(ServiceTest, RestoreAppDataSnapshot) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 700));

  auto fake_package_ce_path = create_data_user_ce_package_path("TEST", 0, "com.foo");
  auto fake_package_de_path = create_data_user_de_package_path("TEST", 0, "com.foo");

  ASSERT_TRUE(mkdirs(fake_package_ce_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_de_path, 700));

  auto deleter = [&rollback_ce_dir, &rollback_de_dir,
          &fake_package_ce_path, &fake_package_de_path]() {
      delete_dir_contents(rollback_ce_dir, true);
      delete_dir_contents(rollback_de_dir, true);
      delete_dir_contents(fake_package_ce_path, true);
      delete_dir_contents(fake_package_de_path, true);
      rmdir(rollback_ce_dir.c_str());
      rmdir(rollback_de_dir.c_str());
  };
  auto scope_guard = android::base::make_scope_guard(deleter);

  // Write contents to the rollback location. We'll write the same files to the
  // app data location and make sure the restore has overwritten them.
  ASSERT_TRUE(mkdirs(rollback_ce_dir + "/com.foo/", 700));
  ASSERT_TRUE(mkdirs(rollback_de_dir + "/com.foo/", 700));
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

  ASSERT_BINDER_SUCCESS(service->restoreAppDataSnapshot(std::make_unique<std::string>("TEST"),
          "com.foo", 10000, -1, "", 0, FLAG_STORAGE_DE | FLAG_STORAGE_CE));

  std::string ce_content, de_content;
  ASSERT_TRUE(android::base::ReadFileToString(
      fake_package_ce_path + "/file1", &ce_content, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::ReadFileToString(
      fake_package_de_path + "/file1", &de_content, false /* follow_symlinks */));
  ASSERT_EQ("CE_RESTORE_CONTENT", ce_content);
  ASSERT_EQ("DE_RESTORE_CONTENT", de_content);
}

TEST_F(ServiceTest, CreateSnapshotThenDestroyIt) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 700));

  auto fake_package_ce_path = create_data_user_ce_package_path("TEST", 0, "com.foo");
  auto fake_package_de_path = create_data_user_de_package_path("TEST", 0, "com.foo");

  ASSERT_TRUE(mkdirs(fake_package_ce_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_de_path, 700));

  auto deleter = [&rollback_ce_dir, &rollback_de_dir,
          &fake_package_ce_path, &fake_package_de_path]() {
      delete_dir_contents(rollback_ce_dir, true);
      delete_dir_contents(rollback_de_dir, true);
      delete_dir_contents(fake_package_ce_path, true);
      delete_dir_contents(fake_package_de_path, true);
      rmdir(rollback_ce_dir.c_str());
      rmdir(rollback_de_dir.c_str());
  };
  auto scope_guard = android::base::make_scope_guard(deleter);

  // Prepare data for snapshot.
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_CE", fake_package_ce_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "TEST_CONTENT_DE", fake_package_de_path + "/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  int64_t ce_snapshot_inode;
  // Request a snapshot of both the CE as well as the DE content.
  ASSERT_TRUE(service->snapshotAppData(std::make_unique<std::string>("TEST"),
          "com.foo", 0, FLAG_STORAGE_DE | FLAG_STORAGE_CE, &ce_snapshot_inode).isOk());
  // Because CE data snapshot was requested, ce_snapshot_inode can't be null.
  ASSERT_NE(0, ce_snapshot_inode);
  // Check snapshot is there.
  struct stat sb;
  ASSERT_EQ(0, stat((rollback_ce_dir + "/com.foo").c_str(), &sb));
  ASSERT_EQ(0, stat((rollback_de_dir + "/com.foo").c_str(), &sb));


  ASSERT_TRUE(service->destroyAppDataSnapshot(std::make_unique<std::string>("TEST"),
          "com.foo", 0, ce_snapshot_inode, FLAG_STORAGE_DE | FLAG_STORAGE_CE).isOk());
  // Check snapshot is deleted.
  ASSERT_EQ(-1, stat((rollback_ce_dir + "/com.foo").c_str(), &sb));
  ASSERT_EQ(-1, stat((rollback_de_dir + "/com.foo").c_str(), &sb));
}

TEST_F(ServiceTest, DestroyAppDataSnapshot_CeSnapshotInodeIsZero) {
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 700));

  auto fake_package_ce_path = create_data_user_ce_package_path("TEST", 0, "com.foo");
  auto fake_package_de_path = create_data_user_de_package_path("TEST", 0, "com.foo");

  ASSERT_TRUE(mkdirs(fake_package_ce_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_de_path, 700));

  auto deleter = [&rollback_ce_dir, &rollback_de_dir,
          &fake_package_ce_path, &fake_package_de_path]() {
      delete_dir_contents(rollback_ce_dir, true);
      delete_dir_contents(rollback_de_dir, true);
      delete_dir_contents(fake_package_ce_path, true);
      delete_dir_contents(fake_package_de_path, true);
      rmdir(rollback_ce_dir.c_str());
      rmdir(rollback_de_dir.c_str());
  };
  auto scope_guard = android::base::make_scope_guard(deleter);

  // Create a snapshot
  ASSERT_TRUE(mkdirs(rollback_ce_dir + "/com.foo/", 700));
  ASSERT_TRUE(mkdirs(rollback_de_dir + "/com.foo/", 700));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "CE_RESTORE_CONTENT", rollback_ce_dir + "/com.foo/file1",
          0700, 10000, 20000, false /* follow_symlinks */));
  ASSERT_TRUE(android::base::WriteStringToFile(
          "DE_RESTORE_CONTENT", rollback_de_dir + "/com.foo/file1",
          0700, 10000, 20000, false /* follow_symlinks */));

  ASSERT_TRUE(service->destroyAppDataSnapshot(std::make_unique<std::string>("TEST"),
          "com.foo", 0, 0, FLAG_STORAGE_DE | FLAG_STORAGE_CE).isOk());

  // Check snapshot is deleted.
  struct stat sb;
  ASSERT_EQ(-1, stat((rollback_ce_dir + "/com.foo").c_str(), &sb));
  ASSERT_EQ(-1, stat((rollback_de_dir + "/com.foo").c_str(), &sb));

  // Check that deleting already deleted snapshot is no-op.
  ASSERT_TRUE(service->destroyAppDataSnapshot(std::make_unique<std::string>("TEST"),
          "com.foo", 0, 0, FLAG_STORAGE_DE | FLAG_STORAGE_CE).isOk());
}

TEST_F(ServiceTest, DestroyAppDataSnapshot_WrongVolumeUuid) {
  // Setup rollback data to make sure that test fails due to wrong volumeUuid
  // being passed, not because of some other reason.
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 700));

  auto fake_package_ce_path = create_data_user_ce_package_path("TEST", 0, "com.foo");
  auto fake_package_de_path = create_data_user_de_package_path("TEST", 0, "com.foo");

  ASSERT_TRUE(mkdirs(fake_package_ce_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_de_path, 700));

  auto deleter = [&rollback_ce_dir, &rollback_de_dir,
          &fake_package_ce_path, &fake_package_de_path]() {
      delete_dir_contents(rollback_ce_dir, true);
      delete_dir_contents(rollback_de_dir, true);
      delete_dir_contents(fake_package_ce_path, true);
      delete_dir_contents(fake_package_de_path, true);
      rmdir(rollback_ce_dir.c_str());
      rmdir(rollback_de_dir.c_str());
  };
  auto scope_guard = android::base::make_scope_guard(deleter);

  ASSERT_FALSE(service->destroyAppDataSnapshot(std::make_unique<std::string>("BAR"),
          "com.foo", 0, 0, FLAG_STORAGE_DE).isOk());
}

TEST_F(ServiceTest, RestoreAppDataSnapshot_WrongVolumeUuid) {
  // Setup rollback data to make sure that fails due to wrong volumeUuid being
  // passed, not because of some other reason.
  auto rollback_ce_dir = create_data_misc_ce_rollback_path("TEST", 0);
  auto rollback_de_dir = create_data_misc_de_rollback_path("TEST", 0);

  ASSERT_TRUE(mkdirs(rollback_ce_dir, 700));
  ASSERT_TRUE(mkdirs(rollback_de_dir, 700));

  auto fake_package_ce_path = create_data_user_ce_package_path("TEST", 0, "com.foo");
  auto fake_package_de_path = create_data_user_de_package_path("TEST", 0, "com.foo");

  ASSERT_TRUE(mkdirs(fake_package_ce_path, 700));
  ASSERT_TRUE(mkdirs(fake_package_de_path, 700));

  auto deleter = [&rollback_ce_dir, &rollback_de_dir,
          &fake_package_ce_path, &fake_package_de_path]() {
      delete_dir_contents(rollback_ce_dir, true);
      delete_dir_contents(rollback_de_dir, true);
      delete_dir_contents(fake_package_ce_path, true);
      delete_dir_contents(fake_package_de_path, true);
      rmdir(rollback_ce_dir.c_str());
      rmdir(rollback_de_dir.c_str());
  };
  auto scope_guard = android::base::make_scope_guard(deleter);

  EXPECT_BINDER_FAIL(service->restoreAppDataSnapshot(std::make_unique<std::string>("BAR"),
          "com.foo", 10000, -1, "", 0, FLAG_STORAGE_DE));
}

}  // namespace installd
}  // namespace android
