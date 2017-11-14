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

#include <stdlib.h>
#include <string.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <cutils/properties.h>
#include <gtest/gtest.h>

#include "dexopt.h"
#include "InstalldNativeService.h"
#include "globals.h"
#include "tests/test_utils.h"
#include "utils.h"

namespace android {
namespace installd {

// TODO(calin): try to dedup this code.
#if defined(__arm__)
static const std::string kRuntimeIsa = "arm";
#elif defined(__aarch64__)
static const std::string kRuntimeIsa = "arm64";
#elif defined(__mips__) && !defined(__LP64__)
static const std::string kRuntimeIsa = "mips";
#elif defined(__mips__) && defined(__LP64__)
static const std::string kRuntimeIsa = "mips64";
#elif defined(__i386__)
static const std::string kRuntimeIsa = "x86";
#elif defined(__x86_64__)
static const std::string kRuntimeIsa = "x86_64";
#else
static const std::string kRuntimeIsa = "none";
#endif

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

static void run_cmd(const std::string& cmd) {
    system(cmd.c_str());
}

static void mkdir(const std::string& path, uid_t owner, gid_t group, mode_t mode) {
    ::mkdir(path.c_str(), mode);
    ::chown(path.c_str(), owner, group);
    ::chmod(path.c_str(), mode);
}

// Base64 encoding of a simple dex files with 2 methods.
static const char kDexFile[] =
    "UEsDBBQAAAAIAOiOYUs9y6BLCgEAABQCAAALABwAY2xhc3Nlcy5kZXhVVAkAA/Ns+lkOHv1ZdXgL"
    "AAEEI+UCAASIEwAAS0mt4DIwNmX4qpn7j/2wA7v7N+ZvoQpCJRlVx5SWa4YaiDAxMBQwMDBUhJkI"
    "MUBBDyMDAzsDRJwFxAdioBDDHAYEYAbiFUAM1M5wAIhFGCGKDIDYAogdgNgDiH2BOAiI0xghekDm"
    "sQIxGxQzM6ACRijNhCbOhCZfyohdPYyuh8szgtVkMkLsLhAAqeCDi+ejibPZZOZlltgxsDnqZSWW"
    "JTKwOUFoZh9HayDhZM0g5AMS0M9JzEvX90/KSk0usWZgDAMaws5nAyXBzmpoYGlgAjsAyJoBMp0b"
    "zQ8gGhbOTEhhzYwU3qxIYc2GFN6MClC/AhUyKUDMAYU9M1Qc5F8GKBscVgIQM0FxCwBQSwECHgMU"
    "AAAACADojmFLPcugSwoBAAAUAgAACwAYAAAAAAAAAAAAoIEAAAAAY2xhc3Nlcy5kZXhVVAUAA/Ns"
    "+ll1eAsAAQQj5QIABIgTAABQSwUGAAAAAAEAAQBRAAAATwEAAAAA";


class DexoptTest : public testing::Test {
protected:
    static constexpr bool kDebug = false;
    static constexpr uid_t kSystemUid = 1000;
    static constexpr uid_t kSystemGid = 1000;
    static constexpr int32_t kOSdkVersion = 25;
    static constexpr int32_t kAppDataFlags = FLAG_STORAGE_CE | FLAG_STORAGE_DE;
    static constexpr uid_t kTestAppUid = 19999;
    static constexpr gid_t kTestAppGid = 19999;
    static constexpr int32_t kTestUserId = 0;

    InstalldNativeService* service_;
    std::unique_ptr<std::string> volume_uuid_;
    std::string package_name_;
    std::string app_apk_dir_;
    std::string app_private_dir_ce_;
    std::string app_private_dir_de_;
    std::string se_info_;

    int64_t ce_data_inode_;

    std::string secondary_dex_ce_;
    std::string secondary_dex_ce_link_;
    std::string secondary_dex_de_;

    virtual void SetUp() {
        setenv("ANDROID_LOG_TAGS", "*:v", 1);
        android::base::InitLogging(nullptr);

        service_ = new InstalldNativeService();

        volume_uuid_ = nullptr;
        package_name_ = "com.installd.test.dexopt";
        se_info_ = "default";

        init_globals_from_data_and_root();

        app_apk_dir_ = android_app_dir + package_name_;

        create_mock_app();
    }

    virtual void TearDown() {
        if (!kDebug) {
            service_->destroyAppData(
                volume_uuid_, package_name_, kTestUserId, kAppDataFlags, ce_data_inode_);
            run_cmd("rm -rf " + app_apk_dir_);
            run_cmd("rm -rf " + app_private_dir_ce_);
            run_cmd("rm -rf " + app_private_dir_de_);
        }
        delete service_;
    }

    void create_mock_app() {
        // Create the oat dir.
        std::string app_oat_dir = app_apk_dir_ + "/oat";
        mkdir(app_apk_dir_, kSystemUid, kSystemGid, 0755);
        service_->createOatDir(app_oat_dir, kRuntimeIsa);

        // Copy the primary apk.
        std::string apk_path = app_apk_dir_ + "/base.jar";
        ASSERT_TRUE(WriteBase64ToFile(kDexFile, apk_path, kSystemUid, kSystemGid, 0644));

        // Create the app user data.
        ASSERT_TRUE(service_->createAppData(
            volume_uuid_,
            package_name_,
            kTestUserId,
            kAppDataFlags,
            kTestAppUid,
            se_info_,
            kOSdkVersion,
            &ce_data_inode_).isOk());

        // Create a secondary dex file on CE storage
        const char* volume_uuid_cstr = volume_uuid_ == nullptr ? nullptr : volume_uuid_->c_str();
        app_private_dir_ce_ = create_data_user_ce_package_path(
                volume_uuid_cstr, kTestUserId, package_name_.c_str());
        secondary_dex_ce_ = app_private_dir_ce_ + "/secondary_ce.jar";
        ASSERT_TRUE(WriteBase64ToFile(kDexFile, secondary_dex_ce_, kTestAppUid, kTestAppGid, 0600));
        std::string app_private_dir_ce_link = create_data_user_ce_package_path_as_user_link(
                volume_uuid_cstr, kTestUserId, package_name_.c_str());
        secondary_dex_ce_link_ = app_private_dir_ce_link + "/secondary_ce.jar";

        // Create a secondary dex file on DE storage.
        app_private_dir_de_ = create_data_user_de_package_path(
                volume_uuid_cstr, kTestUserId, package_name_.c_str());
        secondary_dex_de_ = app_private_dir_de_ + "/secondary_de.jar";
        ASSERT_TRUE(WriteBase64ToFile(kDexFile, secondary_dex_de_, kTestAppUid, kTestAppGid, 0600));

        // Fix app data uid.
        ASSERT_TRUE(service_->fixupAppData(volume_uuid_, kTestUserId).isOk());
    }


    std::string get_secondary_dex_artifact(const std::string& path, const std::string& type) {
        std::string::size_type end = path.rfind('.');
        std::string::size_type start = path.rfind('/', end);
        return path.substr(0, start) + "/oat/" + kRuntimeIsa + "/" +
                path.substr(start + 1, end - start) + type;
    }

    void compile_secondary_dex(const std::string& path, int32_t dex_storage_flag,
            bool should_binder_call_succeed, bool should_dex_be_compiled = true,
            int uid = kTestAppUid) {
        std::unique_ptr<std::string> package_name_ptr(new std::string(package_name_));
        int32_t dexopt_needed = 0;  // does not matter;
        std::unique_ptr<std::string> out_path = nullptr;  // does not matter
        int32_t dex_flags = DEXOPT_SECONDARY_DEX | dex_storage_flag;
        std::string compiler_filter = "speed-profile";
        std::unique_ptr<std::string> class_loader_context_ptr(new std::string("&"));
        std::unique_ptr<std::string> se_info_ptr(new std::string(se_info_));
        bool downgrade = false;

        binder::Status result = service_->dexopt(path,
                                                 uid,
                                                 package_name_ptr,
                                                 kRuntimeIsa,
                                                 dexopt_needed,
                                                 out_path,
                                                 dex_flags,
                                                 compiler_filter,
                                                 volume_uuid_,
                                                 class_loader_context_ptr,
                                                 se_info_ptr,
                                                 downgrade);
        ASSERT_EQ(should_binder_call_succeed, result.isOk());
        int expected_access = should_dex_be_compiled ? 0 : -1;
        std::string odex = get_secondary_dex_artifact(path, "odex");
        std::string vdex = get_secondary_dex_artifact(path, "vdex");
        std::string art = get_secondary_dex_artifact(path, "art");
        ASSERT_EQ(expected_access, access(odex.c_str(), R_OK));
        ASSERT_EQ(expected_access, access(vdex.c_str(), R_OK));
        ASSERT_EQ(-1, access(art.c_str(), R_OK));  // empty profiles do not generate an image.
    }

    void reconcile_secondary_dex(const std::string& path, int32_t storage_flag,
            bool should_binder_call_succeed, bool should_dex_exist, bool should_dex_be_deleted,
            int uid = kTestAppUid, std::string* package_override = nullptr) {
        std::vector<std::string> isas;
        isas.push_back(kRuntimeIsa);
        bool out_secondary_dex_exists = false;
        binder::Status result = service_->reconcileSecondaryDexFile(
            path,
            package_override == nullptr ? package_name_ : *package_override,
            uid,
            isas,
            volume_uuid_,
            storage_flag,
            &out_secondary_dex_exists);

        ASSERT_EQ(should_binder_call_succeed, result.isOk());
        ASSERT_EQ(should_dex_exist, out_secondary_dex_exists);

        int expected_access = should_dex_be_deleted ? -1 : 0;
        std::string odex = get_secondary_dex_artifact(path, "odex");
        std::string vdex = get_secondary_dex_artifact(path, "vdex");
        std::string art = get_secondary_dex_artifact(path, "art");
        ASSERT_EQ(expected_access, access(odex.c_str(), F_OK));
        ASSERT_EQ(expected_access, access(vdex.c_str(), F_OK));
        ASSERT_EQ(-1, access(art.c_str(), R_OK));  // empty profiles do not generate an image.
    }
};


TEST_F(DexoptTest, DexoptSecondaryCe) {
    LOG(INFO) << "DexoptSecondaryCe";
    compile_secondary_dex(secondary_dex_ce_, DEXOPT_STORAGE_CE,
        /*binder_ok*/ true, /*compile_ok*/ true);
}

TEST_F(DexoptTest, DexoptSecondaryCeLink) {
    LOG(INFO) << "DexoptSecondaryCeLink";
    compile_secondary_dex(secondary_dex_ce_link_, DEXOPT_STORAGE_CE,
        /*binder_ok*/ true, /*compile_ok*/ true);
}

TEST_F(DexoptTest, DexoptSecondaryDe) {
    LOG(INFO) << "DexoptSecondaryDe";
    compile_secondary_dex(secondary_dex_de_, DEXOPT_STORAGE_DE,
        /*binder_ok*/ true, /*compile_ok*/ true);
}

TEST_F(DexoptTest, DexoptSecondaryDoesNotExist) {
    LOG(INFO) << "DexoptSecondaryDoesNotExist";
    // If the file validates but does not exist we do not treat it as an error.
    compile_secondary_dex(secondary_dex_ce_ + "not.there", DEXOPT_STORAGE_CE,
        /*binder_ok*/ true,  /*compile_ok*/ false);
}

TEST_F(DexoptTest, DexoptSecondaryStorageValidationError) {
    LOG(INFO) << "DexoptSecondaryStorageValidationError";
    compile_secondary_dex(secondary_dex_ce_, DEXOPT_STORAGE_DE,
        /*binder_ok*/ false,  /*compile_ok*/ false);
}

TEST_F(DexoptTest, DexoptSecondaryAppOwnershipValidationError) {
    LOG(INFO) << "DexoptSecondaryAppOwnershipValidationError";
    compile_secondary_dex("/data/data/random.app/secondary.jar", DEXOPT_STORAGE_CE,
        /*binder_ok*/ false,  /*compile_ok*/ false);
}

TEST_F(DexoptTest, DexoptSecondaryAcessViaDifferentUidError) {
    LOG(INFO) << "DexoptSecondaryAcessViaDifferentUidError";
    compile_secondary_dex(secondary_dex_ce_, DEXOPT_STORAGE_CE,
        /*binder_ok*/ false,  /*compile_ok*/ false, kSystemUid);
}


class ReconcileTest : public DexoptTest {
    virtual void SetUp() {
        DexoptTest::SetUp();
        compile_secondary_dex(secondary_dex_ce_, DEXOPT_STORAGE_CE,
            /*binder_ok*/ true, /*compile_ok*/ true);
        compile_secondary_dex(secondary_dex_de_, DEXOPT_STORAGE_DE,
            /*binder_ok*/ true, /*compile_ok*/ true);
    }
};

TEST_F(ReconcileTest, ReconcileSecondaryCeExists) {
    LOG(INFO) << "ReconcileSecondaryCeExists";
    reconcile_secondary_dex(secondary_dex_ce_, FLAG_STORAGE_CE,
        /*binder_ok*/ true, /*dex_ok */ true, /*odex_deleted*/ false);
}

TEST_F(ReconcileTest, ReconcileSecondaryCeLinkExists) {
    LOG(INFO) << "ReconcileSecondaryCeLinkExists";
    reconcile_secondary_dex(secondary_dex_ce_link_, FLAG_STORAGE_CE,
        /*binder_ok*/ true, /*dex_ok */ true, /*odex_deleted*/ false);
}

TEST_F(ReconcileTest, ReconcileSecondaryDeExists) {
    LOG(INFO) << "ReconcileSecondaryDeExists";
    reconcile_secondary_dex(secondary_dex_de_, FLAG_STORAGE_DE,
        /*binder_ok*/ true, /*dex_ok */ true, /*odex_deleted*/ false);
}

TEST_F(ReconcileTest, ReconcileSecondaryDeDoesNotExist) {
    LOG(INFO) << "ReconcileSecondaryDeDoesNotExist";
    run_cmd("rm -rf " + secondary_dex_de_);
    reconcile_secondary_dex(secondary_dex_de_, FLAG_STORAGE_DE,
        /*binder_ok*/ true, /*dex_ok */ false, /*odex_deleted*/ true);
}

TEST_F(ReconcileTest, ReconcileSecondaryStorageValidationError) {
    // Validation errors will not clean the odex/vdex/art files but will mark
    // the file as non existent so that the PM knows it should purge it from its
    // records.
    LOG(INFO) << "ReconcileSecondaryStorageValidationError";
    reconcile_secondary_dex(secondary_dex_ce_, FLAG_STORAGE_DE,
        /*binder_ok*/ true, /*dex_ok */ false, /*odex_deleted*/ false);
}

TEST_F(ReconcileTest, ReconcileSecondaryAppOwnershipValidationError) {
    LOG(INFO) << "ReconcileSecondaryAppOwnershipValidationError";
    // Attempt to reconcile the dex files of the test app from a different app.
    std::string another_app = "another.app";
    reconcile_secondary_dex(secondary_dex_ce_, FLAG_STORAGE_CE,
        /*binder_ok*/ true, /*dex_ok */ false, /*odex_deleted*/ false, kSystemUid, &another_app);
}

TEST_F(ReconcileTest, ReconcileSecondaryAcessViaDifferentUidError) {
    LOG(INFO) << "ReconcileSecondaryAcessViaDifferentUidError";
    reconcile_secondary_dex(secondary_dex_ce_, FLAG_STORAGE_CE,
        /*binder_ok*/ true, /*dex_ok */ false, /*odex_deleted*/ false, kSystemUid);
}

}  // namespace installd
}  // namespace android
