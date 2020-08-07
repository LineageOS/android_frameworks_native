/*
 * Copyright (C) 2020 The Android Open Source Project
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
#define LOG_TAG "installd"

#include "run_dex2oat.h"

#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <log/log.h>
#include <server_configurable_flags/get_flags.h>

using android::base::Basename;
using android::base::StringPrintf;

namespace android {
namespace installd {

namespace {

// Should minidebug info be included in compiled artifacts? Even if this value is
// "true," usage might still be conditional to other constraints, e.g., system
// property overrides.
static constexpr bool kEnableMinidebugInfo = true;

static constexpr const char* kMinidebugInfoSystemProperty = "dalvik.vm.dex2oat-minidebuginfo";
static constexpr bool kMinidebugInfoSystemPropertyDefault = false;
static constexpr const char* kMinidebugDex2oatFlag = "--generate-mini-debug-info";
static constexpr const char* kDisableCompactDexFlag = "--compact-dex-level=none";

// Location of the JIT Zygote image.
static const char* kJitZygoteImage =
    "boot.art:/nonx/boot-framework.art!/system/etc/boot-image.prof";

std::vector<std::string> SplitBySpaces(const std::string& str) {
    if (str.empty()) {
        return {};
    }
    return android::base::Split(str, " ");
}

}  // namespace

RunDex2Oat::RunDex2Oat(const char* dex2oat_bin, ExecVHelper* execv_helper)
  : dex2oat_bin_(dex2oat_bin), execv_helper_(execv_helper) {}

void RunDex2Oat::Initialize(int zip_fd,
                            int oat_fd,
                            int input_vdex_fd,
                            int output_vdex_fd,
                            int image_fd,
                            const char* input_file_name,
                            const char* output_file_name,
                            int swap_fd,
                            const char* instruction_set,
                            const char* compiler_filter,
                            bool debuggable,
                            bool post_bootcomplete,
                            bool for_restore,
                            int profile_fd,
                            const char* class_loader_context,
                            const std::string& class_loader_context_fds,
                            int target_sdk_version,
                            bool enable_hidden_api_checks,
                            bool generate_compact_dex,
                            int dex_metadata_fd,
                            bool use_jitzygote_image,
                            const char* compilation_reason) {
    // Get the relative path to the input file.
    std::string input_basename = Basename(input_file_name);

    std::string dex2oat_Xms_arg = MapPropertyToArg("dalvik.vm.dex2oat-Xms", "-Xms%s");
    std::string dex2oat_Xmx_arg = MapPropertyToArg("dalvik.vm.dex2oat-Xmx", "-Xmx%s");

    std::string threads_format = "-j%s";
    std::string dex2oat_threads_arg = post_bootcomplete
            ? (for_restore
                ? MapPropertyToArgWithBackup(
                        "dalvik.vm.restore-dex2oat-threads",
                        "dalvik.vm.dex2oat-threads",
                        threads_format)
                : MapPropertyToArg("dalvik.vm.dex2oat-threads", threads_format))
            : MapPropertyToArg("dalvik.vm.boot-dex2oat-threads", threads_format);
    std::string cpu_set_format = "--cpu-set=%s";
    std::string dex2oat_cpu_set_arg = post_bootcomplete
            ? (for_restore
                ? MapPropertyToArgWithBackup(
                        "dalvik.vm.restore-dex2oat-cpu-set",
                        "dalvik.vm.dex2oat-cpu-set",
                        cpu_set_format)
                : MapPropertyToArg("dalvik.vm.dex2oat-cpu-set", cpu_set_format))
            : MapPropertyToArg("dalvik.vm.boot-dex2oat-cpu-set", cpu_set_format);

    std::string bootclasspath;
    char* dex2oat_bootclasspath = getenv("DEX2OATBOOTCLASSPATH");
    if (dex2oat_bootclasspath != nullptr) {
        bootclasspath = StringPrintf("-Xbootclasspath:%s", dex2oat_bootclasspath);
    }
    // If DEX2OATBOOTCLASSPATH is not in the environment, dex2oat is going to query
    // BOOTCLASSPATH.

    const std::string dex2oat_isa_features_key =
            StringPrintf("dalvik.vm.isa.%s.features", instruction_set);
    std::string instruction_set_features_arg =
        MapPropertyToArg(dex2oat_isa_features_key, "--instruction-set-features=%s");

    const std::string dex2oat_isa_variant_key =
            StringPrintf("dalvik.vm.isa.%s.variant", instruction_set);
    std::string instruction_set_variant_arg =
        MapPropertyToArg(dex2oat_isa_variant_key, "--instruction-set-variant=%s");

    const char* dex2oat_norelocation = "-Xnorelocate";

    const std::string dex2oat_flags = GetProperty("dalvik.vm.dex2oat-flags", "");
    std::vector<std::string> dex2oat_flags_args = SplitBySpaces(dex2oat_flags);
    ALOGV("dalvik.vm.dex2oat-flags=%s\n", dex2oat_flags.c_str());

    // If we are booting without the real /data, don't spend time compiling.
    std::string vold_decrypt = GetProperty("vold.decrypt", "");
    bool skip_compilation = vold_decrypt == "trigger_restart_min_framework" ||
                            vold_decrypt == "1";

    std::string updatable_bcp_packages =
        MapPropertyToArg("dalvik.vm.dex2oat-updatable-bcp-packages-file",
                         "--updatable-bcp-packages-file=%s");
    if (updatable_bcp_packages.empty()) {
      // Make dex2oat fail by providing non-existent file name.
      updatable_bcp_packages = "--updatable-bcp-packages-file=/nonx/updatable-bcp-packages.txt";
    }

    std::string resolve_startup_string_arg =
            MapPropertyToArg("persist.device_config.runtime.dex2oat_resolve_startup_strings",
                             "--resolve-startup-const-strings=%s");
    if (resolve_startup_string_arg.empty()) {
      // If empty, fall back to system property.
      resolve_startup_string_arg =
            MapPropertyToArg("dalvik.vm.dex2oat-resolve-startup-strings",
                             "--resolve-startup-const-strings=%s");
    }

    const std::string image_block_size_arg =
            MapPropertyToArg("dalvik.vm.dex2oat-max-image-block-size",
                             "--max-image-block-size=%s");

    const bool generate_debug_info = GetBoolProperty("debug.generate-debug-info", false);

    std::string image_format_arg;
    if (image_fd >= 0) {
        image_format_arg = MapPropertyToArg("dalvik.vm.appimageformat", "--image-format=%s");
    }

    std::string dex2oat_large_app_threshold_arg =
        MapPropertyToArg("dalvik.vm.dex2oat-very-large", "--very-large-app-threshold=%s");

    bool generate_minidebug_info = kEnableMinidebugInfo &&
            GetBoolProperty(kMinidebugInfoSystemProperty, kMinidebugInfoSystemPropertyDefault);

    std::string boot_image;
    if (use_jitzygote_image) {
      boot_image = StringPrintf("--boot-image=%s", kJitZygoteImage);
    } else {
      boot_image = MapPropertyToArg("dalvik.vm.boot-image", "--boot-image=%s");
    }

    // clang FORTIFY doesn't let us use strlen in constant array bounds, so we
    // use arraysize instead.
    std::string zip_fd_arg = StringPrintf("--zip-fd=%d", zip_fd);
    std::string zip_location_arg = StringPrintf("--zip-location=%s", input_basename.c_str());
    std::string input_vdex_fd_arg = StringPrintf("--input-vdex-fd=%d", input_vdex_fd);
    std::string output_vdex_fd_arg = StringPrintf("--output-vdex-fd=%d", output_vdex_fd);
    std::string oat_fd_arg = StringPrintf("--oat-fd=%d", oat_fd);
    std::string oat_location_arg = StringPrintf("--oat-location=%s", output_file_name);
    std::string instruction_set_arg = StringPrintf("--instruction-set=%s", instruction_set);
    std::string dex2oat_compiler_filter_arg;
    std::string dex2oat_swap_fd;
    std::string dex2oat_image_fd;
    std::string target_sdk_version_arg;
    if (target_sdk_version != 0) {
        target_sdk_version_arg = StringPrintf("-Xtarget-sdk-version:%d", target_sdk_version);
    }
    std::string class_loader_context_arg;
    std::string class_loader_context_fds_arg;
    if (class_loader_context != nullptr) {
        class_loader_context_arg = StringPrintf("--class-loader-context=%s",
                                                class_loader_context);
        if (!class_loader_context_fds.empty()) {
            class_loader_context_fds_arg = StringPrintf("--class-loader-context-fds=%s",
                                                        class_loader_context_fds.c_str());
        }
    }

    if (swap_fd >= 0) {
        dex2oat_swap_fd = StringPrintf("--swap-fd=%d", swap_fd);
    }
    if (image_fd >= 0) {
        dex2oat_image_fd = StringPrintf("--app-image-fd=%d", image_fd);
    }

    // Compute compiler filter.
    bool have_dex2oat_relocation_skip_flag = false;
    if (skip_compilation) {
        dex2oat_compiler_filter_arg = "--compiler-filter=extract";
        have_dex2oat_relocation_skip_flag = true;
    } else if (compiler_filter != nullptr) {
        dex2oat_compiler_filter_arg = StringPrintf("--compiler-filter=%s", compiler_filter);
    }

    if (dex2oat_compiler_filter_arg.empty()) {
        dex2oat_compiler_filter_arg = MapPropertyToArg("dalvik.vm.dex2oat-filter",
                                                       "--compiler-filter=%s");
    }

    // Check whether all apps should be compiled debuggable.
    if (!debuggable) {
        debuggable = GetProperty("dalvik.vm.always_debuggable", "") == "1";
    }
    std::string profile_arg;
    if (profile_fd != -1) {
        profile_arg = StringPrintf("--profile-file-fd=%d", profile_fd);
    }

    // Get the directory of the apk to pass as a base classpath directory.
    std::string base_dir;
    std::string apk_dir(input_file_name);
    unsigned long dir_index = apk_dir.rfind('/');
    bool has_base_dir = dir_index != std::string::npos;
    if (has_base_dir) {
        apk_dir = apk_dir.substr(0, dir_index);
        base_dir = StringPrintf("--classpath-dir=%s", apk_dir.c_str());
    }

    std::string dex_metadata_fd_arg = "--dm-fd=" + std::to_string(dex_metadata_fd);

    std::string compilation_reason_arg = compilation_reason == nullptr
            ? ""
            : std::string("--compilation-reason=") + compilation_reason;

    ALOGV("Running %s in=%s out=%s\n", dex2oat_bin_.c_str(), input_basename.c_str(),
          output_file_name);

    // Disable cdex if update input vdex is true since this combination of options is not
    // supported.
    const bool disable_cdex = !generate_compact_dex || (input_vdex_fd == output_vdex_fd);

    AddArg(zip_fd_arg);
    AddArg(zip_location_arg);
    AddArg(input_vdex_fd_arg);
    AddArg(output_vdex_fd_arg);
    AddArg(oat_fd_arg);
    AddArg(oat_location_arg);
    AddArg(instruction_set_arg);

    AddArg(instruction_set_variant_arg);
    AddArg(instruction_set_features_arg);

    AddArg(boot_image);

    AddRuntimeArg(bootclasspath);
    AddRuntimeArg(dex2oat_Xms_arg);
    AddRuntimeArg(dex2oat_Xmx_arg);

    AddArg(updatable_bcp_packages);
    AddArg(resolve_startup_string_arg);
    AddArg(image_block_size_arg);
    AddArg(dex2oat_compiler_filter_arg);
    AddArg(dex2oat_threads_arg);
    AddArg(dex2oat_cpu_set_arg);
    AddArg(dex2oat_swap_fd);
    AddArg(dex2oat_image_fd);

    if (generate_debug_info) {
        AddArg("--generate-debug-info");
    }
    if (debuggable) {
        AddArg("--debuggable");
    }
    AddArg(image_format_arg);
    AddArg(dex2oat_large_app_threshold_arg);

    if (have_dex2oat_relocation_skip_flag) {
        AddRuntimeArg(dex2oat_norelocation);
    }
    AddArg(profile_arg);
    AddArg(base_dir);
    AddArg(class_loader_context_arg);
    AddArg(class_loader_context_fds_arg);
    if (generate_minidebug_info) {
        AddArg(kMinidebugDex2oatFlag);
    }
    if (disable_cdex) {
        AddArg(kDisableCompactDexFlag);
    }
    AddRuntimeArg(target_sdk_version_arg);
    if (enable_hidden_api_checks) {
        AddRuntimeArg("-Xhidden-api-policy:enabled");
    }

    if (dex_metadata_fd > -1) {
        AddArg(dex_metadata_fd_arg);
    }

    AddArg(compilation_reason_arg);

    // Do not add args after dex2oat_flags, they should override others for debugging.
    for (auto it = dex2oat_flags_args.begin(); it != dex2oat_flags_args.end(); ++it) {
        AddArg(*it);
    }

    execv_helper_->PrepareArgs(dex2oat_bin_);
}

RunDex2Oat::~RunDex2Oat() {}

void RunDex2Oat::Exec(int exit_code) {
    LOG(ERROR) << "RunDex2Oat::Exec";
    execv_helper_->Exec(exit_code);
}

void RunDex2Oat::AddArg(const std::string& arg) {
    execv_helper_->AddArg(arg);
}

void RunDex2Oat::AddRuntimeArg(const std::string& arg) {
    execv_helper_->AddRuntimeArg(arg);
}

std::string RunDex2Oat::GetProperty(const std::string& key,
                                    const std::string& default_value) {
    return android::base::GetProperty(key, default_value);
}

bool RunDex2Oat::GetBoolProperty(const std::string& key, bool default_value) {
    return android::base::GetBoolProperty(key, default_value);
}

std::string RunDex2Oat::MapPropertyToArg(const std::string& property,
                                         const std::string& format,
                                         const std::string& default_value) {
    std::string prop = GetProperty(property, default_value);
    if (!prop.empty()) {
        return StringPrintf(format.c_str(), prop.c_str());
    }
    return "";
}

std::string RunDex2Oat::MapPropertyToArgWithBackup(
        const std::string& property,
        const std::string& backupProperty,
        const std::string& format,
        const std::string& default_value) {
    std::string value = GetProperty(property, default_value);
    if (!value.empty()) {
        return StringPrintf(format.c_str(), value.c_str());
    }
    return MapPropertyToArg(backupProperty, format, default_value);
}

}  // namespace installd
}  // namespace android
