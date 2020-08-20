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
    PrepareBootImageAndBootClasspathFlags(use_jitzygote_image);

    PrepareInputFileFlags(zip_fd, oat_fd, input_vdex_fd, output_vdex_fd, image_fd, input_file_name,
                          output_file_name, profile_fd, dex_metadata_fd, swap_fd,
                          class_loader_context, class_loader_context_fds);

    PrepareCompilerConfigFlags(input_vdex_fd, output_vdex_fd, instruction_set, compiler_filter,
                               debuggable, target_sdk_version, enable_hidden_api_checks,
                               generate_compact_dex, compilation_reason);

    PrepareCompilerRuntimeAndPerfConfigFlags(post_bootcomplete, for_restore);

    const std::string dex2oat_flags = GetProperty("dalvik.vm.dex2oat-flags", "");
    std::vector<std::string> dex2oat_flags_args = SplitBySpaces(dex2oat_flags);
    ALOGV("dalvik.vm.dex2oat-flags=%s\n", dex2oat_flags.c_str());

    // Do not add args after dex2oat_flags, they should override others for debugging.
    for (auto it = dex2oat_flags_args.begin(); it != dex2oat_flags_args.end(); ++it) {
        AddArg(*it);
    }

    execv_helper_->PrepareArgs(dex2oat_bin_);
}

RunDex2Oat::~RunDex2Oat() {}

void RunDex2Oat::PrepareBootImageAndBootClasspathFlags(bool use_jitzygote_image) {
    std::string boot_image;
    if (use_jitzygote_image) {
        boot_image = StringPrintf("--boot-image=%s", kJitZygoteImage);
    } else {
        boot_image = MapPropertyToArg("dalvik.vm.boot-image", "--boot-image=%s");
    }
    AddArg(boot_image);

    // If DEX2OATBOOTCLASSPATH is not in the environment, dex2oat is going to query
    // BOOTCLASSPATH.
    char* dex2oat_bootclasspath = getenv("DEX2OATBOOTCLASSPATH");
    if (dex2oat_bootclasspath != nullptr) {
        AddRuntimeArg(StringPrintf("-Xbootclasspath:%s", dex2oat_bootclasspath));
    }

    std::string updatable_bcp_packages =
            MapPropertyToArg("dalvik.vm.dex2oat-updatable-bcp-packages-file",
                             "--updatable-bcp-packages-file=%s");
    if (updatable_bcp_packages.empty()) {
        // Make dex2oat fail by providing non-existent file name.
        updatable_bcp_packages =
                "--updatable-bcp-packages-file=/nonx/updatable-bcp-packages.txt";
    }
    AddArg(updatable_bcp_packages);
}

void RunDex2Oat::PrepareInputFileFlags(int zip_fd,
                                       int oat_fd,
                                       int input_vdex_fd,
                                       int output_vdex_fd,
                                       int image_fd,
                                       const char* input_file_name,
                                       const char* output_file_name,
                                       int profile_fd,
                                       int dex_metadata_fd,
                                       int swap_fd,
                                       const char* class_loader_context,
                                       const std::string& class_loader_context_fds) {
    std::string input_basename = Basename(input_file_name);
    ALOGV("Running %s in=%s out=%s\n", dex2oat_bin_.c_str(), input_basename.c_str(),
          output_file_name);

    AddArg(StringPrintf("--zip-fd=%d", zip_fd));
    AddArg(StringPrintf("--zip-location=%s", input_basename.c_str()));
    AddArg(StringPrintf("--oat-fd=%d", oat_fd));
    AddArg(StringPrintf("--oat-location=%s", output_file_name));
    AddArg(StringPrintf("--input-vdex-fd=%d", input_vdex_fd));
    AddArg(StringPrintf("--output-vdex-fd=%d", output_vdex_fd));

    if (image_fd >= 0) {
        AddArg(StringPrintf("--app-image-fd=%d", image_fd));
        AddArg(MapPropertyToArg("dalvik.vm.appimageformat", "--image-format=%s"));
    }
    if (dex_metadata_fd > -1) {
        AddArg("--dm-fd=" + std::to_string(dex_metadata_fd));
    }
    if (profile_fd != -1) {
        AddArg(StringPrintf("--profile-file-fd=%d", profile_fd));
    }
    if (swap_fd >= 0) {
        AddArg(StringPrintf("--swap-fd=%d", swap_fd));
    }

    // Get the directory of the apk to pass as a base classpath directory.
    {
        std::string apk_dir(input_file_name);
        size_t dir_index = apk_dir.rfind('/');
        if (dir_index != std::string::npos) {
            apk_dir = apk_dir.substr(0, dir_index);
            AddArg(StringPrintf("--classpath-dir=%s", apk_dir.c_str()));
        }
    }

    if (class_loader_context != nullptr) {
        AddArg(StringPrintf("--class-loader-context=%s", class_loader_context));
        if (!class_loader_context_fds.empty()) {
            AddArg(StringPrintf("--class-loader-context-fds=%s",
                                class_loader_context_fds.c_str()));
        }
    }
}

void RunDex2Oat::PrepareCompilerConfigFlags(int input_vdex_fd,
                                            int output_vdex_fd,
                                            const char* instruction_set,
                                            const char* compiler_filter,
                                            bool debuggable,
                                            int target_sdk_version,
                                            bool enable_hidden_api_checks,
                                            bool generate_compact_dex,
                                            const char* compilation_reason) {
    // Disable cdex if update input vdex is true since this combination of options is not
    // supported.
    const bool disable_cdex = !generate_compact_dex || (input_vdex_fd == output_vdex_fd);
    if (disable_cdex) {
        AddArg(kDisableCompactDexFlag);
    }
    
    // ISA related
    {
        AddArg(StringPrintf("--instruction-set=%s", instruction_set));

        const std::string dex2oat_isa_features_key =
                StringPrintf("dalvik.vm.isa.%s.features", instruction_set);
        std::string instruction_set_features_arg =
                MapPropertyToArg(dex2oat_isa_features_key, "--instruction-set-features=%s");
        AddArg(instruction_set_features_arg);

        const std::string dex2oat_isa_variant_key =
                StringPrintf("dalvik.vm.isa.%s.variant", instruction_set);
        std::string instruction_set_variant_arg =
                MapPropertyToArg(dex2oat_isa_variant_key, "--instruction-set-variant=%s");
        AddArg(instruction_set_variant_arg);
    }

    // Compute compiler filter.
    {
        std::string dex2oat_compiler_filter_arg;
        {
            // If we are booting without the real /data, don't spend time compiling.
            std::string vold_decrypt = GetProperty("vold.decrypt", "");
            bool skip_compilation = vold_decrypt == "trigger_restart_min_framework" ||
                    vold_decrypt == "1";

            bool have_dex2oat_relocation_skip_flag = false;
            if (skip_compilation) {
                dex2oat_compiler_filter_arg = "--compiler-filter=extract";
                have_dex2oat_relocation_skip_flag = true;
            } else if (compiler_filter != nullptr) {
                dex2oat_compiler_filter_arg = StringPrintf("--compiler-filter=%s",
                                                           compiler_filter);
            }
            if (have_dex2oat_relocation_skip_flag) {
                AddRuntimeArg("-Xnorelocate");
            }
        }

        if (dex2oat_compiler_filter_arg.empty()) {
            dex2oat_compiler_filter_arg = MapPropertyToArg("dalvik.vm.dex2oat-filter",
                                                           "--compiler-filter=%s");
        }
        AddArg(dex2oat_compiler_filter_arg);

        if (compilation_reason != nullptr) {
            AddArg(std::string("--compilation-reason=") + compilation_reason);
        }
    }

    AddArg(MapPropertyToArg("dalvik.vm.dex2oat-max-image-block-size",
                            "--max-image-block-size=%s"));

    AddArg(MapPropertyToArg("dalvik.vm.dex2oat-very-large",
                            "--very-large-app-threshold=%s"));

    std::string resolve_startup_string_arg = MapPropertyToArg(
        "persist.device_config.runtime.dex2oat_resolve_startup_strings",
        "--resolve-startup-const-strings=%s");
    if (resolve_startup_string_arg.empty()) {
        // If empty, fall back to system property.
        resolve_startup_string_arg =
                MapPropertyToArg("dalvik.vm.dex2oat-resolve-startup-strings",
                                 "--resolve-startup-const-strings=%s");
    }
    AddArg(resolve_startup_string_arg);

    // Debug related
    {
        // Check whether all apps should be compiled debuggable.
        if (!debuggable) {
            debuggable = GetProperty("dalvik.vm.always_debuggable", "") == "1";
        }
        if (debuggable) {
            AddArg("--debuggable");
        }

        const bool generate_debug_info = GetBoolProperty("debug.generate-debug-info", false);
        if (generate_debug_info) {
            AddArg("--generate-debug-info");
        }
        {
            bool generate_minidebug_info = kEnableMinidebugInfo &&
                    GetBoolProperty(kMinidebugInfoSystemProperty,
                                    kMinidebugInfoSystemPropertyDefault);
            if (generate_minidebug_info) {
                AddArg(kMinidebugDex2oatFlag);
            }
        }
    }

    if (target_sdk_version != 0) {
        AddRuntimeArg(StringPrintf("-Xtarget-sdk-version:%d", target_sdk_version));
    }

    if (enable_hidden_api_checks) {
        AddRuntimeArg("-Xhidden-api-policy:enabled");
    }
}

void RunDex2Oat::PrepareCompilerRuntimeAndPerfConfigFlags(bool post_bootcomplete,
                                                          bool for_restore) {
    // CPU set
    {
        std::string cpu_set_format = "--cpu-set=%s";
        std::string dex2oat_cpu_set_arg = post_bootcomplete
                ? (for_restore
                   ? MapPropertyToArgWithBackup(
                           "dalvik.vm.restore-dex2oat-cpu-set",
                           "dalvik.vm.dex2oat-cpu-set",
                           cpu_set_format)
                   : MapPropertyToArg("dalvik.vm.dex2oat-cpu-set", cpu_set_format))
                : MapPropertyToArg("dalvik.vm.boot-dex2oat-cpu-set", cpu_set_format);
        AddArg(dex2oat_cpu_set_arg);
    }

    // Number of threads
    {
        std::string threads_format = "-j%s";
        std::string dex2oat_threads_arg = post_bootcomplete
                ? (for_restore
                   ? MapPropertyToArgWithBackup(
                           "dalvik.vm.restore-dex2oat-threads",
                           "dalvik.vm.dex2oat-threads",
                           threads_format)
                   : MapPropertyToArg("dalvik.vm.dex2oat-threads", threads_format))
                : MapPropertyToArg("dalvik.vm.boot-dex2oat-threads", threads_format);
        AddArg(dex2oat_threads_arg);
    }

    AddRuntimeArg(MapPropertyToArg("dalvik.vm.dex2oat-Xms", "-Xms%s"));
    AddRuntimeArg(MapPropertyToArg("dalvik.vm.dex2oat-Xmx", "-Xmx%s"));
}

void RunDex2Oat::Exec(int exit_code) {
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
