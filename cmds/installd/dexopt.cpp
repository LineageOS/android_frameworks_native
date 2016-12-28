/*
 * Copyright (C) 2016 The Android Open Source Project
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
#define LOG_TAG "installed"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android/log.h>               // TODO: Move everything to base/logging.
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/properties.h>
#include <cutils/sched_policy.h>
#include <private/android_filesystem_config.h>
#include <system/thread_defs.h>

#include "dexopt.h"
#include "installd_deps.h"
#include "otapreopt_utils.h"
#include "utils.h"

using android::base::StringPrintf;
using android::base::EndsWith;

namespace android {
namespace installd {

static const char* parse_null(const char* arg) {
    if (strcmp(arg, "!") == 0) {
        return nullptr;
    } else {
        return arg;
    }
}

static bool clear_profile(const std::string& profile) {
    base::unique_fd ufd(open(profile.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC));
    if (ufd.get() < 0) {
        if (errno != ENOENT) {
            PLOG(WARNING) << "Could not open profile " << profile;
            return false;
        } else {
            // Nothing to clear. That's ok.
            return true;
        }
    }

    if (flock(ufd.get(), LOCK_EX | LOCK_NB) != 0) {
        if (errno != EWOULDBLOCK) {
            PLOG(WARNING) << "Error locking profile " << profile;
        }
        // This implies that the app owning this profile is running
        // (and has acquired the lock).
        //
        // If we can't acquire the lock bail out since clearing is useless anyway
        // (the app will write again to the profile).
        //
        // Note:
        // This does not impact the this is not an issue for the profiling correctness.
        // In case this is needed because of an app upgrade, profiles will still be
        // eventually cleared by the app itself due to checksum mismatch.
        // If this is needed because profman advised, then keeping the data around
        // until the next run is again not an issue.
        //
        // If the app attempts to acquire a lock while we've held one here,
        // it will simply skip the current write cycle.
        return false;
    }

    bool truncated = ftruncate(ufd.get(), 0) == 0;
    if (!truncated) {
        PLOG(WARNING) << "Could not truncate " << profile;
    }
    if (flock(ufd.get(), LOCK_UN) != 0) {
        PLOG(WARNING) << "Error unlocking profile " << profile;
    }
    return truncated;
}

bool clear_reference_profile(const char* pkgname) {
    std::string reference_profile_dir = create_data_ref_profile_package_path(pkgname);
    std::string reference_profile = create_primary_profile(reference_profile_dir);
    return clear_profile(reference_profile);
}

bool clear_current_profile(const char* pkgname, userid_t user) {
    std::string profile_dir = create_data_user_profile_package_path(user, pkgname);
    std::string profile = create_primary_profile(profile_dir);
    return clear_profile(profile);
}

bool clear_current_profiles(const char* pkgname) {
    bool success = true;
    std::vector<userid_t> users = get_known_users(/*volume_uuid*/ nullptr);
    for (auto user : users) {
        success &= clear_current_profile(pkgname, user);
    }
    return success;
}

static int split_count(const char *str)
{
  char *ctx;
  int count = 0;
  char buf[kPropertyValueMax];

  strncpy(buf, str, sizeof(buf));
  char *pBuf = buf;

  while(strtok_r(pBuf, " ", &ctx) != NULL) {
    count++;
    pBuf = NULL;
  }

  return count;
}

static int split(char *buf, const char **argv)
{
  char *ctx;
  int count = 0;
  char *tok;
  char *pBuf = buf;

  while((tok = strtok_r(pBuf, " ", &ctx)) != NULL) {
    argv[count++] = tok;
    pBuf = NULL;
  }

  return count;
}

static void run_patchoat(int input_oat_fd, int input_vdex_fd, int out_oat_fd, int out_vdex_fd,
    const char* input_oat_file_name, const char* input_vdex_file_name,
    const char* output_oat_file_name, const char* output_vdex_file_name,
    const char *pkgname ATTRIBUTE_UNUSED, const char *instruction_set)
{
    static const int MAX_INT_LEN = 12;      // '-'+10dig+'\0' -OR- 0x+8dig
    static const unsigned int MAX_INSTRUCTION_SET_LEN = 7;

    static const char* PATCHOAT_BIN = "/system/bin/patchoat";
    if (strlen(instruction_set) >= MAX_INSTRUCTION_SET_LEN) {
        ALOGE("Instruction set %s longer than max length of %d",
              instruction_set, MAX_INSTRUCTION_SET_LEN);
        return;
    }

    /* input_file_name/input_fd should be the .odex/.oat file that is precompiled. I think*/
    char instruction_set_arg[strlen("--instruction-set=") + MAX_INSTRUCTION_SET_LEN];
    char input_oat_fd_arg[strlen("--input-oat-fd=") + MAX_INT_LEN];
    char input_vdex_fd_arg[strlen("--input-vdex-fd=") + MAX_INT_LEN];
    char output_oat_fd_arg[strlen("--output-oat-fd=") + MAX_INT_LEN];
    char output_vdex_fd_arg[strlen("--output-vdex-fd=") + MAX_INT_LEN];
    const char* patched_image_location_arg = "--patched-image-location=/system/framework/boot.art";
    // The caller has already gotten all the locks we need.
    const char* no_lock_arg = "--no-lock-output";
    sprintf(instruction_set_arg, "--instruction-set=%s", instruction_set);
    sprintf(output_oat_fd_arg, "--output-oat-fd=%d", out_oat_fd);
    sprintf(input_oat_fd_arg, "--input-oat-fd=%d", input_oat_fd);
    ALOGV("Running %s isa=%s in-oat-fd=%d (%s) in-vdex-fd=%d (%s) "
          "out-oat-fd=%d (%s) out-vdex-fd=%d (%s)\n",
          PATCHOAT_BIN, instruction_set,
          input_oat_fd, input_oat_file_name,
          input_vdex_fd, input_vdex_file_name,
          out_oat_fd, output_oat_file_name,
          out_vdex_fd, output_vdex_file_name);

    /* patchoat, patched-image-location, no-lock, isa, input-fd, output-fd */
    char* argv[9];
    argv[0] = (char*) PATCHOAT_BIN;
    argv[1] = (char*) patched_image_location_arg;
    argv[2] = (char*) no_lock_arg;
    argv[3] = instruction_set_arg;
    argv[4] = input_oat_fd_arg;
    argv[5] = input_vdex_fd_arg;
    argv[6] = output_oat_fd_arg;
    argv[7] = output_vdex_fd_arg;
    argv[8] = NULL;

    execv(PATCHOAT_BIN, (char* const *)argv);
    ALOGE("execv(%s) failed: %s\n", PATCHOAT_BIN, strerror(errno));
}

static void run_dex2oat(int zip_fd, int oat_fd, int input_vdex_fd, int output_vdex_fd, int image_fd,
        const char* input_file_name, const char* output_file_name, int swap_fd,
        const char *instruction_set, const char* compiler_filter, bool vm_safe_mode,
        bool debuggable, bool post_bootcomplete, int profile_fd, const char* shared_libraries) {
    static const unsigned int MAX_INSTRUCTION_SET_LEN = 7;

    if (strlen(instruction_set) >= MAX_INSTRUCTION_SET_LEN) {
        ALOGE("Instruction set %s longer than max length of %d",
              instruction_set, MAX_INSTRUCTION_SET_LEN);
        return;
    }

    char dex2oat_Xms_flag[kPropertyValueMax];
    bool have_dex2oat_Xms_flag = get_property("dalvik.vm.dex2oat-Xms", dex2oat_Xms_flag, NULL) > 0;

    char dex2oat_Xmx_flag[kPropertyValueMax];
    bool have_dex2oat_Xmx_flag = get_property("dalvik.vm.dex2oat-Xmx", dex2oat_Xmx_flag, NULL) > 0;

    char dex2oat_threads_buf[kPropertyValueMax];
    bool have_dex2oat_threads_flag = get_property(post_bootcomplete
                                                      ? "dalvik.vm.dex2oat-threads"
                                                      : "dalvik.vm.boot-dex2oat-threads",
                                                  dex2oat_threads_buf,
                                                  NULL) > 0;
    char dex2oat_threads_arg[kPropertyValueMax + 2];
    if (have_dex2oat_threads_flag) {
        sprintf(dex2oat_threads_arg, "-j%s", dex2oat_threads_buf);
    }

    char dex2oat_isa_features_key[kPropertyKeyMax];
    sprintf(dex2oat_isa_features_key, "dalvik.vm.isa.%s.features", instruction_set);
    char dex2oat_isa_features[kPropertyValueMax];
    bool have_dex2oat_isa_features = get_property(dex2oat_isa_features_key,
                                                  dex2oat_isa_features, NULL) > 0;

    char dex2oat_isa_variant_key[kPropertyKeyMax];
    sprintf(dex2oat_isa_variant_key, "dalvik.vm.isa.%s.variant", instruction_set);
    char dex2oat_isa_variant[kPropertyValueMax];
    bool have_dex2oat_isa_variant = get_property(dex2oat_isa_variant_key,
                                                 dex2oat_isa_variant, NULL) > 0;

    const char *dex2oat_norelocation = "-Xnorelocate";
    bool have_dex2oat_relocation_skip_flag = false;

    char dex2oat_flags[kPropertyValueMax];
    int dex2oat_flags_count = get_property("dalvik.vm.dex2oat-flags",
                                 dex2oat_flags, NULL) <= 0 ? 0 : split_count(dex2oat_flags);
    ALOGV("dalvik.vm.dex2oat-flags=%s\n", dex2oat_flags);

    // If we booting without the real /data, don't spend time compiling.
    char vold_decrypt[kPropertyValueMax];
    bool have_vold_decrypt = get_property("vold.decrypt", vold_decrypt, "") > 0;
    bool skip_compilation = (have_vold_decrypt &&
                             (strcmp(vold_decrypt, "trigger_restart_min_framework") == 0 ||
                             (strcmp(vold_decrypt, "1") == 0)));

    bool generate_debug_info = property_get_bool("debug.generate-debug-info", false);

    char app_image_format[kPropertyValueMax];
    char image_format_arg[strlen("--image-format=") + kPropertyValueMax];
    bool have_app_image_format =
            image_fd >= 0 && get_property("dalvik.vm.appimageformat", app_image_format, NULL) > 0;
    if (have_app_image_format) {
        sprintf(image_format_arg, "--image-format=%s", app_image_format);
    }

    char dex2oat_large_app_threshold[kPropertyValueMax];
    bool have_dex2oat_large_app_threshold =
            get_property("dalvik.vm.dex2oat-very-large", dex2oat_large_app_threshold, NULL) > 0;
    char dex2oat_large_app_threshold_arg[strlen("--very-large-app-threshold=") + kPropertyValueMax];
    if (have_dex2oat_large_app_threshold) {
        sprintf(dex2oat_large_app_threshold_arg,
                "--very-large-app-threshold=%s",
                dex2oat_large_app_threshold);
    }

    static const char* DEX2OAT_BIN = "/system/bin/dex2oat";

    static const char* RUNTIME_ARG = "--runtime-arg";

    static const int MAX_INT_LEN = 12;      // '-'+10dig+'\0' -OR- 0x+8dig

    char zip_fd_arg[strlen("--zip-fd=") + MAX_INT_LEN];
    char zip_location_arg[strlen("--zip-location=") + PKG_PATH_MAX];
    char input_vdex_fd_arg[strlen("--input-vdex-fd=") + MAX_INT_LEN];
    char output_vdex_fd_arg[strlen("--output-vdex-fd=") + MAX_INT_LEN];
    char oat_fd_arg[strlen("--oat-fd=") + MAX_INT_LEN];
    char oat_location_arg[strlen("--oat-location=") + PKG_PATH_MAX];
    char instruction_set_arg[strlen("--instruction-set=") + MAX_INSTRUCTION_SET_LEN];
    char instruction_set_variant_arg[strlen("--instruction-set-variant=") + kPropertyValueMax];
    char instruction_set_features_arg[strlen("--instruction-set-features=") + kPropertyValueMax];
    char dex2oat_Xms_arg[strlen("-Xms") + kPropertyValueMax];
    char dex2oat_Xmx_arg[strlen("-Xmx") + kPropertyValueMax];
    char dex2oat_compiler_filter_arg[strlen("--compiler-filter=") + kPropertyValueMax];
    bool have_dex2oat_swap_fd = false;
    char dex2oat_swap_fd[strlen("--swap-fd=") + MAX_INT_LEN];
    bool have_dex2oat_image_fd = false;
    char dex2oat_image_fd[strlen("--app-image-fd=") + MAX_INT_LEN];

    sprintf(zip_fd_arg, "--zip-fd=%d", zip_fd);
    sprintf(zip_location_arg, "--zip-location=%s", input_file_name);
    sprintf(input_vdex_fd_arg, "--input-vdex-fd=%d", input_vdex_fd);
    sprintf(output_vdex_fd_arg, "--output-vdex-fd=%d", output_vdex_fd);
    sprintf(oat_fd_arg, "--oat-fd=%d", oat_fd);
    sprintf(oat_location_arg, "--oat-location=%s", output_file_name);
    sprintf(instruction_set_arg, "--instruction-set=%s", instruction_set);
    sprintf(instruction_set_variant_arg, "--instruction-set-variant=%s", dex2oat_isa_variant);
    sprintf(instruction_set_features_arg, "--instruction-set-features=%s", dex2oat_isa_features);
    if (swap_fd >= 0) {
        have_dex2oat_swap_fd = true;
        sprintf(dex2oat_swap_fd, "--swap-fd=%d", swap_fd);
    }
    if (image_fd >= 0) {
        have_dex2oat_image_fd = true;
        sprintf(dex2oat_image_fd, "--app-image-fd=%d", image_fd);
    }

    if (have_dex2oat_Xms_flag) {
        sprintf(dex2oat_Xms_arg, "-Xms%s", dex2oat_Xms_flag);
    }
    if (have_dex2oat_Xmx_flag) {
        sprintf(dex2oat_Xmx_arg, "-Xmx%s", dex2oat_Xmx_flag);
    }

    // Compute compiler filter.

    bool have_dex2oat_compiler_filter_flag;
    if (skip_compilation) {
        strcpy(dex2oat_compiler_filter_arg, "--compiler-filter=verify-none");
        have_dex2oat_compiler_filter_flag = true;
        have_dex2oat_relocation_skip_flag = true;
    } else if (vm_safe_mode) {
        strcpy(dex2oat_compiler_filter_arg, "--compiler-filter=interpret-only");
        have_dex2oat_compiler_filter_flag = true;
    } else if (compiler_filter != nullptr &&
            strlen(compiler_filter) + strlen("--compiler-filter=") <
                    arraysize(dex2oat_compiler_filter_arg)) {
        sprintf(dex2oat_compiler_filter_arg, "--compiler-filter=%s", compiler_filter);
        have_dex2oat_compiler_filter_flag = true;
    } else {
        char dex2oat_compiler_filter_flag[kPropertyValueMax];
        have_dex2oat_compiler_filter_flag = get_property("dalvik.vm.dex2oat-filter",
                                                         dex2oat_compiler_filter_flag, NULL) > 0;
        if (have_dex2oat_compiler_filter_flag) {
            sprintf(dex2oat_compiler_filter_arg,
                    "--compiler-filter=%s",
                    dex2oat_compiler_filter_flag);
        }
    }

    // Check whether all apps should be compiled debuggable.
    if (!debuggable) {
        char prop_buf[kPropertyValueMax];
        debuggable =
                (get_property("dalvik.vm.always_debuggable", prop_buf, "0") > 0) &&
                (prop_buf[0] == '1');
    }
    char profile_arg[strlen("--profile-file-fd=") + MAX_INT_LEN];
    if (profile_fd != -1) {
        sprintf(profile_arg, "--profile-file-fd=%d", profile_fd);
    }


    ALOGV("Running %s in=%s out=%s\n", DEX2OAT_BIN, input_file_name, output_file_name);

    const char* argv[9  // program name, mandatory arguments and the final NULL
                     + (have_dex2oat_isa_variant ? 1 : 0)
                     + (have_dex2oat_isa_features ? 1 : 0)
                     + (have_dex2oat_Xms_flag ? 2 : 0)
                     + (have_dex2oat_Xmx_flag ? 2 : 0)
                     + (have_dex2oat_compiler_filter_flag ? 1 : 0)
                     + (have_dex2oat_threads_flag ? 1 : 0)
                     + (have_dex2oat_swap_fd ? 1 : 0)
                     + (have_dex2oat_image_fd ? 1 : 0)
                     + (have_dex2oat_relocation_skip_flag ? 2 : 0)
                     + (generate_debug_info ? 1 : 0)
                     + (debuggable ? 1 : 0)
                     + (have_app_image_format ? 1 : 0)
                     + dex2oat_flags_count
                     + (profile_fd == -1 ? 0 : 1)
                     + (shared_libraries != nullptr ? 4 : 0)
                     + (have_dex2oat_large_app_threshold ? 1 : 0)];
    int i = 0;
    argv[i++] = DEX2OAT_BIN;
    argv[i++] = zip_fd_arg;
    argv[i++] = zip_location_arg;
    argv[i++] = input_vdex_fd_arg;
    argv[i++] = output_vdex_fd_arg;
    argv[i++] = oat_fd_arg;
    argv[i++] = oat_location_arg;
    argv[i++] = instruction_set_arg;
    if (have_dex2oat_isa_variant) {
        argv[i++] = instruction_set_variant_arg;
    }
    if (have_dex2oat_isa_features) {
        argv[i++] = instruction_set_features_arg;
    }
    if (have_dex2oat_Xms_flag) {
        argv[i++] = RUNTIME_ARG;
        argv[i++] = dex2oat_Xms_arg;
    }
    if (have_dex2oat_Xmx_flag) {
        argv[i++] = RUNTIME_ARG;
        argv[i++] = dex2oat_Xmx_arg;
    }
    if (have_dex2oat_compiler_filter_flag) {
        argv[i++] = dex2oat_compiler_filter_arg;
    }
    if (have_dex2oat_threads_flag) {
        argv[i++] = dex2oat_threads_arg;
    }
    if (have_dex2oat_swap_fd) {
        argv[i++] = dex2oat_swap_fd;
    }
    if (have_dex2oat_image_fd) {
        argv[i++] = dex2oat_image_fd;
    }
    if (generate_debug_info) {
        argv[i++] = "--generate-debug-info";
    }
    if (debuggable) {
        argv[i++] = "--debuggable";
    }
    if (have_app_image_format) {
        argv[i++] = image_format_arg;
    }
    if (have_dex2oat_large_app_threshold) {
        argv[i++] = dex2oat_large_app_threshold_arg;
    }
    if (dex2oat_flags_count) {
        i += split(dex2oat_flags, argv + i);
    }
    if (have_dex2oat_relocation_skip_flag) {
        argv[i++] = RUNTIME_ARG;
        argv[i++] = dex2oat_norelocation;
    }
    if (profile_fd != -1) {
        argv[i++] = profile_arg;
    }
    if (shared_libraries != nullptr) {
        argv[i++] = RUNTIME_ARG;
        argv[i++] = "-classpath";
        argv[i++] = RUNTIME_ARG;
        argv[i++] = shared_libraries;
    }
    // Do not add after dex2oat_flags, they should override others for debugging.
    argv[i] = NULL;

    execv(DEX2OAT_BIN, (char * const *)argv);
    ALOGE("execv(%s) failed: %s\n", DEX2OAT_BIN, strerror(errno));
}

/*
 * Whether dexopt should use a swap file when compiling an APK.
 *
 * If kAlwaysProvideSwapFile, do this on all devices (dex2oat will make a more informed decision
 * itself, anyways).
 *
 * Otherwise, read "dalvik.vm.dex2oat-swap". If the property exists, return whether it is "true".
 *
 * Otherwise, return true if this is a low-mem device.
 *
 * Otherwise, return default value.
 */
static bool kAlwaysProvideSwapFile = false;
static bool kDefaultProvideSwapFile = true;

static bool ShouldUseSwapFileForDexopt() {
    if (kAlwaysProvideSwapFile) {
        return true;
    }

    // Check the "override" property. If it exists, return value == "true".
    char dex2oat_prop_buf[kPropertyValueMax];
    if (get_property("dalvik.vm.dex2oat-swap", dex2oat_prop_buf, "") > 0) {
        if (strcmp(dex2oat_prop_buf, "true") == 0) {
            return true;
        } else {
            return false;
        }
    }

    // Shortcut for default value. This is an implementation optimization for the process sketched
    // above. If the default value is true, we can avoid to check whether this is a low-mem device,
    // as low-mem is never returning false. The compiler will optimize this away if it can.
    if (kDefaultProvideSwapFile) {
        return true;
    }

    bool is_low_mem = property_get_bool("ro.config.low_ram", false);
    if (is_low_mem) {
        return true;
    }

    // Default value must be false here.
    return kDefaultProvideSwapFile;
}

static void SetDex2OatAndPatchOatScheduling(bool set_to_bg) {
    if (set_to_bg) {
        if (set_sched_policy(0, SP_BACKGROUND) < 0) {
            ALOGE("set_sched_policy failed: %s\n", strerror(errno));
            exit(70);
        }
        if (setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_BACKGROUND) < 0) {
            ALOGE("setpriority failed: %s\n", strerror(errno));
            exit(71);
        }
    }
}

static void close_all_fds(const std::vector<fd_t>& fds, const char* description) {
    for (size_t i = 0; i < fds.size(); i++) {
        if (close(fds[i]) != 0) {
            PLOG(WARNING) << "Failed to close fd for " << description << " at index " << i;
        }
    }
}

static fd_t open_profile_dir(const std::string& profile_dir) {
    fd_t profile_dir_fd = TEMP_FAILURE_RETRY(open(profile_dir.c_str(),
            O_PATH | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
    if (profile_dir_fd < 0) {
        // In a multi-user environment, these directories can be created at
        // different points and it's possible we'll attempt to open a profile
        // dir before it exists.
        if (errno != ENOENT) {
            PLOG(ERROR) << "Failed to open profile_dir: " << profile_dir;
        }
    }
    return profile_dir_fd;
}

static fd_t open_primary_profile_file_from_dir(const std::string& profile_dir, mode_t open_mode) {
    fd_t profile_dir_fd  = open_profile_dir(profile_dir);
    if (profile_dir_fd < 0) {
        return -1;
    }

    fd_t profile_fd = -1;
    std::string profile_file = create_primary_profile(profile_dir);

    profile_fd = TEMP_FAILURE_RETRY(open(profile_file.c_str(), open_mode | O_NOFOLLOW));
    if (profile_fd == -1) {
        // It's not an error if the profile file does not exist.
        if (errno != ENOENT) {
            PLOG(ERROR) << "Failed to lstat profile_dir: " << profile_dir;
        }
    }
    // TODO(calin): use AutoCloseFD instead of closing the fd manually.
    if (close(profile_dir_fd) != 0) {
        PLOG(WARNING) << "Could not close profile dir " << profile_dir;
    }
    return profile_fd;
}

static fd_t open_primary_profile_file(userid_t user, const char* pkgname) {
    std::string profile_dir = create_data_user_profile_package_path(user, pkgname);
    return open_primary_profile_file_from_dir(profile_dir, O_RDONLY);
}

static fd_t open_reference_profile(uid_t uid, const char* pkgname, bool read_write) {
    std::string reference_profile_dir = create_data_ref_profile_package_path(pkgname);
    int flags = read_write ? O_RDWR | O_CREAT : O_RDONLY;
    fd_t fd = open_primary_profile_file_from_dir(reference_profile_dir, flags);
    if (fd < 0) {
        return -1;
    }
    if (read_write) {
        // Fix the owner.
        if (fchown(fd, uid, uid) < 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

static void open_profile_files(uid_t uid, const char* pkgname,
            /*out*/ std::vector<fd_t>* profiles_fd, /*out*/ fd_t* reference_profile_fd) {
    // Open the reference profile in read-write mode as profman might need to save the merge.
    *reference_profile_fd = open_reference_profile(uid, pkgname, /*read_write*/ true);
    if (*reference_profile_fd < 0) {
        // We can't access the reference profile file.
        return;
    }

    std::vector<userid_t> users = get_known_users(/*volume_uuid*/ nullptr);
    for (auto user : users) {
        fd_t profile_fd = open_primary_profile_file(user, pkgname);
        // Add to the lists only if both fds are valid.
        if (profile_fd >= 0) {
            profiles_fd->push_back(profile_fd);
        }
    }
}

static void drop_capabilities(uid_t uid) {
    if (setgid(uid) != 0) {
        ALOGE("setgid(%d) failed in installd during dexopt\n", uid);
        exit(64);
    }
    if (setuid(uid) != 0) {
        ALOGE("setuid(%d) failed in installd during dexopt\n", uid);
        exit(65);
    }
    // drop capabilities
    struct __user_cap_header_struct capheader;
    struct __user_cap_data_struct capdata[2];
    memset(&capheader, 0, sizeof(capheader));
    memset(&capdata, 0, sizeof(capdata));
    capheader.version = _LINUX_CAPABILITY_VERSION_3;
    if (capset(&capheader, &capdata[0]) < 0) {
        ALOGE("capset failed: %s\n", strerror(errno));
        exit(66);
    }
}

static constexpr int PROFMAN_BIN_RETURN_CODE_COMPILE = 0;
static constexpr int PROFMAN_BIN_RETURN_CODE_SKIP_COMPILATION = 1;
static constexpr int PROFMAN_BIN_RETURN_CODE_BAD_PROFILES = 2;
static constexpr int PROFMAN_BIN_RETURN_CODE_ERROR_IO = 3;
static constexpr int PROFMAN_BIN_RETURN_CODE_ERROR_LOCKING = 4;

static void run_profman_merge(const std::vector<fd_t>& profiles_fd, fd_t reference_profile_fd) {
    static const size_t MAX_INT_LEN = 32;
    static const char* PROFMAN_BIN = "/system/bin/profman";

    std::vector<std::string> profile_args(profiles_fd.size());
    char profile_buf[strlen("--profile-file-fd=") + MAX_INT_LEN];
    for (size_t k = 0; k < profiles_fd.size(); k++) {
        sprintf(profile_buf, "--profile-file-fd=%d", profiles_fd[k]);
        profile_args[k].assign(profile_buf);
    }
    char reference_profile_arg[strlen("--reference-profile-file-fd=") + MAX_INT_LEN];
    sprintf(reference_profile_arg, "--reference-profile-file-fd=%d", reference_profile_fd);

    // program name, reference profile fd, the final NULL and the profile fds
    const char* argv[3 + profiles_fd.size()];
    int i = 0;
    argv[i++] = PROFMAN_BIN;
    argv[i++] = reference_profile_arg;
    for (size_t k = 0; k < profile_args.size(); k++) {
        argv[i++] = profile_args[k].c_str();
    }
    // Do not add after dex2oat_flags, they should override others for debugging.
    argv[i] = NULL;

    execv(PROFMAN_BIN, (char * const *)argv);
    ALOGE("execv(%s) failed: %s\n", PROFMAN_BIN, strerror(errno));
    exit(68);   /* only get here on exec failure */
}

// Decides if profile guided compilation is needed or not based on existing profiles.
// Returns true if there is enough information in the current profiles that worth
// a re-compilation of the package.
// If the return value is true all the current profiles would have been merged into
// the reference profiles accessible with open_reference_profile().
bool analyse_profiles(uid_t uid, const char* pkgname) {
    std::vector<fd_t> profiles_fd;
    fd_t reference_profile_fd = -1;
    open_profile_files(uid, pkgname, &profiles_fd, &reference_profile_fd);
    if (profiles_fd.empty() || (reference_profile_fd == -1)) {
        // Skip profile guided compilation because no profiles were found.
        // Or if the reference profile info couldn't be opened.
        close_all_fds(profiles_fd, "profiles_fd");
        if ((reference_profile_fd != - 1) && (close(reference_profile_fd) != 0)) {
            PLOG(WARNING) << "Failed to close fd for reference profile";
        }
        return false;
    }

    ALOGV("PROFMAN (MERGE): --- BEGIN '%s' ---\n", pkgname);

    pid_t pid = fork();
    if (pid == 0) {
        /* child -- drop privileges before continuing */
        drop_capabilities(uid);
        run_profman_merge(profiles_fd, reference_profile_fd);
        exit(68);   /* only get here on exec failure */
    }
    /* parent */
    int return_code = wait_child(pid);
    bool need_to_compile = false;
    bool should_clear_current_profiles = false;
    bool should_clear_reference_profile = false;
    if (!WIFEXITED(return_code)) {
        LOG(WARNING) << "profman failed for package " << pkgname << ": " << return_code;
    } else {
        return_code = WEXITSTATUS(return_code);
        switch (return_code) {
            case PROFMAN_BIN_RETURN_CODE_COMPILE:
                need_to_compile = true;
                should_clear_current_profiles = true;
                should_clear_reference_profile = false;
                break;
            case PROFMAN_BIN_RETURN_CODE_SKIP_COMPILATION:
                need_to_compile = false;
                should_clear_current_profiles = false;
                should_clear_reference_profile = false;
                break;
            case PROFMAN_BIN_RETURN_CODE_BAD_PROFILES:
                LOG(WARNING) << "Bad profiles for package " << pkgname;
                need_to_compile = false;
                should_clear_current_profiles = true;
                should_clear_reference_profile = true;
                break;
            case PROFMAN_BIN_RETURN_CODE_ERROR_IO:  // fall-through
            case PROFMAN_BIN_RETURN_CODE_ERROR_LOCKING:
                // Temporary IO problem (e.g. locking). Ignore but log a warning.
                LOG(WARNING) << "IO error while reading profiles for package " << pkgname;
                need_to_compile = false;
                should_clear_current_profiles = false;
                should_clear_reference_profile = false;
                break;
           default:
                // Unknown return code or error. Unlink profiles.
                LOG(WARNING) << "Unknown error code while processing profiles for package " << pkgname
                        << ": " << return_code;
                need_to_compile = false;
                should_clear_current_profiles = true;
                should_clear_reference_profile = true;
                break;
        }
    }
    close_all_fds(profiles_fd, "profiles_fd");
    if (close(reference_profile_fd) != 0) {
        PLOG(WARNING) << "Failed to close fd for reference profile";
    }
    if (should_clear_current_profiles) {
        clear_current_profiles(pkgname);
    }
    if (should_clear_reference_profile) {
        clear_reference_profile(pkgname);
    }
    return need_to_compile;
}

static void run_profman_dump(const std::vector<fd_t>& profile_fds,
                             fd_t reference_profile_fd,
                             const std::vector<std::string>& dex_locations,
                             const std::vector<fd_t>& apk_fds,
                             fd_t output_fd) {
    std::vector<std::string> profman_args;
    static const char* PROFMAN_BIN = "/system/bin/profman";
    profman_args.push_back(PROFMAN_BIN);
    profman_args.push_back("--dump-only");
    profman_args.push_back(StringPrintf("--dump-output-to-fd=%d", output_fd));
    if (reference_profile_fd != -1) {
        profman_args.push_back(StringPrintf("--reference-profile-file-fd=%d",
                                            reference_profile_fd));
    }
    for (fd_t profile_fd : profile_fds) {
        profman_args.push_back(StringPrintf("--profile-file-fd=%d", profile_fd));
    }
    for (const std::string& dex_location : dex_locations) {
        profman_args.push_back(StringPrintf("--dex-location=%s", dex_location.c_str()));
    }
    for (fd_t apk_fd : apk_fds) {
        profman_args.push_back(StringPrintf("--apk-fd=%d", apk_fd));
    }
    const char **argv = new const char*[profman_args.size() + 1];
    size_t i = 0;
    for (const std::string& profman_arg : profman_args) {
        argv[i++] = profman_arg.c_str();
    }
    argv[i] = NULL;

    execv(PROFMAN_BIN, (char * const *)argv);
    ALOGE("execv(%s) failed: %s\n", PROFMAN_BIN, strerror(errno));
    exit(68);   /* only get here on exec failure */
}

static const char* get_location_from_path(const char* path) {
    static constexpr char kLocationSeparator = '/';
    const char *location = strrchr(path, kLocationSeparator);
    if (location == NULL) {
        return path;
    } else {
        // Skip the separator character.
        return location + 1;
    }
}

bool dump_profiles(int32_t uid, const char* pkgname, const char* code_paths) {
    std::vector<fd_t> profile_fds;
    fd_t reference_profile_fd = -1;
    std::string out_file_name = StringPrintf("/data/misc/profman/%s.txt", pkgname);

    ALOGV("PROFMAN (DUMP): --- BEGIN '%s' ---\n", pkgname);

    open_profile_files(uid, pkgname, &profile_fds, &reference_profile_fd);

    const bool has_reference_profile = (reference_profile_fd != -1);
    const bool has_profiles = !profile_fds.empty();

    if (!has_reference_profile && !has_profiles) {
        ALOGE("profman dump: no profiles to dump for '%s'", pkgname);
        return false;
    }

    fd_t output_fd = open(out_file_name.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW);
    if (fchmod(output_fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) < 0) {
        ALOGE("installd cannot chmod '%s' dump_profile\n", out_file_name.c_str());
        return false;
    }
    std::vector<std::string> code_full_paths = base::Split(code_paths, ";");
    std::vector<std::string> dex_locations;
    std::vector<fd_t> apk_fds;
    for (const std::string& code_full_path : code_full_paths) {
        const char* full_path = code_full_path.c_str();
        fd_t apk_fd = open(full_path, O_RDONLY | O_NOFOLLOW);
        if (apk_fd == -1) {
            ALOGE("installd cannot open '%s'\n", full_path);
            return false;
        }
        dex_locations.push_back(get_location_from_path(full_path));
        apk_fds.push_back(apk_fd);
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* child -- drop privileges before continuing */
        drop_capabilities(uid);
        run_profman_dump(profile_fds, reference_profile_fd, dex_locations,
                         apk_fds, output_fd);
        exit(68);   /* only get here on exec failure */
    }
    /* parent */
    close_all_fds(apk_fds, "apk_fds");
    close_all_fds(profile_fds, "profile_fds");
    if (close(reference_profile_fd) != 0) {
        PLOG(WARNING) << "Failed to close fd for reference profile";
    }
    int return_code = wait_child(pid);
    if (!WIFEXITED(return_code)) {
        LOG(WARNING) << "profman failed for package " << pkgname << ": "
                << return_code;
        return false;
    }
    return true;
}

static std::string replace_file_extension(const std::string& oat_path, const std::string& new_ext) {
  // A standard dalvik-cache entry. Replace ".dex" with `new_ext`.
  if (EndsWith(oat_path, ".dex")) {
    std::string new_path = oat_path;
    new_path.replace(new_path.length() - strlen(".dex"), strlen(".dex"), new_ext);
    CHECK(EndsWith(new_path, new_ext.c_str()));
    return new_path;
  }

  // An odex entry. Not that this may not be an extension, e.g., in the OTA
  // case (where the base name will have an extension for the B artifact).
  size_t odex_pos = oat_path.rfind(".odex");
  if (odex_pos != std::string::npos) {
    std::string new_path = oat_path;
    new_path.replace(odex_pos, strlen(".odex"), new_ext);
    CHECK_NE(new_path.find(new_ext), std::string::npos);
    return new_path;
  }

  // Don't know how to handle this.
  return "";
}

// Translate the given oat path to an art (app image) path. An empty string
// denotes an error.
static std::string create_image_filename(const std::string& oat_path) {
    return replace_file_extension(oat_path, ".art");
}

// Translate the given oat path to a vdex path. An empty string denotes an error.
static std::string create_vdex_filename(const std::string& oat_path) {
    return replace_file_extension(oat_path, ".vdex");
}

static bool add_extension_to_file_name(char* file_name, const char* extension) {
    if (strlen(file_name) + strlen(extension) + 1 > PKG_PATH_MAX) {
        return false;
    }
    strcat(file_name, extension);
    return true;
}

static int open_output_file(const char* file_name, bool recreate, int permissions) {
    int flags = O_RDWR | O_CREAT;
    if (recreate) {
        if (unlink(file_name) < 0) {
            if (errno != ENOENT) {
                PLOG(ERROR) << "open_output_file: Couldn't unlink " << file_name;
            }
        }
        flags |= O_EXCL;
    }
    return open(file_name, flags, permissions);
}

static bool set_permissions_and_ownership(int fd, bool is_public, int uid, const char* path) {
    if (fchmod(fd,
               S_IRUSR|S_IWUSR|S_IRGRP |
               (is_public ? S_IROTH : 0)) < 0) {
        ALOGE("installd cannot chmod '%s' during dexopt\n", path);
        return false;
    } else if (fchown(fd, AID_SYSTEM, uid) < 0) {
        ALOGE("installd cannot chown '%s' during dexopt\n", path);
        return false;
    }
    return true;
}

static bool IsOutputDalvikCache(const char* oat_dir) {
  // InstallerConnection.java (which invokes installd) transforms Java null arguments
  // into '!'. Play it safe by handling it both.
  // TODO: ensure we never get null.
  // TODO: pass a flag instead of inferring if the output is dalvik cache.
  return oat_dir == nullptr || oat_dir[0] == '!';
}

static bool create_oat_out_path(const char* apk_path, const char* instruction_set,
            const char* oat_dir, /*out*/ char* out_oat_path) {
    // Early best-effort check whether we can fit the the path into our buffers.
    // Note: the cache path will require an additional 5 bytes for ".swap", but we'll try to run
    // without a swap file, if necessary. Reference profiles file also add an extra ".prof"
    // extension to the cache path (5 bytes).
    if (strlen(apk_path) >= (PKG_PATH_MAX - 8)) {
        ALOGE("apk_path too long '%s'\n", apk_path);
        return false;
    }

    if (!IsOutputDalvikCache(oat_dir)) {
        if (validate_apk_path(oat_dir)) {
            ALOGE("cannot validate apk path with oat_dir '%s'\n", oat_dir);
            return false;
        }
        if (!calculate_oat_file_path(out_oat_path, oat_dir, apk_path, instruction_set)) {
            return false;
        }
    } else {
        if (!create_cache_path(out_oat_path, apk_path, instruction_set)) {
            return false;
        }
    }
    return true;
}

// Helper for fd management. This is similar to a unique_fd in that it closes the file descriptor
// on destruction. It will also run the given cleanup (unless told not to) after closing.
//
// Usage example:
//
//   Dex2oatFileWrapper<std::function<void ()>> file(open(...),
//                                                   [name]() {
//                                                       unlink(name.c_str());
//                                                   });
//   // Note: care needs to be taken about name, as it needs to have a lifetime longer than the
//            wrapper if captured as a reference.
//
//   if (file.get() == -1) {
//       // Error opening...
//   }
//
//   ...
//   if (error) {
//       // At this point, when the Dex2oatFileWrapper is destructed, the cleanup function will run
//       // and delete the file (after the fd is closed).
//       return -1;
//   }
//
//   (Success case)
//   file.SetCleanup(false);
//   // At this point, when the Dex2oatFileWrapper is destructed, the cleanup function will not run
//   // (leaving the file around; after the fd is closed).
//
template <typename Cleanup>
class Dex2oatFileWrapper {
 public:
    Dex2oatFileWrapper() : value_(-1), cleanup_(), do_cleanup_(true) {
    }

    Dex2oatFileWrapper(int value, Cleanup cleanup)
            : value_(value), cleanup_(cleanup), do_cleanup_(true) {}

    ~Dex2oatFileWrapper() {
        reset(-1);
    }

    int get() {
        return value_;
    }

    void SetCleanup(bool cleanup) {
        do_cleanup_ = cleanup;
    }

    void reset(int new_value) {
        if (value_ >= 0) {
            close(value_);
        }
        if (do_cleanup_ && cleanup_ != nullptr) {
            cleanup_();
        }

        value_ = new_value;
    }

    void reset(int new_value, Cleanup new_cleanup) {
        if (value_ >= 0) {
            close(value_);
        }
        if (do_cleanup_ && cleanup_ != nullptr) {
            cleanup_();
        }

        value_ = new_value;
        cleanup_ = new_cleanup;
    }

 private:
    int value_;
    Cleanup cleanup_;
    bool do_cleanup_;
};

int dexopt(const char* apk_path, uid_t uid, const char* pkgname, const char* instruction_set,
        int dexopt_needed, const char* oat_dir, int dexopt_flags,const char* compiler_filter,
        const char* volume_uuid ATTRIBUTE_UNUSED, const char* shared_libraries) {
    bool is_public = ((dexopt_flags & DEXOPT_PUBLIC) != 0);
    bool vm_safe_mode = (dexopt_flags & DEXOPT_SAFEMODE) != 0;
    bool debuggable = (dexopt_flags & DEXOPT_DEBUGGABLE) != 0;
    bool boot_complete = (dexopt_flags & DEXOPT_BOOTCOMPLETE) != 0;
    bool profile_guided = (dexopt_flags & DEXOPT_PROFILE_GUIDED) != 0;

    CHECK(pkgname != nullptr);
    CHECK(pkgname[0] != 0);

    // Public apps should not be compiled with profile information ever. Same goes for the special
    // package '*' used for the system server.
    Dex2oatFileWrapper<std::function<void ()>> reference_profile_fd;
    if (!is_public && pkgname[0] != '*') {
        // Open reference profile in read only mode as dex2oat does not get write permissions.
        const std::string pkgname_str(pkgname);
        reference_profile_fd.reset(open_reference_profile(uid, pkgname, /*read_write*/ false),
                                   [pkgname_str]() {
                                       clear_reference_profile(pkgname_str.c_str());
                                   });
        // Note: it's OK to not find a profile here.
    }

    if ((dexopt_flags & ~DEXOPT_MASK) != 0) {
        LOG_FATAL("dexopt flags contains unknown fields\n");
    }

    char out_oat_path[PKG_PATH_MAX];
    if (!create_oat_out_path(apk_path, instruction_set, oat_dir, out_oat_path)) {
        return false;
    }

    const char *input_file;
    char in_odex_path[PKG_PATH_MAX];
    int dexopt_action = abs(dexopt_needed);
    bool is_odex_location = dexopt_needed < 0;
    switch (dexopt_action) {
        case DEX2OAT_FROM_SCRATCH:
        case DEX2OAT_FOR_BOOT_IMAGE:
        case DEX2OAT_FOR_FILTER:
        case DEX2OAT_FOR_RELOCATION:
            input_file = apk_path;
            break;

        case PATCHOAT_FOR_RELOCATION:
            if (is_odex_location) {
                if (!calculate_odex_file_path(in_odex_path, apk_path, instruction_set)) {
                    return -1;
                }
                input_file = in_odex_path;
            } else {
                input_file = out_oat_path;
            }
            break;

        default:
            ALOGE("Invalid dexopt needed: %d\n", dexopt_needed);
            return 72;
    }

    struct stat input_stat;
    memset(&input_stat, 0, sizeof(input_stat));
    stat(input_file, &input_stat);

    // Open the input file. If running dex2oat, `input_file` is the APK. If running
    // patchoat, it is the OAT file to be relocated.
    base::unique_fd input_fd(open(input_file, O_RDONLY, 0));
    if (input_fd.get() < 0) {
        ALOGE("installd cannot open '%s' for input during dexopt\n", input_file);
        return -1;
    }

    // Create the output OAT file.
    const std::string out_oat_path_str(out_oat_path);
    Dex2oatFileWrapper<std::function<void ()>> out_oat_fd(
            open_output_file(out_oat_path, /*recreate*/true, /*permissions*/0644),
            [out_oat_path_str]() { unlink(out_oat_path_str.c_str()); });
    if (out_oat_fd.get() < 0) {
        ALOGE("installd cannot open '%s' for output during dexopt\n", out_oat_path);
        return -1;
    }
    if (!set_permissions_and_ownership(out_oat_fd.get(), is_public, uid, out_oat_path)) {
        return -1;
    }

    // Open the existing VDEX. We do this before creating the new output VDEX, which will
    // unlink the old one.
    base::unique_fd in_vdex_fd;
    std::string in_vdex_path_str;
    if (dexopt_action == PATCHOAT_FOR_RELOCATION) {
        // `input_file` is the OAT file to be relocated. The VDEX has to be there as well.
        in_vdex_path_str = create_vdex_filename(input_file);
        if (in_vdex_path_str.empty()) {
            ALOGE("installd cannot compute input vdex location for '%s'\n", input_file);
            return -1;
        }
        in_vdex_fd.reset(open(in_vdex_path_str.c_str(), O_RDONLY, 0));
        if (in_vdex_fd.get() < 0) {
            ALOGE("installd cannot open '%s' for input during dexopt: %s\n",
                in_vdex_path_str.c_str(), strerror(errno));
            return -1;
        }
    } else if (dexopt_action != DEX2OAT_FROM_SCRATCH) {
        // Open the possibly existing vdex. If none exist, we pass -1 to dex2oat for input-vdex-fd.
        const char* path = nullptr;
        if (is_odex_location) {
            if (calculate_odex_file_path(in_odex_path, apk_path, instruction_set)) {
                path = in_odex_path;
            } else {
                ALOGE("installd cannot compute input vdex location for '%s'\n", apk_path);
                return -1;
            }
        } else {
            path = out_oat_path;
        }
        in_vdex_path_str = create_vdex_filename(path);
        if (in_vdex_path_str.empty()) {
            ALOGE("installd cannot compute input vdex location for '%s'\n", path);
            return -1;
        }
        in_vdex_fd.reset(open(in_vdex_path_str.c_str(), O_RDONLY, 0));
    }

    // Infer the name of the output VDEX and create it.
    const std::string out_vdex_path_str = create_vdex_filename(out_oat_path_str);
    if (out_vdex_path_str.empty()) {
        return -1;
    }
    Dex2oatFileWrapper<std::function<void ()>> out_vdex_fd(
            open_output_file(out_vdex_path_str.c_str(), /*recreate*/true, /*permissions*/0644),
            [out_vdex_path_str]() { unlink(out_vdex_path_str.c_str()); });
    if (out_vdex_fd.get() < 0) {
        ALOGE("installd cannot open '%s' for output during dexopt\n", out_vdex_path_str.c_str());
        return -1;
    }
    if (!set_permissions_and_ownership(out_vdex_fd.get(), is_public,
                uid, out_vdex_path_str.c_str())) {
        return -1;
    }

    // Create a swap file if necessary.
    base::unique_fd swap_fd;
    if (ShouldUseSwapFileForDexopt()) {
        // Make sure there really is enough space.
        char swap_file_name[PKG_PATH_MAX];
        strcpy(swap_file_name, out_oat_path);
        if (add_extension_to_file_name(swap_file_name, ".swap")) {
            swap_fd.reset(open_output_file(swap_file_name, /*recreate*/true, /*permissions*/0600));
        }
        if (swap_fd.get() < 0) {
            // Could not create swap file. Optimistically go on and hope that we can compile
            // without it.
            ALOGE("installd could not create '%s' for swap during dexopt\n", swap_file_name);
        } else {
            // Immediately unlink. We don't really want to hit flash.
            if (unlink(swap_file_name) < 0) {
                PLOG(ERROR) << "Couldn't unlink swap file " << swap_file_name;
            }
        }
    }

    // Avoid generating an app image for extract only since it will not contain any classes.
    Dex2oatFileWrapper<std::function<void ()>> image_fd;
    const std::string image_path = create_image_filename(out_oat_path);
    if (dexopt_action != PATCHOAT_FOR_RELOCATION && !image_path.empty()) {
        char app_image_format[kPropertyValueMax];
        bool have_app_image_format =
                get_property("dalvik.vm.appimageformat", app_image_format, NULL) > 0;
        // Use app images only if it is enabled (by a set image format) and we are compiling
        // profile-guided (so the app image doesn't conservatively contain all classes).
        if (profile_guided && have_app_image_format) {
            // Recreate is true since we do not want to modify a mapped image. If the app is
            // already running and we modify the image file, it can cause crashes (b/27493510).
            image_fd.reset(open_output_file(image_path.c_str(),
                                            true /*recreate*/,
                                            0600 /*permissions*/),
                           [image_path]() { unlink(image_path.c_str()); }
                           );
            if (image_fd.get() < 0) {
                // Could not create application image file. Go on since we can compile without
                // it.
                LOG(ERROR) << "installd could not create '"
                        << image_path
                        << "' for image file during dexopt";
            } else if (!set_permissions_and_ownership(image_fd.get(),
                                                      is_public,
                                                      uid,
                                                      image_path.c_str())) {
                image_fd.reset(-1);
            }
        }
        // If we have a valid image file path but no image fd, explicitly erase the image file.
        if (image_fd.get() < 0) {
            if (unlink(image_path.c_str()) < 0) {
                if (errno != ENOENT) {
                    PLOG(ERROR) << "Couldn't unlink image file " << image_path;
                }
            }
        }
    }

    ALOGV("DexInv: --- BEGIN '%s' ---\n", input_file);

    pid_t pid = fork();
    if (pid == 0) {
        /* child -- drop privileges before continuing */
        drop_capabilities(uid);

        SetDex2OatAndPatchOatScheduling(boot_complete);
        if (flock(out_oat_fd.get(), LOCK_EX | LOCK_NB) != 0) {
            ALOGE("flock(%s) failed: %s\n", out_oat_path, strerror(errno));
            _exit(67);
        }

        if (dexopt_action == PATCHOAT_FOR_RELOCATION) {
            run_patchoat(input_fd.get(),
                         in_vdex_fd.get(),
                         out_oat_fd.get(),
                         out_vdex_fd.get(),
                         input_file,
                         in_vdex_path_str.c_str(),
                         out_oat_path,
                         out_vdex_path_str.c_str(),
                         pkgname,
                         instruction_set);
        } else {
            // Pass dex2oat the relative path to the input file.
            const char *input_file_name = get_location_from_path(input_file);
            run_dex2oat(input_fd.get(),
                        out_oat_fd.get(),
                        in_vdex_fd.get(),
                        out_vdex_fd.get(),
                        image_fd.get(),
                        input_file_name,
                        out_oat_path,
                        swap_fd.get(),
                        instruction_set,
                        compiler_filter,
                        vm_safe_mode,
                        debuggable,
                        boot_complete,
                        reference_profile_fd.get(),
                        shared_libraries);
        }
        _exit(68);   /* only get here on exec failure */
    } else {
        int res = wait_child(pid);
        if (res == 0) {
            ALOGV("DexInv: --- END '%s' (success) ---\n", input_file);
        } else {
            ALOGE("DexInv: --- END '%s' --- status=0x%04x, process failed\n", input_file, res);
            return -1;
        }
    }

    struct utimbuf ut;
    ut.actime = input_stat.st_atime;
    ut.modtime = input_stat.st_mtime;
    utime(out_oat_path, &ut);

    // We've been successful, don't delete output.
    out_oat_fd.SetCleanup(false);
    out_vdex_fd.SetCleanup(false);
    image_fd.SetCleanup(false);
    reference_profile_fd.SetCleanup(false);

    return 0;
}

// Helper for move_ab, so that we can have common failure-case cleanup.
static bool unlink_and_rename(const char* from, const char* to) {
    // Check whether "from" exists, and if so whether it's regular. If it is, unlink. Otherwise,
    // return a failure.
    struct stat s;
    if (stat(to, &s) == 0) {
        if (!S_ISREG(s.st_mode)) {
            LOG(ERROR) << from << " is not a regular file to replace for A/B.";
            return false;
        }
        if (unlink(to) != 0) {
            LOG(ERROR) << "Could not unlink " << to << " to move A/B.";
            return false;
        }
    } else {
        // This may be a permission problem. We could investigate the error code, but we'll just
        // let the rename failure do the work for us.
    }

    // Try to rename "to" to "from."
    if (rename(from, to) != 0) {
        PLOG(ERROR) << "Could not rename " << from << " to " << to;
        return false;
    }
    return true;
}

// Move/rename a B artifact (from) to an A artifact (to).
static bool move_ab_path(const std::string& b_path, const std::string& a_path) {
    // Check whether B exists.
    {
        struct stat s;
        if (stat(b_path.c_str(), &s) != 0) {
            // Silently ignore for now. The service calling this isn't smart enough to understand
            // lack of artifacts at the moment.
            return false;
        }
        if (!S_ISREG(s.st_mode)) {
            LOG(ERROR) << "A/B artifact " << b_path << " is not a regular file.";
            // Try to unlink, but swallow errors.
            unlink(b_path.c_str());
            return false;
        }
    }

    // Rename B to A.
    if (!unlink_and_rename(b_path.c_str(), a_path.c_str())) {
        // Delete the b_path so we don't try again (or fail earlier).
        if (unlink(b_path.c_str()) != 0) {
            PLOG(ERROR) << "Could not unlink " << b_path;
        }

        return false;
    }

    return true;
}

bool move_ab(const char* apk_path, const char* instruction_set, const char* oat_dir) {
    // Get the current slot suffix. No suffix, no A/B.
    std::string slot_suffix;
    {
        char buf[kPropertyValueMax];
        if (get_property("ro.boot.slot_suffix", buf, nullptr) <= 0) {
            return false;
        }
        slot_suffix = buf;

        if (!ValidateTargetSlotSuffix(slot_suffix)) {
            LOG(ERROR) << "Target slot suffix not legal: " << slot_suffix;
            return false;
        }
    }

    // Validate other inputs.
    if (validate_apk_path(apk_path) != 0) {
        LOG(ERROR) << "Invalid apk_path: " << apk_path;
        return false;
    }
    if (validate_apk_path(oat_dir) != 0) {
        LOG(ERROR) << "Invalid oat_dir: " << oat_dir;
        return false;
    }

    char a_path[PKG_PATH_MAX];
    if (!calculate_oat_file_path(a_path, oat_dir, apk_path, instruction_set)) {
        return false;
    }
    const std::string a_vdex_path = create_vdex_filename(a_path);
    const std::string a_image_path = create_image_filename(a_path);

    // B path = A path + slot suffix.
    const std::string b_path = StringPrintf("%s.%s", a_path, slot_suffix.c_str());
    const std::string b_vdex_path = StringPrintf("%s.%s", a_vdex_path.c_str(), slot_suffix.c_str());
    const std::string b_image_path = StringPrintf("%s.%s",
                                                  a_image_path.c_str(),
                                                  slot_suffix.c_str());

    bool success = true;
    if (move_ab_path(b_path, a_path)) {
        if (move_ab_path(b_vdex_path, a_vdex_path)) {
            // Note: we can live without an app image. As such, ignore failure to move the image file.
            //       If we decide to require the app image, or the app image being moved correctly,
            //       then change accordingly.
            constexpr bool kIgnoreAppImageFailure = true;

            if (!a_image_path.empty()) {
                if (!move_ab_path(b_image_path, a_image_path)) {
                    unlink(a_image_path.c_str());
                    if (!kIgnoreAppImageFailure) {
                        success = false;
                    }
                }
            }
        } else {
            // Cleanup: delete B image, ignore errors.
            unlink(b_image_path.c_str());
            success = false;
        }
    } else {
        // Cleanup: delete B image, ignore errors.
        unlink(b_vdex_path.c_str());
        unlink(b_image_path.c_str());
        success = false;
    }
    return success;
}

bool delete_odex(const char* apk_path, const char* instruction_set, const char* oat_dir) {
    // Delete the oat/odex file.
    char out_path[PKG_PATH_MAX];
    if (!create_oat_out_path(apk_path, instruction_set, oat_dir, out_path)) {
        return false;
    }

    // In case of a permission failure report the issue. Otherwise just print a warning.
    auto unlink_and_check = [](const char* path) -> bool {
        int result = unlink(path);
        if (result != 0) {
            if (errno == EACCES || errno == EPERM) {
                PLOG(ERROR) << "Could not unlink " << path;
                return false;
            }
            PLOG(WARNING) << "Could not unlink " << path;
        }
        return true;
    };

    // Delete the oat/odex file.
    bool return_value_oat = unlink_and_check(out_path);

    // Derive and delete the app image.
    bool return_value_art = unlink_and_check(create_image_filename(out_path).c_str());

    // Report success.
    return return_value_oat && return_value_art;
}

int dexopt(const char* const params[DEXOPT_PARAM_COUNT]) {
    return dexopt(params[0],                    // apk_path
                  atoi(params[1]),              // uid
                  params[2],                    // pkgname
                  params[3],                    // instruction_set
                  atoi(params[4]),              // dexopt_needed
                  params[5],                    // oat_dir
                  atoi(params[6]),              // dexopt_flags
                  params[7],                    // compiler_filter
                  parse_null(params[8]),        // volume_uuid
                  parse_null(params[9]));       // shared_libraries
    static_assert(DEXOPT_PARAM_COUNT == 10U, "Unexpected dexopt param count");
}

}  // namespace installd
}  // namespace android
