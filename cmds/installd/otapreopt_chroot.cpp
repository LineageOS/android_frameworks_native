/*
 ** Copyright 2016, The Android Open Source Project
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

#include <fcntl.h>
#include <linux/unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <libdm/dm.h>
#include <selinux/android.h>

#include "installd_constants.h"
#include "otapreopt_utils.h"

#ifndef LOG_TAG
#define LOG_TAG "otapreopt_chroot"
#endif

using android::base::StringPrintf;

namespace android {
namespace installd {

// We don't know the filesystem types of the partitions in the update package,
// so just try the possibilities one by one.
static constexpr std::array kTryMountFsTypes = {"ext4", "erofs"};

static void CloseDescriptor(const char* descriptor_string) {
    int fd = -1;
    std::istringstream stream(descriptor_string);
    stream >> fd;
    if (!stream.fail()) {
        if (fd >= 0) {
            if (close(fd) < 0) {
                PLOG(ERROR) << "Failed to close " << fd;
            }
        }
    }
}

static void SetCloseOnExec(int fd) {
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        PLOG(ERROR) << "Failed to set FD_CLOEXEC on " << fd;
    }
}

static void ActivateApexPackages() {
    std::vector<std::string> apexd_cmd{"/system/bin/apexd", "--otachroot-bootstrap"};
    std::string apexd_error_msg;

    bool exec_result = Exec(apexd_cmd, &apexd_error_msg);
    if (!exec_result) {
        PLOG(ERROR) << "Running otapreopt failed: " << apexd_error_msg;
        exit(220);
    }
}

static void DeactivateApexPackages() {
    std::vector<std::string> apexd_cmd{"/system/bin/apexd", "--unmount-all"};
    std::string apexd_error_msg;
    bool exec_result = Exec(apexd_cmd, &apexd_error_msg);
    if (!exec_result) {
        PLOG(ERROR) << "Running /system/bin/apexd --unmount-all failed: " << apexd_error_msg;
    }
}

static bool TryMountWithFstypes(const char* block_device, const char* target) {
    for (int i = 0; i < kTryMountFsTypes.size(); ++i) {
        const char* fstype = kTryMountFsTypes[i];
        int mount_result = mount(block_device, target, fstype, MS_RDONLY, /* data */ nullptr);
        if (mount_result == 0) {
            return true;
        }
        if (errno == EINVAL && i < kTryMountFsTypes.size() - 1) {
            // Only try the next fstype if mounting failed due to the current one
            // being invalid.
            LOG(WARNING) << "Failed to mount " << block_device << " on " << target << " with "
                         << fstype << " - trying " << kTryMountFsTypes[i + 1];
        } else {
            PLOG(ERROR) << "Failed to mount " << block_device << " on " << target << " with "
                        << fstype;
            return false;
        }
    }
    __builtin_unreachable();
}

static void TryExtraMount(const char* name, const char* slot, const char* target) {
    std::string partition_name = StringPrintf("%s%s", name, slot);

    // See whether update_engine mounted a logical partition.
    {
        auto& dm = dm::DeviceMapper::Instance();
        if (dm.GetState(partition_name) != dm::DmDeviceState::INVALID) {
            std::string path;
            if (dm.GetDmDevicePathByName(partition_name, &path)) {
                if (TryMountWithFstypes(path.c_str(), target)) {
                    return;
                }
            }
        }
    }

    // Fall back and attempt a direct mount.
    std::string block_device = StringPrintf("/dev/block/by-name/%s", partition_name.c_str());
    (void)TryMountWithFstypes(block_device.c_str(), target);
}

// Entry for otapreopt_chroot. Expected parameters are:
//
//   [cmd] [status-fd] [target-slot-suffix]
//
// The file descriptor denoted by status-fd will be closed. Dexopt commands on
// the form
//
//   "dexopt" [dexopt-params]
//
// are then read from stdin until EOF and passed on to /system/bin/otapreopt one
// by one. After each call a line with the current command count is written to
// stdout and flushed.
static int otapreopt_chroot(const int argc, char **arg) {
    // Validate arguments
    if (argc == 2 && std::string_view(arg[1]) == "--version") {
        // Accept a single --version flag, to allow the script to tell this binary
        // from the earlier one.
        std::cout << "2" << std::endl;
        return 0;
    }
    if (argc != 3) {
        LOG(ERROR) << "Wrong number of arguments: " << argc;
        exit(208);
    }
    const char* status_fd = arg[1];
    const char* slot_suffix = arg[2];

    // Set O_CLOEXEC on standard fds. They are coming from the caller, we do not
    // want to pass them on across our fork/exec into a different domain.
    SetCloseOnExec(STDIN_FILENO);
    SetCloseOnExec(STDOUT_FILENO);
    SetCloseOnExec(STDERR_FILENO);
    // Close the status channel.
    CloseDescriptor(status_fd);

    // We need to run the otapreopt tool from the postinstall partition. As such, set up a
    // mount namespace and change root.

    // Create our own mount namespace.
    if (unshare(CLONE_NEWNS) != 0) {
        PLOG(ERROR) << "Failed to unshare() for otapreopt.";
        exit(200);
    }

    // Make postinstall private, so that our changes don't propagate.
    if (mount("", "/postinstall", nullptr, MS_PRIVATE, nullptr) != 0) {
        PLOG(ERROR) << "Failed to mount private.";
        exit(201);
    }

    // Bind mount necessary directories.
    constexpr const char* kBindMounts[] = {
            "/data", "/dev", "/proc", "/sys",
            "/sys/fs/selinux" /* Required for apexd which includes libselinux */
    };
    for (size_t i = 0; i < arraysize(kBindMounts); ++i) {
        std::string trg = StringPrintf("/postinstall%s", kBindMounts[i]);
        if (mount(kBindMounts[i], trg.c_str(), nullptr, MS_BIND, nullptr) != 0) {
            PLOG(ERROR) << "Failed to bind-mount " << kBindMounts[i];
            exit(202);
        }
    }

    // Try to mount the vendor partition. update_engine doesn't do this for us, but we
    // want it for vendor APKs.
    // Notes:
    //  1) We pretty much guess a name here and hope to find the partition by name.
    //     It is just as complicated and brittle to scan /proc/mounts. But this requires
    //     validating the target-slot so as not to try to mount some totally random path.
    //  2) We're in a mount namespace here, so when we die, this will be cleaned up.
    //  3) Ignore errors. Printing anything at this stage will open a file descriptor
    //     for logging.
    if (!ValidateTargetSlotSuffix(slot_suffix)) {
        LOG(ERROR) << "Target slot suffix not legal: " << slot_suffix;
        exit(207);
    }
    TryExtraMount("vendor", slot_suffix, "/postinstall/vendor");

    // Try to mount the product partition. update_engine doesn't do this for us, but we
    // want it for product APKs. Same notes as vendor above.
    TryExtraMount("product", slot_suffix, "/postinstall/product");

    // Try to mount the system_ext partition. update_engine doesn't do this for
    // us, but we want it for system_ext APKs. Same notes as vendor and product
    // above.
    TryExtraMount("system_ext", slot_suffix, "/postinstall/system_ext");

    constexpr const char* kPostInstallLinkerconfig = "/postinstall/linkerconfig";
    // Try to mount /postinstall/linkerconfig. we will set it up after performing the chroot
    if (mount("tmpfs", kPostInstallLinkerconfig, "tmpfs", 0, nullptr) != 0) {
        PLOG(ERROR) << "Failed to mount a tmpfs for " << kPostInstallLinkerconfig;
        exit(215);
    }

    // Setup APEX mount point and its security context.
    static constexpr const char* kPostinstallApexDir = "/postinstall/apex";
    // The following logic is similar to the one in system/core/rootdir/init.rc:
    //
    //   mount tmpfs tmpfs /apex nodev noexec nosuid
    //   chmod 0755 /apex
    //   chown root root /apex
    //   restorecon /apex
    //
    // except we perform the `restorecon` step just after mounting the tmpfs
    // filesystem in /postinstall/apex, so that this directory is correctly
    // labeled (with type `postinstall_apex_mnt_dir`) and may be manipulated in
    // following operations (`chmod`, `chown`, etc.) following policies
    // restricted to `postinstall_apex_mnt_dir`:
    //
    //   mount tmpfs tmpfs /postinstall/apex nodev noexec nosuid
    //   restorecon /postinstall/apex
    //   chmod 0755 /postinstall/apex
    //   chown root root /postinstall/apex
    //
    if (mount("tmpfs", kPostinstallApexDir, "tmpfs", MS_NODEV | MS_NOEXEC | MS_NOSUID, nullptr)
        != 0) {
        PLOG(ERROR) << "Failed to mount tmpfs in " << kPostinstallApexDir;
        exit(209);
    }
    if (selinux_android_restorecon(kPostinstallApexDir, 0) < 0) {
        PLOG(ERROR) << "Failed to restorecon " << kPostinstallApexDir;
        exit(214);
    }
    if (chmod(kPostinstallApexDir, 0755) != 0) {
        PLOG(ERROR) << "Failed to chmod " << kPostinstallApexDir << " to 0755";
        exit(210);
    }
    if (chown(kPostinstallApexDir, 0, 0) != 0) {
        PLOG(ERROR) << "Failed to chown " << kPostinstallApexDir << " to root:root";
        exit(211);
    }

    // Chdir into /postinstall.
    if (chdir("/postinstall") != 0) {
        PLOG(ERROR) << "Unable to chdir into /postinstall.";
        exit(203);
    }

    // Make /postinstall the root in our mount namespace.
    if (chroot(".")  != 0) {
        PLOG(ERROR) << "Failed to chroot";
        exit(204);
    }

    if (chdir("/") != 0) {
        PLOG(ERROR) << "Unable to chdir into /.";
        exit(205);
    }

    // Call apexd --unmount-all to free up loop and dm block devices, so that we can re-use
    // them during the next invocation. Since otapreopt_chroot calls exit in case something goes
    // wrong we need to register our own atexit handler.
    // We want to register this handler before actually activating apex packages. This is mostly
    // due to the fact that if fail to unmount apexes, then on the next run of otapreopt_chroot
    // we will ask for new loop devices instead of re-using existing ones, and we really don't want
    // to do that. :)
    if (atexit(DeactivateApexPackages) != 0) {
        LOG(ERROR) << "Failed to register atexit hander";
        exit(206);
    }

    // Try to mount APEX packages in "/apex" in the chroot dir. We need at least
    // the ART APEX, as it is required by otapreopt to run dex2oat.
    ActivateApexPackages();

    auto cleanup = android::base::make_scope_guard([](){
        std::vector<std::string> apexd_cmd{"/system/bin/apexd", "--unmount-all"};
        std::string apexd_error_msg;
        bool exec_result = Exec(apexd_cmd, &apexd_error_msg);
        if (!exec_result) {
            PLOG(ERROR) << "Running /system/bin/apexd --unmount-all failed: " << apexd_error_msg;
        }
    });
    // Check that an ART APEX has been activated; clean up and exit
    // early otherwise.
    static constexpr const std::string_view kRequiredApexs[] = {
      "com.android.art",
      "com.android.runtime",
      "com.android.sdkext",  // For derive_classpath
    };
    std::array<bool, arraysize(kRequiredApexs)> found_apexs{ false, false };
    DIR* apex_dir = opendir("/apex");
    if (apex_dir == nullptr) {
        PLOG(ERROR) << "unable to open /apex";
        exit(220);
    }
    for (dirent* entry = readdir(apex_dir); entry != nullptr; entry = readdir(apex_dir)) {
        for (int i = 0; i < found_apexs.size(); i++) {
            if (kRequiredApexs[i] == std::string_view(entry->d_name)) {
                found_apexs[i] = true;
                break;
            }
        }
    }
    closedir(apex_dir);
    auto it = std::find(found_apexs.cbegin(), found_apexs.cend(), false);
    if (it != found_apexs.cend()) {
        LOG(ERROR) << "No activated " << kRequiredApexs[std::distance(found_apexs.cbegin(), it)]
                   << " package!";
        exit(221);
    }

    // Setup /linkerconfig. Doing it after the chroot means it doesn't need its own category
    if (selinux_android_restorecon("/linkerconfig", 0) < 0) {
        PLOG(ERROR) << "Failed to restorecon /linkerconfig";
        exit(219);
    }
    std::vector<std::string> linkerconfig_cmd{"/apex/com.android.runtime/bin/linkerconfig",
                                              "--target", "/linkerconfig"};
    std::string linkerconfig_error_msg;
    bool linkerconfig_exec_result = Exec(linkerconfig_cmd, &linkerconfig_error_msg);
    if (!linkerconfig_exec_result) {
        LOG(ERROR) << "Running linkerconfig failed: " << linkerconfig_error_msg;
        exit(218);
    }

    // Now go on and read dexopt lines from stdin and pass them on to otapreopt.

    int count = 1;
    for (std::array<char, 10000> linebuf;
         std::cin.clear(), std::cin.getline(&linebuf[0], linebuf.size()); ++count) {
        // Subtract one from gcount() since getline() counts the newline.
        std::string line(&linebuf[0], std::cin.gcount() - 1);

        if (std::cin.fail()) {
            LOG(ERROR) << "Command exceeds max length " << linebuf.size() << " - skipped: " << line;
            continue;
        }

        std::vector<std::string> tokenized_line = android::base::Tokenize(line, " ");
        std::vector<std::string> cmd{"/system/bin/otapreopt", slot_suffix};
        std::move(tokenized_line.begin(), tokenized_line.end(), std::back_inserter(cmd));

        LOG(INFO) << "Command " << count << ": " << android::base::Join(cmd, " ");

        // Fork and execute otapreopt in its own process.
        std::string error_msg;
        bool exec_result = Exec(cmd, &error_msg);
        if (!exec_result) {
            LOG(ERROR) << "Running otapreopt failed: " << error_msg;
        }

        // Print the count to stdout and flush to indicate progress.
        std::cout << count << std::endl;
    }

    LOG(INFO) << "No more dexopt commands";
    return 0;
}

}  // namespace installd
}  // namespace android

int main(const int argc, char *argv[]) {
    return android::installd::otapreopt_chroot(argc, argv);
}
