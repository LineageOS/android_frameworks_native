/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <memory>
#include <regex>
#include <set>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/properties.h>
#include <hardware_legacy/power.h>

#include "private/android_filesystem_config.h"

#define LOG_TAG "dumpstate"
#include <cutils/log.h>

#include "dumpstate.h"
#include "ziparchive/zip_writer.h"

#include <openssl/sha.h>

using android::base::StringPrintf;

/* read before root is shed */
static char cmdline_buf[16384] = "(unknown)";
static const char *dump_traces_path = NULL;

// Command-line arguments as string
static std::string args;

// TODO: variables below should be part of dumpstate object
static std::string buildType;
static time_t now;
static std::unique_ptr<ZipWriter> zip_writer;
static std::set<std::string> mount_points;
void add_mountinfo();
/* suffix of the bugreport files - it's typically the date (when invoked with -d),
 * although it could be changed by the user using a system property */
static std::string suffix;
static std::string extraOptions;

#define PSTORE_LAST_KMSG "/sys/fs/pstore/console-ramoops"
#define ALT_PSTORE_LAST_KMSG "/sys/fs/pstore/console-ramoops-0"

#define RAFT_DIR "/data/misc/raft"
#define RECOVERY_DIR "/cache/recovery"
#define RECOVERY_DATA_DIR "/data/misc/recovery"
#define LOGPERSIST_DATA_DIR "/data/misc/logd"
#define PROFILE_DATA_DIR_CUR "/data/misc/profiles/cur"
#define PROFILE_DATA_DIR_REF "/data/misc/profiles/ref"
#define TOMBSTONE_DIR "/data/tombstones"
#define TOMBSTONE_FILE_PREFIX TOMBSTONE_DIR "/tombstone_"
/* Can accomodate a tombstone number up to 9999. */
#define TOMBSTONE_MAX_LEN (sizeof(TOMBSTONE_FILE_PREFIX) + 4)
#define NUM_TOMBSTONES  10
#define WLUTIL "/vendor/xbin/wlutil"
#define WAKE_LOCK_NAME "dumpstate_wakelock"

typedef struct {
  char name[TOMBSTONE_MAX_LEN];
  int fd;
} tombstone_data_t;

static tombstone_data_t tombstone_data[NUM_TOMBSTONES];

// TODO: temporary variables and functions used during C++ refactoring
static Dumpstate& ds = Dumpstate::GetInstance();
static int RunCommand(const std::string& title, const std::vector<std::string>& fullCommand,
                      const CommandOptions& options = CommandOptions::DEFAULT) {
    return ds.RunCommand(title, fullCommand, options);
}
static void RunDumpsys(const std::string& title, const std::vector<std::string>& dumpsysArgs,
                       const CommandOptions& options = CommandOptions::DEFAULT_DUMPSYS,
                       long dumpsysTimeout = 0) {
    return ds.RunDumpsys(title, dumpsysArgs, options, dumpsysTimeout);
}
static int DumpFile(const std::string& title, const std::string& path) {
    return ds.DumpFile(title, path);
}

/*
 * List of supported zip format versions.
 *
 * See bugreport-format.md for more info.
 */
static std::string VERSION_DEFAULT = "1.0";

// Relative directory (inside the zip) for all files copied as-is into the bugreport.
static const std::string ZIP_ROOT_DIR = "FS";

static constexpr char PROPERTY_EXTRA_OPTIONS[] = "dumpstate.options";
static constexpr char PROPERTY_LAST_ID[] = "dumpstate.last_id";

bool is_user_build() {
    return "user" == buildType;
}

bool Dumpstate::IsDryRun() {
    return dryRun_;
}

/* gets the tombstone data, according to the bugreport type: if zipped, gets all tombstones;
 * otherwise, gets just those modified in the last half an hour. */
static void get_tombstone_fds(tombstone_data_t data[NUM_TOMBSTONES]) {
    time_t thirty_minutes_ago = now - 60*30;
    for (size_t i = 0; i < NUM_TOMBSTONES; i++) {
        snprintf(data[i].name, sizeof(data[i].name), "%s%02zu", TOMBSTONE_FILE_PREFIX, i);
        int fd = TEMP_FAILURE_RETRY(open(data[i].name,
                                         O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
            (zip_writer || (time_t) st.st_mtime >= thirty_minutes_ago)) {
            data[i].fd = fd;
        } else {
            close(fd);
            data[i].fd = -1;
        }
    }
}

// for_each_pid() callback to get mount info about a process.
void do_mountinfo(int pid, const char *name) {
    char path[PATH_MAX];

    // Gets the the content of the /proc/PID/ns/mnt link, so only unique mount points
    // are added.
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);
    char linkname[PATH_MAX];
    ssize_t r = readlink(path, linkname, PATH_MAX);
    if (r == -1) {
        MYLOGE("Unable to read link for %s: %s\n", path, strerror(errno));
        return;
    }
    linkname[r] = '\0';

    if (mount_points.find(linkname) == mount_points.end()) {
        // First time this mount point was found: add it
        snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
        if (add_zip_entry(ZIP_ROOT_DIR + path, path)) {
            mount_points.insert(linkname);
        } else {
            MYLOGE("Unable to add mountinfo %s to zip file\n", path);
        }
    }
}

void add_mountinfo() {
    if (!zip_writer) return;
    std::string title = "MOUNT INFO";
    mount_points.clear();
    DurationReporter durationReporter(title, nullptr);
    for_each_pid(do_mountinfo, nullptr);
    MYLOGD("%s: %d entries added to zip file\n", title.c_str(), (int)mount_points.size());
}

static void dump_dev_files(const char *title, const char *driverpath, const char *filename)
{
    DIR *d;
    struct dirent *de;
    char path[PATH_MAX];

    d = opendir(driverpath);
    if (d == NULL) {
        return;
    }

    while ((de = readdir(d))) {
        if (de->d_type != DT_LNK) {
            continue;
        }
        snprintf(path, sizeof(path), "%s/%s/%s", driverpath, de->d_name, filename);
        DumpFile(title, path);
    }

    closedir(d);
}

// return pid of a userspace process. If not found or error, return 0.
static unsigned int pid_of_process(const char* ps_name) {
    DIR *proc_dir;
    struct dirent *ps;
    unsigned int pid;
    std::string cmdline;

    if (!(proc_dir = opendir("/proc"))) {
        MYLOGE("Can't open /proc\n");
        return 0;
    }

    while ((ps = readdir(proc_dir))) {
        if (!(pid = atoi(ps->d_name))) {
            continue;
        }
        android::base::ReadFileToString("/proc/"
                + std::string(ps->d_name) + "/cmdline", &cmdline);
        if (cmdline.find(ps_name) == std::string::npos) {
            continue;
        } else {
            closedir(proc_dir);
            return pid;
        }
    }
    closedir(proc_dir);
    return 0;
}

// dump anrd's trace and add to the zip file.
// 1. check if anrd is running on this device.
// 2. send a SIGUSR1 to its pid which will dump anrd's trace.
// 3. wait until the trace generation completes and add to the zip file.
static bool dump_anrd_trace() {
    unsigned int pid;
    char buf[50], path[PATH_MAX];
    struct dirent *trace;
    struct stat st;
    DIR *trace_dir;
    int retry = 5;
    long max_ctime = 0, old_mtime;
    long long cur_size = 0;
    const char *trace_path = "/data/misc/anrd/";

    if (!zip_writer) {
        MYLOGE("Not dumping anrd trace because zip_writer is not set\n");
        return false;
    }

    // find anrd's pid if it is running.
    pid = pid_of_process("/system/xbin/anrd");

    if (pid > 0) {
        if (stat(trace_path, &st) == 0) {
            old_mtime = st.st_mtime;
        } else {
            MYLOGE("Failed to find: %s\n", trace_path);
            return false;
        }

        // send SIGUSR1 to the anrd to generate a trace.
        sprintf(buf, "%u", pid);
        if (RunCommand("ANRD_DUMP", {"kill", "-SIGUSR1", buf},
                       CommandOptions::WithTimeout(1).Build())) {
            MYLOGE("anrd signal timed out. Please manually collect trace\n");
            return false;
        }

        while (retry-- > 0 && old_mtime == st.st_mtime) {
            sleep(1);
            stat(trace_path, &st);
        }

        if (retry < 0 && old_mtime == st.st_mtime) {
            MYLOGE("Failed to stat %s or trace creation timeout\n", trace_path);
            return false;
        }

        // identify the trace file by its creation time.
        if (!(trace_dir = opendir(trace_path))) {
            MYLOGE("Can't open trace file under %s\n", trace_path);
        }
        while ((trace = readdir(trace_dir))) {
            if (strcmp(trace->d_name, ".") == 0
                    || strcmp(trace->d_name, "..") == 0) {
                continue;
            }
            sprintf(path, "%s%s", trace_path, trace->d_name);
            if (stat(path, &st) == 0) {
                if (st.st_ctime > max_ctime) {
                    max_ctime = st.st_ctime;
                    sprintf(buf, "%s", trace->d_name);
                }
            }
        }
        closedir(trace_dir);

        // Wait until the dump completes by checking the size of the trace.
        if (max_ctime > 0) {
            sprintf(path, "%s%s", trace_path, buf);
            while(true) {
                sleep(1);
                if (stat(path, &st) == 0) {
                    if (st.st_size == cur_size) {
                        break;
                    } else if (st.st_size > cur_size) {
                        cur_size = st.st_size;
                    } else {
                        return false;
                    }
                } else {
                    MYLOGE("Cant stat() %s anymore\n", path);
                    return false;
                }
            }
            // Add to the zip file.
            if (!add_zip_entry("anrd_trace.txt", path)) {
                MYLOGE("Unable to add anrd_trace file %s to zip file\n", path);
            } else {
                if (remove(path)) {
                    MYLOGE("Error removing anrd_trace file %s: %s", path, strerror(errno));
                }
                return true;
            }
        } else {
            MYLOGE("Can't stats any trace file under %s\n", trace_path);
        }
    }
    return false;
}

static void dump_systrace() {
    if (!zip_writer) {
        MYLOGD("Not dumping systrace because zip_writer is not set\n");
        return;
    }
    std::string systrace_path = ds.bugreportDir_ + "/systrace-" + suffix + ".txt";
    if (systrace_path.empty()) {
        MYLOGE("Not dumping systrace because path is empty\n");
        return;
    }
    const char* path = "/sys/kernel/debug/tracing/tracing_on";
    long int is_tracing;
    if (read_file_as_long(path, &is_tracing)) {
        return; // error already logged
    }
    if (is_tracing <= 0) {
        MYLOGD("Skipping systrace because '%s' content is '%ld'\n", path, is_tracing);
        return;
    }

    MYLOGD("Running '/system/bin/atrace --async_dump -o %s', which can take several minutes",
            systrace_path.c_str());
    if (RunCommand("SYSTRACE", {"/system/bin/atrace", "--async_dump", "-o", systrace_path},
                   CommandOptions::WithTimeout(120).Build())) {
        MYLOGE("systrace timed out, its zip entry will be incomplete\n");
        // TODO: run_command tries to kill the process, but atrace doesn't die
        // peacefully; ideally, we should call strace to stop itself, but there is no such option
        // yet (just a --async_stop, which stops and dump
        // if (RunCommand("SYSTRACE", {"/system/bin/atrace", "--kill"})) {
        //   MYLOGE("could not stop systrace ");
        // }
    }
    if (!add_zip_entry("systrace.txt", systrace_path)) {
        MYLOGE("Unable to add systrace file %s to zip file\n", systrace_path.c_str());
    } else {
        if (remove(systrace_path.c_str())) {
            MYLOGE("Error removing systrace file %s: %s", systrace_path.c_str(), strerror(errno));
        }
    }
}

static void dump_raft() {
    if (is_user_build()) {
        return;
    }

    std::string raft_log_path = ds.bugreportDir_ + "/raft_log.txt";
    if (raft_log_path.empty()) {
        MYLOGD("raft_log_path is empty\n");
        return;
    }

    struct stat s;
    if (stat(RAFT_DIR, &s) != 0 || !S_ISDIR(s.st_mode)) {
        MYLOGD("%s does not exist or is not a directory\n", RAFT_DIR);
        return;
    }

    CommandOptions options = CommandOptions::WithTimeout(600).Build();
    if (!zip_writer) {
        // Write compressed and encoded raft logs to stdout if not zip_writer.
        RunCommand("RAFT LOGS", {"logcompressor", "-r", RAFT_DIR}, options);
        return;
    }

    RunCommand("RAFT LOGS", {"logcompressor", "-n", "-r", RAFT_DIR, "-o", raft_log_path}, options);
    if (!add_zip_entry("raft_log.txt", raft_log_path)) {
        MYLOGE("Unable to add raft log %s to zip file\n", raft_log_path.c_str());
    } else {
        if (remove(raft_log_path.c_str())) {
            MYLOGE("Error removing raft file %s: %s\n", raft_log_path.c_str(), strerror(errno));
        }
    }
}

static bool skip_not_stat(const char *path) {
    static const char stat[] = "/stat";
    size_t len = strlen(path);
    if (path[len - 1] == '/') { /* Directory? */
        return false;
    }
    return strcmp(path + len - sizeof(stat) + 1, stat); /* .../stat? */
}

static bool skip_none(const char *path) {
    return false;
}

static const char mmcblk0[] = "/sys/block/mmcblk0/";
unsigned long worst_write_perf = 20000; /* in KB/s */

//
//  stat offsets
// Name            units         description
// ----            -----         -----------
// read I/Os       requests      number of read I/Os processed
#define __STAT_READ_IOS      0
// read merges     requests      number of read I/Os merged with in-queue I/O
#define __STAT_READ_MERGES   1
// read sectors    sectors       number of sectors read
#define __STAT_READ_SECTORS  2
// read ticks      milliseconds  total wait time for read requests
#define __STAT_READ_TICKS    3
// write I/Os      requests      number of write I/Os processed
#define __STAT_WRITE_IOS     4
// write merges    requests      number of write I/Os merged with in-queue I/O
#define __STAT_WRITE_MERGES  5
// write sectors   sectors       number of sectors written
#define __STAT_WRITE_SECTORS 6
// write ticks     milliseconds  total wait time for write requests
#define __STAT_WRITE_TICKS   7
// in_flight       requests      number of I/Os currently in flight
#define __STAT_IN_FLIGHT     8
// io_ticks        milliseconds  total time this block device has been active
#define __STAT_IO_TICKS      9
// time_in_queue   milliseconds  total wait time for all requests
#define __STAT_IN_QUEUE     10
#define __STAT_NUMBER_FIELD 11
//
// read I/Os, write I/Os
// =====================
//
// These values increment when an I/O request completes.
//
// read merges, write merges
// =========================
//
// These values increment when an I/O request is merged with an
// already-queued I/O request.
//
// read sectors, write sectors
// ===========================
//
// These values count the number of sectors read from or written to this
// block device.  The "sectors" in question are the standard UNIX 512-byte
// sectors, not any device- or filesystem-specific block size.  The
// counters are incremented when the I/O completes.
#define SECTOR_SIZE 512
//
// read ticks, write ticks
// =======================
//
// These values count the number of milliseconds that I/O requests have
// waited on this block device.  If there are multiple I/O requests waiting,
// these values will increase at a rate greater than 1000/second; for
// example, if 60 read requests wait for an average of 30 ms, the read_ticks
// field will increase by 60*30 = 1800.
//
// in_flight
// =========
//
// This value counts the number of I/O requests that have been issued to
// the device driver but have not yet completed.  It does not include I/O
// requests that are in the queue but not yet issued to the device driver.
//
// io_ticks
// ========
//
// This value counts the number of milliseconds during which the device has
// had I/O requests queued.
//
// time_in_queue
// =============
//
// This value counts the number of milliseconds that I/O requests have waited
// on this block device.  If there are multiple I/O requests waiting, this
// value will increase as the product of the number of milliseconds times the
// number of requests waiting (see "read ticks" above for an example).
#define S_TO_MS 1000
//

static int dump_stat_from_fd(const char *title __unused, const char *path, int fd) {
    unsigned long long fields[__STAT_NUMBER_FIELD];
    bool z;
    char *cp, *buffer = NULL;
    size_t i = 0;
    FILE *fp = fdopen(fd, "rb");
    getline(&buffer, &i, fp);
    fclose(fp);
    if (!buffer) {
        return -errno;
    }
    i = strlen(buffer);
    while ((i > 0) && (buffer[i - 1] == '\n')) {
        buffer[--i] = '\0';
    }
    if (!*buffer) {
        free(buffer);
        return 0;
    }
    z = true;
    for (cp = buffer, i = 0; i < (sizeof(fields) / sizeof(fields[0])); ++i) {
        fields[i] = strtoull(cp, &cp, 10);
        if (fields[i] != 0) {
            z = false;
        }
    }
    if (z) { /* never accessed */
        free(buffer);
        return 0;
    }

    if (!strncmp(path, mmcblk0, sizeof(mmcblk0) - 1)) {
        path += sizeof(mmcblk0) - 1;
    }

    printf("%s: %s\n", path, buffer);
    free(buffer);

    if (fields[__STAT_IO_TICKS]) {
        unsigned long read_perf = 0;
        unsigned long read_ios = 0;
        if (fields[__STAT_READ_TICKS]) {
            unsigned long long divisor = fields[__STAT_READ_TICKS]
                                       * fields[__STAT_IO_TICKS];
            read_perf = ((unsigned long long)SECTOR_SIZE
                           * fields[__STAT_READ_SECTORS]
                           * fields[__STAT_IN_QUEUE] + (divisor >> 1))
                                        / divisor;
            read_ios = ((unsigned long long)S_TO_MS * fields[__STAT_READ_IOS]
                           * fields[__STAT_IN_QUEUE] + (divisor >> 1))
                                        / divisor;
        }

        unsigned long write_perf = 0;
        unsigned long write_ios = 0;
        if (fields[__STAT_WRITE_TICKS]) {
            unsigned long long divisor = fields[__STAT_WRITE_TICKS]
                                       * fields[__STAT_IO_TICKS];
            write_perf = ((unsigned long long)SECTOR_SIZE
                           * fields[__STAT_WRITE_SECTORS]
                           * fields[__STAT_IN_QUEUE] + (divisor >> 1))
                                        / divisor;
            write_ios = ((unsigned long long)S_TO_MS * fields[__STAT_WRITE_IOS]
                           * fields[__STAT_IN_QUEUE] + (divisor >> 1))
                                        / divisor;
        }

        unsigned queue = (fields[__STAT_IN_QUEUE]
                             + (fields[__STAT_IO_TICKS] >> 1))
                                 / fields[__STAT_IO_TICKS];

        if (!write_perf && !write_ios) {
            printf("%s: perf(ios) rd: %luKB/s(%lu/s) q: %u\n",
                   path, read_perf, read_ios, queue);
        } else {
            printf("%s: perf(ios) rd: %luKB/s(%lu/s) wr: %luKB/s(%lu/s) q: %u\n",
                   path, read_perf, read_ios, write_perf, write_ios, queue);
        }

        /* bugreport timeout factor adjustment */
        if ((write_perf > 1) && (write_perf < worst_write_perf)) {
            worst_write_perf = write_perf;
        }
    }
    return 0;
}

/* Copied policy from system/core/logd/LogBuffer.cpp */

#define LOG_BUFFER_SIZE (256 * 1024)
#define LOG_BUFFER_MIN_SIZE (64 * 1024UL)
#define LOG_BUFFER_MAX_SIZE (256 * 1024 * 1024UL)

static bool valid_size(unsigned long value) {
    if ((value < LOG_BUFFER_MIN_SIZE) || (LOG_BUFFER_MAX_SIZE < value)) {
        return false;
    }

    long pages = sysconf(_SC_PHYS_PAGES);
    if (pages < 1) {
        return true;
    }

    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 1) {
        pagesize = PAGE_SIZE;
    }

    // maximum memory impact a somewhat arbitrary ~3%
    pages = (pages + 31) / 32;
    unsigned long maximum = pages * pagesize;

    if ((maximum < LOG_BUFFER_MIN_SIZE) || (LOG_BUFFER_MAX_SIZE < maximum)) {
        return true;
    }

    return value <= maximum;
}

// TODO: migrate to logd/LogBuffer.cpp or use android::base::GetProperty
static unsigned long property_get_size(const char *key) {
    unsigned long value;
    char *cp, property[PROPERTY_VALUE_MAX];

    property_get(key, property, "");
    value = strtoul(property, &cp, 10);

    switch(*cp) {
    case 'm':
    case 'M':
        value *= 1024;
    /* FALLTHRU */
    case 'k':
    case 'K':
        value *= 1024;
    /* FALLTHRU */
    case '\0':
        break;

    default:
        value = 0;
    }

    if (!valid_size(value)) {
        value = 0;
    }

    return value;
}

/* timeout in ms */
static unsigned long logcat_timeout(const char *name) {
    static const char global_tuneable[] = "persist.logd.size"; // Settings App
    static const char global_default[] = "ro.logd.size";       // BoardConfig.mk
    char key[PROP_NAME_MAX];
    unsigned long property_size, default_size;

    default_size = property_get_size(global_tuneable);
    if (!default_size) {
        default_size = property_get_size(global_default);
    }

    snprintf(key, sizeof(key), "%s.%s", global_tuneable, name);
    property_size = property_get_size(key);

    if (!property_size) {
        snprintf(key, sizeof(key), "%s.%s", global_default, name);
        property_size = property_get_size(key);
    }

    if (!property_size) {
        property_size = default_size;
    }

    if (!property_size) {
        property_size = LOG_BUFFER_SIZE;
    }

    /* Engineering margin is ten-fold our guess */
    return 10 * (property_size + worst_write_perf) / worst_write_perf;
}

/* End copy from system/core/logd/LogBuffer.cpp */

/* dumps the current system state to stdout */
void print_header(const std::string& version) {
    std::string build, fingerprint, radio, bootloader, network;
    char date[80];

    build = android::base::GetProperty("ro.build.display.id", "(unknown)");
    fingerprint = android::base::GetProperty("ro.build.fingerprint", "(unknown)");
    buildType = android::base::GetProperty("ro.build.type", "(unknown)");
    radio = android::base::GetProperty("gsm.version.baseband", "(unknown)");
    bootloader = android::base::GetProperty("ro.bootloader", "(unknown)");
    network = android::base::GetProperty("gsm.operator.alpha", "(unknown)");
    strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", localtime(&now));

    printf("========================================================\n");
    printf("== dumpstate: %s\n", date);
    printf("========================================================\n");

    printf("\n");
    printf("Build: %s\n", build.c_str());
    // NOTE: fingerprint entry format is important for other tools.
    printf("Build fingerprint: '%s'\n", fingerprint.c_str());
    printf("Bootloader: %s\n", bootloader.c_str());
    printf("Radio: %s\n", radio.c_str());
    printf("Network: %s\n", network.c_str());

    printf("Kernel: ");
    DumpFile("", "/proc/version");
    printf("Command line: %s\n", strtok(cmdline_buf, "\n"));
    printf("Bugreport format version: %s\n", version.c_str());
    printf("Dumpstate info: id=%lu pid=%d dryRun=%d args=%s extraOptions=%s\n", ds.id_, getpid(),
           ds.dryRun_, args.c_str(), extraOptions.c_str());
    printf("\n");
}

// List of file extensions that can cause a zip file attachment to be rejected by some email
// service providers.
static const std::set<std::string> PROBLEMATIC_FILE_EXTENSIONS = {
      ".ade", ".adp", ".bat", ".chm", ".cmd", ".com", ".cpl", ".exe", ".hta", ".ins", ".isp",
      ".jar", ".jse", ".lib", ".lnk", ".mde", ".msc", ".msp", ".mst", ".pif", ".scr", ".sct",
      ".shb", ".sys", ".vb",  ".vbe", ".vbs", ".vxd", ".wsc", ".wsf", ".wsh"
};

bool add_zip_entry_from_fd(const std::string& entry_name, int fd) {
    if (!zip_writer) {
        MYLOGD("Not adding zip entry %s from fd because zip_writer is not set\n",
                entry_name.c_str());
        return false;
    }
    std::string valid_name = entry_name;

    // Rename extension if necessary.
    size_t idx = entry_name.rfind(".");
    if (idx != std::string::npos) {
        std::string extension = entry_name.substr(idx);
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
        if (PROBLEMATIC_FILE_EXTENSIONS.count(extension) != 0) {
            valid_name = entry_name + ".renamed";
            MYLOGI("Renaming entry %s to %s\n", entry_name.c_str(), valid_name.c_str());
        }
    }

    // Logging statement  below is useful to time how long each entry takes, but it's too verbose.
    // MYLOGD("Adding zip entry %s\n", entry_name.c_str());
    int32_t err = zip_writer->StartEntryWithTime(valid_name.c_str(),
            ZipWriter::kCompress, get_mtime(fd, now));
    if (err) {
        MYLOGE("zip_writer->StartEntryWithTime(%s): %s\n", valid_name.c_str(),
                ZipWriter::ErrorCodeString(err));
        return false;
    }

    std::vector<uint8_t> buffer(65536);
    while (1) {
        ssize_t bytes_read = TEMP_FAILURE_RETRY(read(fd, buffer.data(), buffer.size()));
        if (bytes_read == 0) {
            break;
        } else if (bytes_read == -1) {
            MYLOGE("read(%s): %s\n", entry_name.c_str(), strerror(errno));
            return false;
        }
        err = zip_writer->WriteBytes(buffer.data(), bytes_read);
        if (err) {
            MYLOGE("zip_writer->WriteBytes(): %s\n", ZipWriter::ErrorCodeString(err));
            return false;
        }
    }

    err = zip_writer->FinishEntry();
    if (err) {
        MYLOGE("zip_writer->FinishEntry(): %s\n", ZipWriter::ErrorCodeString(err));
        return false;
    }

    return true;
}

bool add_zip_entry(const std::string& entry_name, const std::string& entry_path) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(entry_path.c_str(), O_RDONLY | O_NONBLOCK
            | O_CLOEXEC)));
    if (fd == -1) {
        MYLOGE("open(%s): %s\n", entry_path.c_str(), strerror(errno));
        return false;
    }

    return add_zip_entry_from_fd(entry_name, fd.get());
}

/* adds a file to the existing zipped bugreport */
static int _add_file_from_fd(const char *title, const char *path, int fd) {
    return add_zip_entry_from_fd(ZIP_ROOT_DIR + path, fd) ? 0 : 1;
}

// TODO: move to util.cpp
void add_dir(const std::string& dir, bool recursive) {
    if (!zip_writer) {
        MYLOGD("Not adding dir %s because zip_writer is not set\n", dir.c_str());
        return;
    }
    MYLOGD("Adding dir %s (recursive: %d)\n", dir.c_str(), recursive);
    DurationReporter durationReporter(dir, nullptr);
    dump_files("", dir.c_str(), recursive ? skip_none : is_dir, _add_file_from_fd);
}

/* adds a text entry entry to the existing zip file. */
static bool add_text_zip_entry(const std::string& entry_name, const std::string& content) {
    if (!zip_writer) {
        MYLOGD("Not adding text zip entry %s because zip_writer is not set\n", entry_name.c_str());
        return false;
    }
    MYLOGD("Adding zip text entry %s\n", entry_name.c_str());
    int32_t err = zip_writer->StartEntryWithTime(entry_name.c_str(), ZipWriter::kCompress, now);
    if (err) {
        MYLOGE("zip_writer->StartEntryWithTime(%s): %s\n", entry_name.c_str(),
                ZipWriter::ErrorCodeString(err));
        return false;
    }

    err = zip_writer->WriteBytes(content.c_str(), content.length());
    if (err) {
        MYLOGE("zip_writer->WriteBytes(%s): %s\n", entry_name.c_str(),
                ZipWriter::ErrorCodeString(err));
        return false;
    }

    err = zip_writer->FinishEntry();
    if (err) {
        MYLOGE("zip_writer->FinishEntry(): %s\n", ZipWriter::ErrorCodeString(err));
        return false;
    }

    return true;
}

static void dump_iptables() {
    RunCommand("IPTABLES", {"iptables", "-L", "-nvx"});
    RunCommand("IP6TABLES", {"ip6tables", "-L", "-nvx"});
    RunCommand("IPTABLE NAT", {"iptables", "-t", "nat", "-L", "-nvx"});
    /* no ip6 nat */
    RunCommand("IPTABLE MANGLE", {"iptables", "-t", "mangle", "-L", "-nvx"});
    RunCommand("IP6TABLE MANGLE", {"ip6tables", "-t", "mangle", "-L", "-nvx"});
    RunCommand("IPTABLE RAW", {"iptables", "-t", "raw", "-L", "-nvx"});
    RunCommand("IP6TABLE RAW", {"ip6tables", "-t", "raw", "-L", "-nvx"});
}

static void dumpstate(const std::string& screenshot_path, const std::string& version) {
    DurationReporter durationReporter("DUMPSTATE");
    unsigned long timeout;

    dump_dev_files("TRUSTY VERSION", "/sys/bus/platform/drivers/trusty", "trusty_version");
    RunCommand("UPTIME", {"uptime"});
    dump_files("UPTIME MMC PERF", mmcblk0, skip_not_stat, dump_stat_from_fd);
    dump_emmc_ecsd("/d/mmc0/mmc0:0001/ext_csd");
    DumpFile("MEMORY INFO", "/proc/meminfo");
    RunCommand("CPU INFO", {"top", "-b", "-n", "1", "-H", "-s", "6", "-o",
                            "pid,tid,user,pr,ni,%cpu,s,virt,res,pcy,cmd,name"});
    RunCommand("PROCRANK", {"procrank"}, CommandOptions::AS_ROOT_20);
    DumpFile("VIRTUAL MEMORY STATS", "/proc/vmstat");
    DumpFile("VMALLOC INFO", "/proc/vmallocinfo");
    DumpFile("SLAB INFO", "/proc/slabinfo");
    DumpFile("ZONEINFO", "/proc/zoneinfo");
    DumpFile("PAGETYPEINFO", "/proc/pagetypeinfo");
    DumpFile("BUDDYINFO", "/proc/buddyinfo");
    DumpFile("FRAGMENTATION INFO", "/d/extfrag/unusable_index");

    DumpFile("KERNEL WAKE SOURCES", "/d/wakeup_sources");
    DumpFile("KERNEL CPUFREQ", "/sys/devices/system/cpu/cpu0/cpufreq/stats/time_in_state");
    DumpFile("KERNEL SYNC", "/d/sync");

    RunCommand("PROCESSES AND THREADS",
               {"ps", "-A", "-T", "-Z", "-O", "pri,nice,rtprio,sched,pcy"});
    RunCommand("LIBRANK", {"librank"}, CommandOptions::AS_ROOT_10);

    RunCommand("PRINTENV", {"printenv"});
    RunCommand("NETSTAT", {"netstat", "-n"});
    struct stat s;
    if (stat("/proc/modules", &s) != 0) {
        MYLOGD("Skipping 'lsmod' because /proc/modules does not exist\n");
    } else {
        RunCommand("LSMOD", {"lsmod"});
    }

    do_dmesg();

    RunCommand("LIST OF OPEN FILES", {"lsof"}, CommandOptions::AS_ROOT_10);
    for_each_pid(do_showmap, "SMAPS OF ALL PROCESSES");
    for_each_tid(show_wchan, "BLOCKED PROCESS WAIT-CHANNELS");
    for_each_pid(show_showtime, "PROCESS TIMES (pid cmd user system iowait+percentage)");

    /* Dump Bluetooth HCI logs */
    add_dir("/data/misc/bluetooth/logs", true);

    if (!screenshot_path.empty()) {
        MYLOGI("taking late screenshot\n");
        take_screenshot(screenshot_path);
        MYLOGI("wrote screenshot: %s\n", screenshot_path.c_str());
    }

    // DumpFile("EVENT LOG TAGS", "/etc/event-log-tags");
    // calculate timeout
    timeout = logcat_timeout("main") + logcat_timeout("system") + logcat_timeout("crash");
    if (timeout < 20000) {
        timeout = 20000;
    }
    RunCommand("SYSTEM LOG", {"logcat", "-v", "threadtime", "-v", "printable", "-d", "*:v"},
               CommandOptions::WithTimeout(timeout / 1000).Build());
    timeout = logcat_timeout("events");
    if (timeout < 20000) {
        timeout = 20000;
    }
    RunCommand("EVENT LOG",
               {"logcat", "-b", "events", "-v", "threadtime", "-v", "printable", "-d", "*:v"},
               CommandOptions::WithTimeout(timeout / 1000).Build());
    timeout = logcat_timeout("radio");
    if (timeout < 20000) {
        timeout = 20000;
    }
    RunCommand("RADIO LOG",
               {"logcat", "-b", "radio", "-v", "threadtime", "-v", "printable", "-d", "*:v"},
               CommandOptions::WithTimeout(timeout / 1000).Build());

    RunCommand("LOG STATISTICS", {"logcat", "-b", "all", "-S"});

    /* show the traces we collected in main(), if that was done */
    if (dump_traces_path != NULL) {
        DumpFile("VM TRACES JUST NOW", dump_traces_path);
    }

    /* only show ANR traces if they're less than 15 minutes old */
    struct stat st;
    std::string anrTracesPath = android::base::GetProperty("dalvik.vm.stack-trace-file", "");
    if (anrTracesPath.empty()) {
        printf("*** NO VM TRACES FILE DEFINED (dalvik.vm.stack-trace-file)\n\n");
    } else {
        int fd = TEMP_FAILURE_RETRY(
            open(anrTracesPath.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (fd < 0) {
            printf("*** NO ANR VM TRACES FILE (%s): %s\n\n", anrTracesPath.c_str(), strerror(errno));
      } else {
          dump_file_from_fd("VM TRACES AT LAST ANR", anrTracesPath.c_str(), fd);
      }
    }

    /* slow traces for slow operations */
    if (!anrTracesPath.empty()) {
        int tail = anrTracesPath.size() - 1;
        while (tail > 0 && anrTracesPath.at(tail) != '/') {
            tail--;
        }
        int i = 0;
        while (1) {
            anrTracesPath =
                anrTracesPath.substr(0, tail + 1) + android::base::StringPrintf("slow%02d.txt", i);
            if (stat(anrTracesPath.c_str(), &st)) {
                // No traces file at this index, done with the files.
                break;
            }
            DumpFile("VM TRACES WHEN SLOW", anrTracesPath.c_str());
            i++;
        }
    }

    int dumped = 0;
    for (size_t i = 0; i < NUM_TOMBSTONES; i++) {
        if (tombstone_data[i].fd != -1) {
            const char *name = tombstone_data[i].name;
            int fd = tombstone_data[i].fd;
            dumped = 1;
            if (zip_writer) {
                if (!add_zip_entry_from_fd(ZIP_ROOT_DIR + name, fd)) {
                    MYLOGE("Unable to add tombstone %s to zip file\n", name);
                }
            } else {
                dump_file_from_fd("TOMBSTONE", name, fd);
            }
            close(fd);
            tombstone_data[i].fd = -1;
        }
    }
    if (!dumped) {
        printf("*** NO TOMBSTONES to dump in %s\n\n", TOMBSTONE_DIR);
    }

    DumpFile("NETWORK DEV INFO", "/proc/net/dev");
    DumpFile("QTAGUID NETWORK INTERFACES INFO", "/proc/net/xt_qtaguid/iface_stat_all");
    DumpFile("QTAGUID NETWORK INTERFACES INFO (xt)", "/proc/net/xt_qtaguid/iface_stat_fmt");
    DumpFile("QTAGUID CTRL INFO", "/proc/net/xt_qtaguid/ctrl");
    DumpFile("QTAGUID STATS INFO", "/proc/net/xt_qtaguid/stats");

    if (!stat(PSTORE_LAST_KMSG, &st)) {
        /* Also TODO: Make console-ramoops CAP_SYSLOG protected. */
        DumpFile("LAST KMSG", PSTORE_LAST_KMSG);
    } else if (!stat(ALT_PSTORE_LAST_KMSG, &st)) {
        DumpFile("LAST KMSG", ALT_PSTORE_LAST_KMSG);
    } else {
        /* TODO: Make last_kmsg CAP_SYSLOG protected. b/5555691 */
        DumpFile("LAST KMSG", "/proc/last_kmsg");
    }

    /* kernels must set CONFIG_PSTORE_PMSG, slice up pstore with device tree */
    RunCommand("LAST LOGCAT",
               {"logcat", "-L", "-b", "all", "-v", "threadtime", "-v", "printable", "-d", "*:v"});

    /* The following have a tendency to get wedged when wifi drivers/fw goes belly-up. */

    RunCommand("NETWORK INTERFACES", {"ip", "link"});

    RunCommand("IPv4 ADDRESSES", {"ip", "-4", "addr", "show"});
    RunCommand("IPv6 ADDRESSES", {"ip", "-6", "addr", "show"});

    RunCommand("IP RULES", {"ip", "rule", "show"});
    RunCommand("IP RULES v6", {"ip", "-6", "rule", "show"});

    dump_route_tables();

    RunCommand("ARP CACHE", {"ip", "-4", "neigh", "show"});
    RunCommand("IPv6 ND CACHE", {"ip", "-6", "neigh", "show"});
    RunCommand("MULTICAST ADDRESSES", {"ip", "maddr"});
    RunCommand("WIFI NETWORKS", {"wpa_cli", "IFNAME=wlan0", "list_networks"},
               CommandOptions::WithTimeout(20).Build());

#ifdef FWDUMP_bcmdhd
    RunCommand("ND OFFLOAD TABLE", {WLUTIL, "nd_hostip"}, CommandOptions::AS_ROOT_5);

    RunCommand("DUMP WIFI INTERNAL COUNTERS (1)", {WLUTIL, "counters"}, CommandOptions::AS_ROOT_20);

    RunCommand("ND OFFLOAD STATUS (1)", {WLUTIL, "nd_status"}, CommandOptions::AS_ROOT_5);

#endif
    DumpFile("INTERRUPTS (1)", "/proc/interrupts");

    RunDumpsys("NETWORK DIAGNOSTICS", {"connectivity", "--diag"},
               CommandOptions::WithTimeout(10).Build());

#ifdef FWDUMP_bcmdhd
    RunCommand("DUMP WIFI STATUS", {"dhdutil", "-i", "wlan0", "dump"}, CommandOptions::AS_ROOT_20);

    RunCommand("DUMP WIFI INTERNAL COUNTERS (2)", {WLUTIL, "counters"}, CommandOptions::AS_ROOT_20);

    RunCommand("ND OFFLOAD STATUS (2)", {WLUTIL, "nd_status"}, CommandOptions::AS_ROOT_5);
#endif
    DumpFile("INTERRUPTS (2)", "/proc/interrupts");

    print_properties();

    RunCommand("VOLD DUMP", {"vdc", "dump"});
    RunCommand("SECURE CONTAINERS", {"vdc", "asec", "list"});

    RunCommand("FILESYSTEMS & FREE SPACE", {"df"});

    RunCommand("LAST RADIO LOG", {"parse_radio_log", "/proc/last_radio_log"});

    printf("------ BACKLIGHTS ------\n");
    printf("LCD brightness=");
    DumpFile("", "/sys/class/leds/lcd-backlight/brightness");
    printf("Button brightness=");
    DumpFile("", "/sys/class/leds/button-backlight/brightness");
    printf("Keyboard brightness=");
    DumpFile("", "/sys/class/leds/keyboard-backlight/brightness");
    printf("ALS mode=");
    DumpFile("", "/sys/class/leds/lcd-backlight/als");
    printf("LCD driver registers:\n");
    DumpFile("", "/sys/class/leds/lcd-backlight/registers");
    printf("\n");

    /* Binder state is expensive to look at as it uses a lot of memory. */
    DumpFile("BINDER FAILED TRANSACTION LOG", "/sys/kernel/debug/binder/failed_transaction_log");
    DumpFile("BINDER TRANSACTION LOG", "/sys/kernel/debug/binder/transaction_log");
    DumpFile("BINDER TRANSACTIONS", "/sys/kernel/debug/binder/transactions");
    DumpFile("BINDER STATS", "/sys/kernel/debug/binder/stats");
    DumpFile("BINDER STATE", "/sys/kernel/debug/binder/state");

    printf("========================================================\n");
    printf("== Board\n");
    printf("========================================================\n");

    {
        DurationReporter tmpDr("dumpstate_board()");
        dumpstate_board();
        printf("\n");
    }

    /* Migrate the ril_dumpstate to a dumpstate_board()? */
    int rilDumpstateTimeout = android::base::GetIntProperty("ril.dumpstate.timeout", 0);
    if (rilDumpstateTimeout > 0) {
        // su does not exist on user builds, so try running without it.
        // This way any implementations of vril-dump that do not require
        // root can run on user builds.
        CommandOptions::CommandOptionsBuilder options =
            CommandOptions::WithTimeout(rilDumpstateTimeout);
        if (!is_user_build()) {
            options.AsRoot();
        }
        RunCommand("DUMP VENDOR RIL LOGS", {"vril-dump"}, options.Build());
    }

    printf("========================================================\n");
    printf("== Android Framework Services\n");
    printf("========================================================\n");

    RunDumpsys("DUMPSYS", {"--skip", "meminfo", "cpuinfo"}, CommandOptions::WithTimeout(90).Build(),
               10);

    printf("========================================================\n");
    printf("== Checkins\n");
    printf("========================================================\n");

    RunDumpsys("CHECKIN BATTERYSTATS", {"batterystats", "-c"});
    RunDumpsys("CHECKIN MEMINFO", {"meminfo", "--checkin"});
    RunDumpsys("CHECKIN NETSTATS", {"netstats", "--checkin"});
    RunDumpsys("CHECKIN PROCSTATS", {"procstats", "-c"});
    RunDumpsys("CHECKIN USAGESTATS", {"usagestats", "-c"});
    RunDumpsys("CHECKIN PACKAGE", {"package", "--checkin"});

    printf("========================================================\n");
    printf("== Running Application Activities\n");
    printf("========================================================\n");

    RunDumpsys("APP ACTIVITIES", {"activity", "all"});

    printf("========================================================\n");
    printf("== Running Application Services\n");
    printf("========================================================\n");

    RunDumpsys("APP SERVICES", {"activity", "service", "all"});

    printf("========================================================\n");
    printf("== Running Application Providers\n");
    printf("========================================================\n");

    RunDumpsys("APP PROVIDERS", {"activity", "provider", "all"});

    printf("========================================================\n");
    printf("== Final progress (pid %d): %d/%d (originally %d)\n", getpid(), ds.progress_,
           ds.weightTotal_, WEIGHT_TOTAL);
    printf("========================================================\n");
    printf("== dumpstate: done (id %lu)\n", ds.id_);
    printf("========================================================\n");
}

static void usage() {
  fprintf(stderr,
          "usage: dumpstate [-h] [-b soundfile] [-e soundfile] [-o file [-d] [-p] "
          "[-z]] [-s] [-S] [-q] [-B] [-P] [-R] [-V version]\n"
          "  -h: display this help message\n"
          "  -b: play sound file instead of vibrate, at beginning of job\n"
          "  -e: play sound file instead of vibrate, at end of job\n"
          "  -o: write to file (instead of stdout)\n"
          "  -d: append date to filename (requires -o)\n"
          "  -p: capture screenshot to filename.png (requires -o)\n"
          "  -z: generate zipped file (requires -o)\n"
          "  -s: write output to control socket (for init)\n"
          "  -S: write file location to control socket (for init; requires -o and -z)"
          "  -q: disable vibrate\n"
          "  -B: send broadcast when finished (requires -o)\n"
          "  -P: send broadcast when started and update system properties on "
          "progress (requires -o and -B)\n"
          "  -R: take bugreport in remote mode (requires -o, -z, -d and -B, "
          "shouldn't be used with -P)\n"
          "  -V: sets the bugreport format version (valid values: %s)\n",
          VERSION_DEFAULT.c_str());
}

static void wake_lock_releaser() {
    if (release_wake_lock(WAKE_LOCK_NAME) < 0) {
        MYLOGE("Failed to release wake lock: %s \n", strerror(errno));
    } else {
        MYLOGD("Wake lock released.\n");
    }
}

static void sig_handler(int signo) {
    wake_lock_releaser();
    _exit(EXIT_FAILURE);
}

static void register_sig_handler() {
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = sig_handler;
    sigaction(SIGPIPE, &sa, NULL); // broken pipe
    sigaction(SIGSEGV, &sa, NULL); // segment fault
    sigaction(SIGINT, &sa, NULL); // ctrl-c
    sigaction(SIGTERM, &sa, NULL); // killed
    sigaction(SIGQUIT, &sa, NULL); // quit
}

/* adds the temporary report to the existing .zip file, closes the .zip file, and removes the
   temporary file.
 */
static bool finish_zip_file(const std::string& bugreport_name, const std::string& bugreport_path,
                            const std::string& log_path, time_t now) {
    // Final timestamp
    char date[80];
    time_t the_real_now_please_stand_up = time(nullptr);
    strftime(date, sizeof(date), "%Y/%m/%d %H:%M:%S", localtime(&the_real_now_please_stand_up));
    MYLOGD("dumpstate id %lu finished around %s (%ld s)\n", ds.id_, date,
           the_real_now_please_stand_up - now);

    if (!add_zip_entry(bugreport_name, bugreport_path)) {
        MYLOGE("Failed to add text entry to .zip file\n");
        return false;
    }
    if (!add_text_zip_entry("main_entry.txt", bugreport_name)) {
        MYLOGE("Failed to add main_entry.txt to .zip file\n");
        return false;
    }

    // Add log file (which contains stderr output) to zip...
    fprintf(stderr, "dumpstate_log.txt entry on zip file logged up to here\n");
    if (!add_zip_entry("dumpstate_log.txt", log_path.c_str())) {
        MYLOGE("Failed to add dumpstate log to .zip file\n");
        return false;
    }
    // ... and re-opens it for further logging.
    redirect_to_existing_file(stderr, const_cast<char*>(log_path.c_str()));
    fprintf(stderr, "\n");

    int32_t err = zip_writer->Finish();
    if (err) {
        MYLOGE("zip_writer->Finish(): %s\n", ZipWriter::ErrorCodeString(err));
        return false;
    }

    if (is_user_build()) {
        MYLOGD("Removing temporary file %s\n", bugreport_path.c_str())
        if (remove(bugreport_path.c_str())) {
            ALOGW("remove(%s): %s\n", bugreport_path.c_str(), strerror(errno));
        }
    } else {
        MYLOGD("Keeping temporary file %s on non-user build\n", bugreport_path.c_str())
    }

    return true;
}

static std::string SHA256_file_hash(std::string filepath) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(filepath.c_str(), O_RDONLY | O_NONBLOCK
            | O_CLOEXEC | O_NOFOLLOW)));
    if (fd == -1) {
        MYLOGE("open(%s): %s\n", filepath.c_str(), strerror(errno));
        return NULL;
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    std::vector<uint8_t> buffer(65536);
    while (1) {
        ssize_t bytes_read = TEMP_FAILURE_RETRY(read(fd.get(), buffer.data(), buffer.size()));
        if (bytes_read == 0) {
            break;
        } else if (bytes_read == -1) {
            MYLOGE("read(%s): %s\n", filepath.c_str(), strerror(errno));
            return NULL;
        }

        SHA256_Update(&ctx, buffer.data(), bytes_read);
    }

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    char hash_buffer[SHA256_DIGEST_LENGTH * 2 + 1];
    for(size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_buffer + (i * 2), "%02x", hash[i]);
    }
    hash_buffer[sizeof(hash_buffer) - 1] = 0;
    return std::string(hash_buffer);
}

int main(int argc, char *argv[]) {
    int do_add_date = 0;
    int do_zip_file = 0;
    int do_vibrate = 1;
    char* use_outfile = 0;
    int use_socket = 0;
    int use_control_socket = 0;
    int do_fb = 0;
    int do_broadcast = 0;
    int do_early_screenshot = 0;
    int is_remote_mode = 0;
    std::string version = VERSION_DEFAULT;

    now = time(nullptr);

    MYLOGI("begin\n");

    if (acquire_wake_lock(PARTIAL_WAKE_LOCK, WAKE_LOCK_NAME) < 0) {
        MYLOGE("Failed to acquire wake lock: %s \n", strerror(errno));
    } else {
        MYLOGD("Wake lock acquired.\n");
        atexit(wake_lock_releaser);
        register_sig_handler();
    }

    ds.dryRun_ = android::base::GetBoolProperty("dumpstate.dry_run", false);
    if (ds.dryRun_) {
        MYLOGI("Running on dry-run mode (to disable it, call 'setprop dumpstate.dry_run false')\n");
    }

    // TODO: use helper function to convert argv into a string
    for (int i = 0; i < argc; i++) {
        args += argv[i];
        if (i < argc - 1) {
            args += " ";
        }
    }

    extraOptions = android::base::GetProperty(PROPERTY_EXTRA_OPTIONS, "");
    MYLOGI("Dumpstate args: %s (extra options: %s)\n", args.c_str(), extraOptions.c_str());

    /* gets the sequential id */
    int lastId = android::base::GetIntProperty(PROPERTY_LAST_ID, 0);
    ds.id_ = ++lastId;
    android::base::SetProperty(PROPERTY_LAST_ID, std::to_string(lastId));
    MYLOGI("dumpstate id: %lu\n", ds.id_);

    /* set as high priority, and protect from OOM killer */
    setpriority(PRIO_PROCESS, 0, -20);

    FILE *oom_adj = fopen("/proc/self/oom_score_adj", "we");
    if (oom_adj) {
        fputs("-1000", oom_adj);
        fclose(oom_adj);
    } else {
        /* fallback to kernels <= 2.6.35 */
        oom_adj = fopen("/proc/self/oom_adj", "we");
        if (oom_adj) {
            fputs("-17", oom_adj);
            fclose(oom_adj);
        }
    }

    /* parse arguments */
    int c;
    while ((c = getopt(argc, argv, "dho:svqzpPBRSV:")) != -1) {
        switch (c) {
            // clang-format off
            case 'd': do_add_date = 1;          break;
            case 'z': do_zip_file = 1;          break;
            case 'o': use_outfile = optarg;     break;
            case 's': use_socket = 1;           break;
            case 'S': use_control_socket = 1;   break;
            case 'v': break;  // compatibility no-op
            case 'q': do_vibrate = 0;           break;
            case 'p': do_fb = 1;                break;
            case 'P': ds.updateProgress_ = 1;   break;
            case 'R': is_remote_mode = 1;       break;
            case 'B': do_broadcast = 1;         break;
            case 'V': version = optarg;         break;
            case '?': printf("\n");
            case 'h': usage(); exit(1);
                // clang-format on
        }
    }

    if (!extraOptions.empty()) {
        // Framework uses a system property to override some command-line args.
        // Currently, it contains the type of the requested bugreport.
        if (extraOptions == "bugreportplus") {
            MYLOGD("Running as bugreportplus: add -P, remove -p\n");
            ds.updateProgress_ = 1;
            do_fb = 0;
        } else if (extraOptions == "bugreportremote") {
            MYLOGD("Running as bugreportremote: add -q -R, remove -p\n");
            do_vibrate = 0;
            is_remote_mode = 1;
            do_fb = 0;
        } else if (extraOptions == "bugreportwear") {
            MYLOGD("Running as bugreportwear: add -P\n");
            ds.updateProgress_ = 1;
        } else {
            MYLOGE("Unknown extra option: %s\n", extraOptions.c_str());
        }
        // Reset the property
        android::base::SetProperty(PROPERTY_EXTRA_OPTIONS, "");
    }

    if ((do_zip_file || do_add_date || ds.updateProgress_ || do_broadcast) && !use_outfile) {
        usage();
        exit(1);
    }

    if (use_control_socket && !do_zip_file) {
        usage();
        exit(1);
    }

    if (ds.updateProgress_ && !do_broadcast) {
        usage();
        exit(1);
    }

    if (is_remote_mode && (ds.updateProgress_ || !do_broadcast || !do_zip_file || !do_add_date)) {
        usage();
        exit(1);
    }

    if (version != VERSION_DEFAULT) {
      usage();
      exit(1);
    }

    MYLOGI("bugreport format version: %s\n", version.c_str());

    do_early_screenshot = ds.updateProgress_;

    // If we are going to use a socket, do it as early as possible
    // to avoid timeouts from bugreport.
    if (use_socket) {
        redirect_to_socket(stdout, "dumpstate");
    }

    if (use_control_socket) {
        MYLOGD("Opening control socket\n");
        ds.controlSocketFd_ = open_socket("dumpstate");
        ds.updateProgress_ = 1;
    }

    /* full path of the temporary file containing the bugreport */
    std::string tmp_path;

    /* full path of the file containing the dumpstate logs */
    std::string log_path;

    /* full path of the systrace file, when enabled */
    std::string systrace_path;

    /* full path of the temporary file containing the screenshot (when requested) */
    std::string screenshot_path;

    /* base name (without suffix or extensions) of the bugreport files */
    std::string base_name;

    /* pointer to the actual path, be it zip or text */
    std::string path;

    /* pointer to the zipped file */
    std::unique_ptr<FILE, int(*)(FILE*)> zip_file(NULL, fclose);

    /* redirect output if needed */
    bool is_redirecting = !use_socket && use_outfile;

    if (is_redirecting) {
        ds.bugreportDir_ = dirname(use_outfile);
        base_name = basename(use_outfile);
        if (do_add_date) {
            char date[80];
            strftime(date, sizeof(date), "%Y-%m-%d-%H-%M-%S", localtime(&now));
            suffix = date;
        } else {
            suffix = "undated";
        }
        std::string buildId = android::base::GetProperty("ro.build.id", "UNKNOWN_BUILD");
        base_name = base_name + "-" + buildId;
        if (do_fb) {
            // TODO: if dumpstate was an object, the paths could be internal variables and then
            // we could have a function to calculate the derived values, such as:
            //     screenshot_path = GetPath(".png");
            screenshot_path = ds.bugreportDir_ + "/" + base_name + "-" + suffix + ".png";
        }
        tmp_path = ds.bugreportDir_ + "/" + base_name + "-" + suffix + ".tmp";
        log_path =
            ds.bugreportDir_ + "/dumpstate_log-" + suffix + "-" + std::to_string(getpid()) + ".txt";

        MYLOGD(
            "Bugreport dir: %s\n"
            "Base name: %s\n"
            "Suffix: %s\n"
            "Log path: %s\n"
            "Temporary path: %s\n"
            "Screenshot path: %s\n",
            ds.bugreportDir_.c_str(), base_name.c_str(), suffix.c_str(), log_path.c_str(),
            tmp_path.c_str(), screenshot_path.c_str());

        if (do_zip_file) {
            path = ds.bugreportDir_ + "/" + base_name + "-" + suffix + ".zip";
            MYLOGD("Creating initial .zip file (%s)\n", path.c_str());
            create_parent_dirs(path.c_str());
            zip_file.reset(fopen(path.c_str(), "wb"));
            if (!zip_file) {
                MYLOGE("fopen(%s, 'wb'): %s\n", path.c_str(), strerror(errno));
                do_zip_file = 0;
            } else {
                zip_writer.reset(new ZipWriter(zip_file.get()));
            }
            add_text_zip_entry("version.txt", version);
        }

        if (ds.updateProgress_) {
            if (do_broadcast) {
                // clang-format off
                std::vector<std::string> am_args = {
                     "--receiver-permission", "android.permission.DUMP", "--receiver-foreground",
                     "--es", "android.intent.extra.NAME", suffix,
                     "--ei", "android.intent.extra.ID", std::to_string(ds.id_),
                     "--ei", "android.intent.extra.PID", std::to_string(getpid()),
                     "--ei", "android.intent.extra.MAX", std::to_string(WEIGHT_TOTAL),
                };
                // clang-format on
                send_broadcast("android.intent.action.BUGREPORT_STARTED", am_args);
            }
            if (use_control_socket) {
                dprintf(ds.controlSocketFd_, "BEGIN:%s\n", path.c_str());
            }
        }
    }

    /* read /proc/cmdline before dropping root */
    FILE *cmdline = fopen("/proc/cmdline", "re");
    if (cmdline) {
        fgets(cmdline_buf, sizeof(cmdline_buf), cmdline);
        fclose(cmdline);
    }

    /* open the vibrator before dropping root */
    std::unique_ptr<FILE, int(*)(FILE*)> vibrator(NULL, fclose);
    if (do_vibrate) {
        vibrator.reset(fopen("/sys/class/timed_output/vibrator/enable", "we"));
        if (vibrator) {
            vibrate(vibrator.get(), 150);
        }
    }

    if (do_fb && do_early_screenshot) {
        if (screenshot_path.empty()) {
            // should not have happened
            MYLOGE("INTERNAL ERROR: skipping early screenshot because path was not set\n");
        } else {
            MYLOGI("taking early screenshot\n");
            take_screenshot(screenshot_path);
            MYLOGI("wrote screenshot: %s\n", screenshot_path.c_str());
            if (chown(screenshot_path.c_str(), AID_SHELL, AID_SHELL)) {
                MYLOGE("Unable to change ownership of screenshot file %s: %s\n",
                        screenshot_path.c_str(), strerror(errno));
            }
        }
    }

    if (do_zip_file) {
        if (chown(path.c_str(), AID_SHELL, AID_SHELL)) {
            MYLOGE("Unable to change ownership of zip file %s: %s\n", path.c_str(), strerror(errno));
        }
    }

    if (is_redirecting) {
        redirect_to_file(stderr, const_cast<char*>(log_path.c_str()));
        if (chown(log_path.c_str(), AID_SHELL, AID_SHELL)) {
            MYLOGE("Unable to change ownership of dumpstate log file %s: %s\n",
                    log_path.c_str(), strerror(errno));
        }
        /* TODO: rather than generating a text file now and zipping it later,
           it would be more efficient to redirect stdout to the zip entry
           directly, but the libziparchive doesn't support that option yet. */
        redirect_to_file(stdout, const_cast<char*>(tmp_path.c_str()));
        if (chown(tmp_path.c_str(), AID_SHELL, AID_SHELL)) {
            MYLOGE("Unable to change ownership of temporary bugreport file %s: %s\n",
                    tmp_path.c_str(), strerror(errno));
        }
    }
    // NOTE: there should be no stdout output until now, otherwise it would break the header.
    // In particular, DurationReport objects should be created passing 'title, NULL', so their
    // duration is logged into MYLOG instead.
    print_header(version);

    // Dumps systrace right away, otherwise it will be filled with unnecessary events.
    // First try to dump anrd trace if the daemon is running. Otherwise, dump
    // the raw trace.
    if (!dump_anrd_trace()) {
        dump_systrace();
    }

    // Invoking the following dumpsys calls before dump_traces() to try and
    // keep the system stats as close to its initial state as possible.
    RunDumpsys("DUMPSYS MEMINFO", {"meminfo", "-a"},
               CommandOptions::WithTimeout(90).DropRoot().Build());
    RunDumpsys("DUMPSYS CPUINFO", {"cpuinfo", "-a"},
               CommandOptions::WithTimeout(10).DropRoot().Build());

    // TODO: Drop root user and move into dumpstate() once b/28633932 is fixed.
    dump_raft();

    /* collect stack traces from Dalvik and native processes (needs root) */
    dump_traces_path = dump_traces();

    /* Run some operations that require root. */
    get_tombstone_fds(tombstone_data);
    add_dir(RECOVERY_DIR, true);
    add_dir(RECOVERY_DATA_DIR, true);
    add_dir(LOGPERSIST_DATA_DIR, false);
    if (!is_user_build()) {
        add_dir(PROFILE_DATA_DIR_CUR, true);
        add_dir(PROFILE_DATA_DIR_REF, true);
    }
    add_mountinfo();
    dump_iptables();

    // Run ss as root so we can see socket marks.
    run_command("DETAILED SOCKET STATE", 10, "ss", "-eionptu", NULL);

    if (!drop_root_user()) {
        return -1;
    }

    dumpstate(do_early_screenshot ? "": screenshot_path, version);

    /* close output if needed */
    if (is_redirecting) {
        fclose(stdout);
    }

    /* rename or zip the (now complete) .tmp file to its final location */
    if (use_outfile) {

        /* check if user changed the suffix using system properties */
        std::string name = android::base::GetProperty(
            android::base::StringPrintf("dumpstate.%d.name", getpid()), "");
        bool change_suffix= false;
        if (!name.empty()) {
            /* must whitelist which characters are allowed, otherwise it could cross directories */
            std::regex valid_regex("^[-_a-zA-Z0-9]+$");
            if (std::regex_match(name.c_str(), valid_regex)) {
                change_suffix = true;
            } else {
                MYLOGE("invalid suffix provided by user: %s\n", name.c_str());
            }
        }
        if (change_suffix) {
            MYLOGI("changing suffix from %s to %s\n", suffix.c_str(), name.c_str());
            suffix = name;
            if (!screenshot_path.empty()) {
                std::string new_screenshot_path =
                    ds.bugreportDir_ + "/" + base_name + "-" + suffix + ".png";
                if (rename(screenshot_path.c_str(), new_screenshot_path.c_str())) {
                    MYLOGE("rename(%s, %s): %s\n", screenshot_path.c_str(),
                            new_screenshot_path.c_str(), strerror(errno));
                } else {
                    screenshot_path = new_screenshot_path;
                }
            }
        }

        bool do_text_file = true;
        if (do_zip_file) {
            std::string entry_name = base_name + "-" + suffix + ".txt";
            MYLOGD("Adding main entry (%s) to .zip bugreport\n", entry_name.c_str());
            if (!finish_zip_file(entry_name, tmp_path, log_path, now)) {
                MYLOGE("Failed to finish zip file; sending text bugreport instead\n");
                do_text_file = true;
            } else {
                do_text_file = false;
                // Since zip file is already created, it needs to be renamed.
                std::string new_path = ds.bugreportDir_ + "/" + base_name + "-" + suffix + ".zip";
                if (path != new_path) {
                    MYLOGD("Renaming zip file from %s to %s\n", path.c_str(), new_path.c_str());
                    if (rename(path.c_str(), new_path.c_str())) {
                        MYLOGE("rename(%s, %s): %s\n", path.c_str(),
                                new_path.c_str(), strerror(errno));
                    } else {
                        path = new_path;
                    }
                }
            }
        }
        if (do_text_file) {
            path = ds.bugreportDir_ + "/" + base_name + "-" + suffix + ".txt";
            MYLOGD("Generating .txt bugreport at %s from %s\n", path.c_str(), tmp_path.c_str());
            if (rename(tmp_path.c_str(), path.c_str())) {
                MYLOGE("rename(%s, %s): %s\n", tmp_path.c_str(), path.c_str(), strerror(errno));
                path.clear();
            }
        }
        if (use_control_socket) {
            if (do_text_file) {
                dprintf(ds.controlSocketFd_,
                        "FAIL:could not create zip file, check %s "
                        "for more details\n",
                        log_path.c_str());
            } else {
                dprintf(ds.controlSocketFd_, "OK:%s\n", path.c_str());
            }
        }
    }

    /* vibrate a few but shortly times to let user know it's finished */
    if (vibrator) {
        for (int i = 0; i < 3; i++) {
            vibrate(vibrator.get(), 75);
            usleep((75 + 50) * 1000);
        }
    }

    /* tell activity manager we're done */
    if (do_broadcast) {
        if (!path.empty()) {
            MYLOGI("Final bugreport path: %s\n", path.c_str());
            // clang-format off
            std::vector<std::string> am_args = {
                 "--receiver-permission", "android.permission.DUMP", "--receiver-foreground",
                 "--ei", "android.intent.extra.ID", std::to_string(ds.id_),
                 "--ei", "android.intent.extra.PID", std::to_string(getpid()),
                 "--ei", "android.intent.extra.MAX", std::to_string(ds.weightTotal_),
                 "--es", "android.intent.extra.BUGREPORT", path,
                 "--es", "android.intent.extra.DUMPSTATE_LOG", log_path
            };
            // clang-format on
            if (do_fb) {
                am_args.push_back("--es");
                am_args.push_back("android.intent.extra.SCREENSHOT");
                am_args.push_back(screenshot_path);
            }
            if (is_remote_mode) {
                am_args.push_back("--es");
                am_args.push_back("android.intent.extra.REMOTE_BUGREPORT_HASH");
                am_args.push_back(SHA256_file_hash(path));
                send_broadcast("android.intent.action.REMOTE_BUGREPORT_FINISHED", am_args);
            } else {
                send_broadcast("android.intent.action.BUGREPORT_FINISHED", am_args);
            }
        } else {
            MYLOGE("Skipping finished broadcast because bugreport could not be generated\n");
        }
    }

    MYLOGD("Final progress: %d/%d (originally %d)\n", ds.progress_, ds.weightTotal_, WEIGHT_TOTAL);
    MYLOGI("done (id %lu)\n", ds.id_);

    if (is_redirecting) {
        fclose(stderr);
    }

    if (use_control_socket && ds.controlSocketFd_ != -1) {
        MYLOGD("Closing control socket\n");
        close(ds.controlSocketFd_);
    }

    return 0;
}
