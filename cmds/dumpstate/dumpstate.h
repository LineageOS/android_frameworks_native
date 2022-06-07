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

#ifndef FRAMEWORK_NATIVE_CMD_DUMPSTATE_H_
#define FRAMEWORK_NATIVE_CMD_DUMPSTATE_H_

#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>

#include <string>
#include <vector>

#include <android-base/macros.h>
#include <android-base/unique_fd.h>
#include <android/hardware/dumpstate/1.1/types.h>
#include <android/os/BnIncidentAuthListener.h>
#include <android/os/IDumpstate.h>
#include <android/os/IDumpstateListener.h>
#include <utils/StrongPointer.h>
#include <ziparchive/zip_writer.h>

#include "DumpstateUtil.h"
#include "DumpPool.h"
#include "TaskQueue.h"

// Workaround for const char *args[MAX_ARGS_ARRAY_SIZE] variables until they're converted to
// std::vector<std::string>
// TODO: remove once not used
#define MAX_ARGS_ARRAY_SIZE 1000

// TODO: move everything under this namespace
// TODO: and then remove explicitly android::os::dumpstate:: prefixes
namespace android {
namespace os {

struct DumpstateOptions;

namespace dumpstate {

class DumpstateTest;
class ProgressTest;
class ZippedBugReportStreamTest;

}  // namespace dumpstate
}  // namespace os
}  // namespace android

class ZipWriter;

// TODO: remove once moved to HAL
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Helper class used to report how long it takes for a section to finish.
 *
 * Typical usage:
 *
 *    DurationReporter duration_reporter(title);
 *
 */
class DurationReporter {
  public:
    explicit DurationReporter(const std::string& title, bool logcat_only = false,
                              bool verbose = false, int duration_fd = STDOUT_FILENO);

    ~DurationReporter();

  private:
    std::string title_;
    bool logcat_only_;
    bool verbose_;
    uint64_t started_;
    int duration_fd_;

    DISALLOW_COPY_AND_ASSIGN(DurationReporter);
};

/*
 * Keeps track of current progress and estimated max, saving stats on file to tune up future runs.
 *
 * Each `dumpstate` section contributes to the total weight by an individual weight, so the overall
 * progress can be calculated by dividing the estimate max progress by the current progress.
 *
 * The estimated max progress is initially set to a value (`kDefaultMax) defined empirically, but
 * it's adjusted after each dumpstate run by storing the average duration in a file.
 *
 */
class Progress {
    friend class android::os::dumpstate::ProgressTest;
    friend class android::os::dumpstate::DumpstateTest;

  public:
    /*
     * Default estimation of the max duration of a bugreport generation.
     *
     * It does not need to match the exact sum of all sections, but ideally it should to be slight
     * more than such sum: a value too high will cause the bugreport to finish before the user
     * expected (for example, jumping from 70% to 100%), while a value too low will cause the
     * progress to get stuck at an almost-finished value (like 99%) for a while.
     *
     * This constant is only used when the average duration from previous runs cannot be used.
     */
    static const int kDefaultMax;

    explicit Progress(const std::string& path = "");

    // Gets the current progress.
    int32_t Get() const;

    // Gets the current estimated max progress.
    int32_t GetMax() const;

    // Gets the initial estimated max progress.
    int32_t GetInitialMax() const;

    // Increments progress (ignored if not positive).
    // Returns `true` if the max progress increased as well.
    bool Inc(int32_t delta);

    // Persist the stats.
    void Save();

    void Dump(int fd, const std::string& prefix) const;

  private:
    Progress(int32_t initial_max, float growth_factor,
             const std::string& path = "");                                // Used by test cases.
    Progress(int32_t initial_max, int32_t progress, float growth_factor);  // Used by test cases.
    void Load();
    int32_t initial_max_;
    int32_t progress_;
    int32_t max_;
    float growth_factor_;
    int32_t n_runs_;
    int32_t average_max_;
    std::string path_;
};

/*
 * List of supported zip format versions.
 *
 * See bugreport-format.md for more info.
 */
static std::string VERSION_CURRENT = "2.0";

/*
 * Temporary version that adds a anr-traces.txt entry. Once tools support it, the current version
 * will be bumped to 3.0.
 */
static std::string VERSION_SPLIT_ANR = "3.0-dev-split-anr";

/*
 * "Alias" for the current version.
 */
static std::string VERSION_DEFAULT = "default";

/*
 * Directory used by Dumpstate binary to keep its local files.
 */
static const std::string DUMPSTATE_DIRECTORY = "/bugreports";

/*
 * Structure that contains the information of an open dump file.
 */
struct DumpData {
    // Path of the file.
    std::string name;

    // Open file descriptor for the file.
    android::base::unique_fd fd;

    // Modification time of the file.
    time_t mtime;
};

/*
 * Main class driving a bugreport generation.
 *
 * Currently, it only contains variables that are accessed externally, but gradually the functions
 * that are spread accross utils.cpp and dumpstate.cpp will be moved to it.
 */
class Dumpstate {
    friend class android::os::dumpstate::DumpstateTest;
    friend class android::os::dumpstate::ZippedBugReportStreamTest;

  public:
    enum RunStatus { OK, HELP, INVALID_INPUT, ERROR, USER_CONSENT_DENIED, USER_CONSENT_TIMED_OUT };

    // The mode under which the bugreport should be run. Each mode encapsulates a few options.
    enum BugreportMode {
        BUGREPORT_FULL = android::os::IDumpstate::BUGREPORT_MODE_FULL,
        BUGREPORT_INTERACTIVE = android::os::IDumpstate::BUGREPORT_MODE_INTERACTIVE,
        BUGREPORT_REMOTE = android::os::IDumpstate::BUGREPORT_MODE_REMOTE,
        BUGREPORT_WEAR = android::os::IDumpstate::BUGREPORT_MODE_WEAR,
        BUGREPORT_TELEPHONY = android::os::IDumpstate::BUGREPORT_MODE_TELEPHONY,
        BUGREPORT_WIFI = android::os::IDumpstate::BUGREPORT_MODE_WIFI,
        BUGREPORT_DEFAULT = android::os::IDumpstate::BUGREPORT_MODE_DEFAULT
    };

    static android::os::dumpstate::CommandOptions DEFAULT_DUMPSYS;

    static Dumpstate& GetInstance();

    /* Checkes whether dumpstate is generating a zipped bugreport. */
    bool IsZipping() const;

    /* Initialize dumpstate fields before starting bugreport generation */
    void Initialize();

    /*
     * Forks a command, waits for it to finish, and returns its status.
     *
     * |title| description of the command printed on `stdout` (or empty to skip
     * description).
     * |full_command| array containing the command (first entry) and its arguments.
     * Must contain at least one element.
     * |options| optional argument defining the command's behavior.
     * |out_fd| A fd to support the DumpPool to output results to a temporary
     * file. Using STDOUT_FILENO if it's not running in the parallel task.
     */
    int RunCommand(const std::string& title, const std::vector<std::string>& fullCommand,
                   const android::os::dumpstate::CommandOptions& options =
                       android::os::dumpstate::CommandOptions::DEFAULT,
                   bool verbose_duration = false, int out_fd = STDOUT_FILENO);

    /*
     * Runs `dumpsys` with the given arguments, automatically setting its timeout
     * (`-T` argument)
     * according to the command options.
     *
     * |title| description of the command printed on `stdout` (or empty to skip
     * description).
     * |dumpsys_args| `dumpsys` arguments (except `-t`).
     * |options| optional argument defining the command's behavior.
     * |dumpsys_timeout| when > 0, defines the value passed to `dumpsys -T` (otherwise it uses the
     * timeout from `options`)
     * |out_fd| A fd to support the DumpPool to output results to a temporary
     * file. Using STDOUT_FILENO if it's not running in the parallel task.
     */
    void RunDumpsys(const std::string& title, const std::vector<std::string>& dumpsys_args,
                    const android::os::dumpstate::CommandOptions& options = DEFAULT_DUMPSYS,
                    long dumpsys_timeout_ms = 0, int out_fd = STDOUT_FILENO);

    /*
     * Prints the contents of a file.
     *
     * |title| description of the command printed on `stdout` (or empty to skip
     * description).
     * |path| location of the file to be dumped.
     */
    int DumpFile(const std::string& title, const std::string& path);

    /*
     * Adds a new entry to the existing zip file.
     * */
    bool AddZipEntry(const std::string& entry_name, const std::string& entry_path);

    /*
     * Adds a new entry to the existing zip file.
     *
     * |entry_name| destination path of the new entry.
     * |fd| file descriptor to read from.
     * |timeout| timeout to terminate the read if not completed. Set
     * value of 0s (default) to disable timeout.
     */
    android::status_t AddZipEntryFromFd(const std::string& entry_name, int fd,
                                        std::chrono::milliseconds timeout);

    /*
     * Adds a text entry to the existing zip file.
     */
    bool AddTextZipEntry(const std::string& entry_name, const std::string& content);

    /*
     * Adds all files from a directory to the zipped bugreport file.
     */
    void AddDir(const std::string& dir, bool recursive);

    /*
     * Takes a screenshot and save it to the given `path`.
     *
     * If `path` is empty, uses a standard path based on the bugreport name.
     */
    void TakeScreenshot(const std::string& path = "");

    /////////////////////////////////////////////////////////////////////
    // TODO: members below should be private once refactor is finished //
    /////////////////////////////////////////////////////////////////////

    // TODO: temporary method until Dumpstate object is properly set
    void SetProgress(std::unique_ptr<Progress> progress);

    // Dumps Dalvik and native stack traces, sets the trace file location to path
    // if it succeeded.
    // Note that it returns early if user consent is denied with status USER_CONSENT_DENIED.
    // Returns OK in all other cases.
    RunStatus DumpTraces(const char** path);

    /*
     * |out_fd| A fd to support the DumpPool to output results to a temporary file.
     * Dumpstate can pick up later and output to the bugreport. Using STDOUT_FILENO
     * if it's not running in the parallel task.
     */
    void DumpstateBoard(int out_fd = STDOUT_FILENO);

    /*
     * Updates the overall progress of the bugreport generation by the given weight increment.
     */
    void UpdateProgress(int32_t delta);

    /* Prints the dumpstate header on `stdout`. */
    void PrintHeader() const;

    /*
     * Adds the temporary report to the existing .zip file, closes the .zip file, and removes the
     * temporary file.
     */
    bool FinishZipFile();

    /* Constructs a full path inside directory with file name formatted using the given suffix. */
    std::string GetPath(const std::string& directory, const std::string& suffix) const;

    /* Constructs a full path inside bugreport_internal_dir_ with file name formatted using the
     * given suffix. */
    std::string GetPath(const std::string& suffix) const;

    /* Returns true if the current version supports priority dump feature. */
    bool CurrentVersionSupportsPriorityDumps() const;

    struct DumpOptions;

    /*
     * Main entry point for running a complete bugreport.
     *
     * Initialize() dumpstate before calling this method.
     *
     */
    RunStatus Run(int32_t calling_uid, const std::string& calling_package);

    RunStatus ParseCommandlineAndRun(int argc, char* argv[]);

    /* Deletes in-progress files */
    void Cancel();

    /* Sets runtime options. */
    void SetOptions(std::unique_ptr<DumpOptions> options);

    /*
     * Returns true if user consent is necessary and has been denied.
     * Consent is only necessary if the caller has asked to copy over the bugreport to a file they
     * provided.
     */
    bool IsUserConsentDenied() const;

    /*
     * Returns true if dumpstate is called by bugreporting API
     */
    bool CalledByApi() const;

    /*
     * Enqueues a task to the dumpstate's TaskQueue if the parallel run is enabled,
     * otherwise invokes it immediately. The task adds file at path entry_path
     * as a zip file entry with name entry_name. Unlinks entry_path when done.
     *
     * All enqueued tasks will be executed in the dumpstate's FinishZipFile method
     * before the zip file is finished. Tasks will be cancelled in dumpstate's
     * ShutdownDumpPool method if they have never been called.
     */
    void EnqueueAddZipEntryAndCleanupIfNeeded(const std::string& entry_name,
            const std::string& entry_path);

    /*
     * Structure to hold options that determine the behavior of dumpstate.
     */
    struct DumpOptions {
        bool do_vibrate = true;
        // Writes bugreport zipped file to a socket.
        bool stream_to_socket = false;
        // Writes generation progress updates to a socket.
        bool progress_updates_to_socket = false;
        bool do_screenshot = false;
        bool is_screenshot_copied = false;
        bool is_remote_mode = false;
        bool show_header_only = false;
        bool telephony_only = false;
        bool wifi_only = false;
        // Trimmed-down version of dumpstate to only include whitelisted logs.
        bool limited_only = false;
        // Whether progress updates should be published.
        bool do_progress_updates = false;
        // The mode we'll use when calling IDumpstateDevice::dumpstateBoard.
        // TODO(b/148168577) get rid of the AIDL values, replace them with the HAL values instead.
        // The HAL is actually an API surface that can be validated, while the AIDL is not (@hide).
        ::android::hardware::dumpstate::V1_1::DumpstateMode dumpstate_hal_mode =
            ::android::hardware::dumpstate::V1_1::DumpstateMode::DEFAULT;
        // File descriptor to output zip file. Takes precedence over out_dir.
        android::base::unique_fd bugreport_fd;
        // File descriptor to screenshot file.
        android::base::unique_fd screenshot_fd;
        // Custom output directory.
        std::string out_dir;
        // Bugreport mode of the bugreport.
        std::string bugreport_mode;
        // Command-line arguments as string
        std::string args;
        // Notification title and description
        std::string notification_title;
        std::string notification_description;

        /* Initializes options from commandline arguments. */
        RunStatus Initialize(int argc, char* argv[]);

        /* Initializes options from the requested mode. */
        void Initialize(BugreportMode bugreport_mode, const android::base::unique_fd& bugreport_fd,
                        const android::base::unique_fd& screenshot_fd,
                        bool is_screenshot_requested);

        /* Returns true if the options set so far are consistent. */
        bool ValidateOptions() const;

        /* Returns if options specified require writing to custom file location */
        bool OutputToCustomFile() {
            // Custom location is only honored in limited mode.
            return limited_only && !out_dir.empty() && bugreport_fd.get() == -1;
        }
    };

    // TODO: initialize fields on constructor
    // dumpstate id - unique after each device reboot.
    uint32_t id_;

    // dumpstate pid
    pid_t pid_;

    // Runtime options.
    std::unique_ptr<DumpOptions> options_;

    // Last progress that was sent to the listener [0-100].
    int last_reported_percent_progress_ = 0;

    // Whether it should take an screenshot earlier in the process.
    bool do_early_screenshot_ = false;

    // This is set to true when the trace snapshot request in the early call to
    // MaybeSnapshotSystemTrace(). When this is true, the later stages of
    // dumpstate will append the trace to the zip archive.
    bool has_system_trace_ = false;

    std::unique_ptr<Progress> progress_;

    // When set, defines a socket file-descriptor use to report progress to bugreportz
    // or to stream the zipped file to.
    int control_socket_fd_ = -1;

    // Bugreport format version;
    std::string version_ = VERSION_CURRENT;

    time_t now_;

    // Base name (without suffix or extensions) of the bugreport files, typically
    // `bugreport-BUILD_ID`.
    std::string base_name_;

    // Name is the suffix part of the bugreport files - it's typically the date,
    // but it could be changed by the user..
    std::string name_;

    std::string bugreport_internal_dir_ = DUMPSTATE_DIRECTORY;

    // Full path of the temporary file containing the bugreport, inside bugreport_internal_dir_.
    // At the very end this file is pulled into the zip file.
    std::string tmp_path_;

    // Full path of the file containing the dumpstate logs, inside bugreport_internal_dir_.
    // This is useful for debugging.
    std::string log_path_;

    // Full path of the bugreport file, be it zip or text, inside bugreport_internal_dir_.
    std::string path_;

    // Full path of the file containing the screenshot (when requested).
    std::string screenshot_path_;

    // Pointer to the zipped file.
    std::unique_ptr<FILE, int (*)(FILE*)> zip_file{nullptr, fclose};

    // Pointer to the zip structure.
    std::unique_ptr<ZipWriter> zip_writer_;

    // Binder object listening to progress.
    android::sp<android::os::IDumpstateListener> listener_;

    // List of open tombstone dump files.
    std::vector<DumpData> tombstone_data_;

    // List of open ANR dump files.
    std::vector<DumpData> anr_data_;

    // A thread pool to execute dump tasks simultaneously if the parallel run is enabled.
    std::unique_ptr<android::os::dumpstate::DumpPool> dump_pool_;

    // A task queue to collect adding zip entry tasks inside dump tasks if the
    // parallel run is enabled.
    std::unique_ptr<android::os::dumpstate::TaskQueue> zip_entry_tasks_;

    // A callback to IncidentCompanion service, which checks user consent for sharing the
    // bugreport with the calling app. If the user has not responded yet to the dialog it will
    // be neither confirmed nor denied.
    class ConsentCallback : public android::os::BnIncidentAuthListener {
      public:
        ConsentCallback();
        android::binder::Status onReportApproved() override;
        android::binder::Status onReportDenied() override;

        enum ConsentResult { APPROVED, DENIED, UNAVAILABLE };

        ConsentResult getResult();

        // Returns the time since creating this listener
        uint64_t getElapsedTimeMs() const;

      private:
        ConsentResult result_;
        uint64_t start_time_;
        std::mutex lock_;
    };

  private:
    RunStatus RunInternal(int32_t calling_uid, const std::string& calling_package);

    RunStatus DumpstateDefaultAfterCritical();

    void MaybeTakeEarlyScreenshot();
    void MaybeSnapshotSystemTrace();
    void MaybeSnapshotWinTrace();

    void onUiIntensiveBugreportDumpsFinished(int32_t calling_uid);

    void MaybeCheckUserConsent(int32_t calling_uid, const std::string& calling_package);

    // Removes the in progress files output files (tmp file, zip/txt file, screenshot),
    // but leaves the log file alone.
    void CleanupTmpFiles();

    // Create the thread pool to enable the parallel run function.
    void EnableParallelRunIfNeeded();
    void ShutdownDumpPool();

    RunStatus HandleUserConsentDenied();

    // Copies bugreport artifacts over to the caller's directories provided there is user consent or
    // called by Shell.
    RunStatus CopyBugreportIfUserConsented(int32_t calling_uid);

    std::function<int(const char *)> open_socket_fn_;

    // Used by GetInstance() only.
    explicit Dumpstate(const std::string& version = VERSION_CURRENT);

    android::sp<ConsentCallback> consent_callback_;

    std::recursive_mutex mutex_;

    DISALLOW_COPY_AND_ASSIGN(Dumpstate);
};

// for_each_pid_func = void (*)(int, const char*);
// for_each_tid_func = void (*)(int, int, const char*);

typedef void(for_each_pid_func)(int, const char*);
typedef void(for_each_tid_func)(int, int, const char*);

/* saves the the contents of a file as a long */
int read_file_as_long(const char *path, long int *output);

/* prints the contents of the fd
 * fd must have been opened with the flag O_NONBLOCK.
 */
int dump_file_from_fd(const char *title, const char *path, int fd);

/* calls skip to gate calling dump_from_fd recursively
 * in the specified directory. dump_from_fd defaults to
 * dump_file_from_fd above when set to NULL. skip defaults
 * to false when set to NULL. dump_from_fd will always be
 * called with title NULL.
 */
int dump_files(const std::string& title, const char* dir, bool (*skip)(const char* path),
               int (*dump_from_fd)(const char* title, const char* path, int fd));

/*
 * Redirects 'redirect' to a file indicated by 'path', truncating it.
 *
 * Returns true if redirect succeeds.
 */
bool redirect_to_file(FILE* redirect, char* path);

/*
 * Redirects 'redirect' to an existing file indicated by 'path', appending it.
 *
 * Returns true if redirect succeeds.
 */
bool redirect_to_existing_file(FILE* redirect, char* path);

/* create leading directories, if necessary */
void create_parent_dirs(const char *path);

/* for each process in the system, run the specified function */
void for_each_pid(for_each_pid_func func, const char *header);

/* for each thread in the system, run the specified function */
void for_each_tid(for_each_tid_func func, const char *header);

/* Displays a blocked processes in-kernel wait channel */
void show_wchan(int pid, int tid, const char *name);

/* Displays a processes times */
void show_showtime(int pid, const char *name);

/* Runs "showmap" for a process */
void do_showmap(int pid, const char *name);

/* Gets the dmesg output for the kernel */
void do_dmesg();

/* Prints the contents of all the routing tables, both IPv4 and IPv6. */
void dump_route_tables();

/* Dump subdirectories of cgroupfs if the corresponding process is frozen */
void dump_frozen_cgroupfs();

/* Play a sound via Stagefright */
void play_sound(const char *path);

/* Checks if a given path is a directory. */
bool is_dir(const char* pathname);

/** Gets the last modification time of a file, or default time if file is not found. */
time_t get_mtime(int fd, time_t default_mtime);

/** Gets command-line arguments. */
void format_args(int argc, const char *argv[], std::string *args);

/** Main entry point for dumpstate. */
int run_main(int argc, char* argv[]);

#ifdef __cplusplus
}
#endif

#endif /* FRAMEWORK_NATIVE_CMD_DUMPSTATE_H_ */
