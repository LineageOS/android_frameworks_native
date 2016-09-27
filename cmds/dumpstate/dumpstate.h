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

#ifndef MYLOGD
#define MYLOGD(...) fprintf(stderr, __VA_ARGS__); ALOGD(__VA_ARGS__);
#endif

#ifndef MYLOGI
#define MYLOGI(...) fprintf(stderr, __VA_ARGS__); ALOGI(__VA_ARGS__);
#endif

#ifndef MYLOGE
#define MYLOGE(...) fprintf(stderr, __VA_ARGS__); ALOGE(__VA_ARGS__);
#endif

#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>

#include <string>
#include <vector>

#define SU_PATH "/system/xbin/su"

// Workaround for const char *args[MAX_ARGS_ARRAY_SIZE] variables until they're converted to
// std::vector<std::string>
// TODO: remove once not used
#define MAX_ARGS_ARRAY_SIZE 1000

// TODO: remove once moved to HAL
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Defines the Linux user that should be executing a command.
 */
enum RootMode {
    /* Explicitly change the `uid` and `gid` to be `shell`.*/
    DROP_ROOT,
    /* Don't change the `uid` and `gid`. */
    DONT_DROP_ROOT,
    /* Prefix the command with `/PATH/TO/su root`. Won't work non user builds. */
    SU_ROOT
};

/*
 * Defines what should happen with the `stdout` stream of a command.
 */
enum StdoutMode {
    /* Don't change `stdout`. */
    NORMAL_STDOUT,
    /* Redirect `stdout` to `stderr`. */
    REDIRECT_TO_STDERR
};

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
    DurationReporter(const char* title);
    DurationReporter(const char* title, FILE* out);

    ~DurationReporter();

    static uint64_t Nanotime();

  private:
    // TODO: use std::string for title, once dump_files() and other places that pass a char* are
    // refactored as well.
    const char* title_;
    FILE* out_;
    uint64_t started_;
};

/*
 * Value object used to set command options.
 *
 * Typically constructed using a builder with chained setters. Examples:
 *
 *  CommandOptions::WithTimeout(20).AsRoot().Build();
 *  CommandOptions::WithTimeout(10).Always().RedirectStderr().Build();
 *
 * Although the builder could be used to dynamically set values. Example:
 *
 *  CommandOptions::CommandOptionsBuilder options =
 *  CommandOptions::WithTimeout(10);
 *  if (!is_user_build()) {
 *    options.AsRoot();
 *  }
 *  RunCommand("command", {"args"}, options.Build());
 */
class CommandOptions {
  private:
    class CommandOptionsValues {
      private:
        CommandOptionsValues(long timeout);

        long timeout_;
        bool always_;
        RootMode rootMode_;
        StdoutMode stdoutMode_;
        std::string loggingMessage_;

        friend class CommandOptions;
        friend class CommandOptionsBuilder;
    };

    CommandOptions(const CommandOptionsValues& values);

    const CommandOptionsValues values_;

  public:
    class CommandOptionsBuilder {
      public:
        /* Sets the command to always run, even on `dry-run` mode. */
        CommandOptionsBuilder& Always();
        /* Sets the command's RootMode as `SU_ROOT` */
        CommandOptionsBuilder& AsRoot();
        /* Sets the command's RootMode as `DROP_ROOT` */
        CommandOptionsBuilder& DropRoot();
        /* Sets the command's StdoutMode `REDIRECT_TO_STDERR` */
        CommandOptionsBuilder& RedirectStderr();
        /* When not empty, logs a message before executing the command.
         * Must contain a `%s`, which will be replaced by the full command line, and end on `\n`. */
        CommandOptionsBuilder& Log(const std::string& message);
        /* Builds the command options. */
        CommandOptions Build();

      private:
        CommandOptionsBuilder(long timeout);
        CommandOptionsValues values_;
        friend class CommandOptions;
    };

    /** Gets the command timeout, in seconds. */
    long Timeout() const;
    /* Checks whether the command should always be run, even on dry-run mode. */
    bool Always() const;
    /** Gets the RootMode of the command. */
    RootMode RootMode() const;
    /** Gets the StdoutMode of the command. */
    StdoutMode StdoutMode() const;
    /** Gets the logging message header, it any. */
    std::string LoggingMessage() const;

    /** Creates a builder with the requied timeout. */
    static CommandOptionsBuilder WithTimeout(long timeout);

    // Common options.
    static CommandOptions DEFAULT;
    static CommandOptions DEFAULT_DUMPSYS;
    static CommandOptions AS_ROOT_5;
    static CommandOptions AS_ROOT_10;
    static CommandOptions AS_ROOT_20;
};

typedef void (for_each_pid_func)(int, const char *);
typedef void (for_each_tid_func)(int, int, const char *);

/* Estimated total weight of bugreport generation.
 *
 * Each section contributes to the total weight by an individual weight, so the overall progress
 * can be calculated by dividing the all completed weight by the total weight.
 *
 * This value is defined empirically and it need to be adjusted as more sections are added.
 *
 * It does not need to match the exact sum of all sections, but ideally it should to be slight more
 * than such sum: a value too high will cause the bugreport to finish before the user expected (for
 * example, jumping from 70% to 100%), while a value too low will cause the progress to get stuck
 * at an almost-finished value (like 99%) for a while.
 */
static const int WEIGHT_TOTAL = 6500;

/* Most simple commands have 10 as timeout, so 5 is a good estimate */
static const int WEIGHT_FILE = 5;

/*
 * TODO: the dumpstate internal state is getting fragile; for example, this variable is defined
 * here, declared at utils.cpp, and used on utils.cpp and dumpstate.cpp.
 * It would be better to take advantage of the C++ migration and encapsulate the state in an object,
 * but that will be better handled in a major C++ refactoring, which would also get rid of other C
 * idioms (like using std::string instead of char*, removing varargs, etc...) */
extern int do_update_progress, progress, weight_total, control_socket_fd;

/* full path of the directory where the bugreport files will be written */
extern std::string bugreport_dir;

/* root dir for all files copied as-is into the bugreport. */
extern const std::string ZIP_ROOT_DIR;

/* adds a new entry to the existing zip file. */
bool add_zip_entry(const std::string& entry_name, const std::string& entry_path);

/* adds a new entry to the existing zip file. */
bool add_zip_entry_from_fd(const std::string& entry_name, int fd);

/* adds all files from a directory to the zipped bugreport file */
void add_dir(const char *dir, bool recursive);

/* prints the contents of a file
 * DEPRECATED: will be removed once device-specific implementations use
 * dumpFile */
int dump_file(const char *title, const char *path);

/* Prints the contents of a file. */
// TODO: use std::string for title once other char* title references are refactored.
int DumpFile(const char* title, const std::string& path);

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
int dump_files(const char *title, const char *dir,
        bool (*skip)(const char *path),
        int (*dump_from_fd)(const char *title, const char *path, int fd));

/* forks a command and waits for it to finish -- terminate args with NULL
 * DEPRECATED: will be removed once device-specific implementations use
 * runCommand */
int run_command(const char *title, int timeout_seconds, const char *command, ...);

/*
 * Forks a command, waits for it to finish, and returns its status.
 *
 * |title| description of the command printed on `stdout` (or `nullptr` to skip
 * description).
 * |full_command| array containing the command (first entry) and its arguments.
 * Must contain at least one element.
 * |options| optional argument defining the command's behavior.
 */
// TODO: use std::string for title once other char* title references are refactored.
int RunCommand(const char* title, const std::vector<std::string>& fullCommand,
               const CommandOptions& options = CommandOptions::DEFAULT);

/*
 * Runs `dumpsys` with the given arguments, automatically setting its timeout
 * (`-t` argument)
 * according to the command options.
 *
 * |title| description of the command printed on `stdout`.
 * |dumpsys_args| `dumpsys` arguments (except `-t`).
 * |options| optional argument defining the command's behavior.
 */
void RunDumpsys(const std::string& title, const std::vector<std::string>& dumpsysArgs,
                const CommandOptions& options = CommandOptions::DEFAULT_DUMPSYS);

/* switch to non-root user and group */
bool drop_root_user();

/* sends a broadcast using Activity Manager */
void send_broadcast(const std::string& action, const std::vector<std::string>& args);

/* updates the overall progress of dumpstate by the given weight increment */
void update_progress(int weight);

/* prints all the system properties */
void print_properties();

/** opens a socket and returns its file descriptor */
int open_socket(const char *service);

/* redirect output to a service control socket */
void redirect_to_socket(FILE *redirect, const char *service);

/* redirect output to a new file */
void redirect_to_file(FILE *redirect, char *path);

/* redirect output to an existing file */
void redirect_to_existing_file(FILE *redirect, char *path);

/* create leading directories, if necessary */
void create_parent_dirs(const char *path);

/* dump Dalvik and native stack traces, return the trace file location (NULL if none) */
const char *dump_traces();

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

/* Play a sound via Stagefright */
void play_sound(const char *path);

/* Implemented by libdumpstate_board to dump board-specific info */
void dumpstate_board();

/* Takes a screenshot and save it to the given file */
void take_screenshot(const std::string& path);

/* Vibrates for a given durating (in milliseconds). */
void vibrate(FILE* vibrator, int ms);

/* Checks if a given path is a directory. */
bool is_dir(const char* pathname);

/** Gets the last modification time of a file, or default time if file is not found. */
time_t get_mtime(int fd, time_t default_mtime);

/* Dumps eMMC Extended CSD data. */
void dump_emmc_ecsd(const char *ext_csd_path);

/** Gets command-line arguments. */
void format_args(int argc, const char *argv[], std::string *args);

/** Tells if the device is running a user build. */
bool is_user_build();

/*
 * When running in dry-run mode, skips the real dumps and just print the section headers.
 *
 * Useful when debugging dumpstate or other bugreport-related activities.
 *
 * Dry-run mode is enabled by setting the system property dumpstate.dry_run to true.
 */
bool is_dry_run();

#ifdef __cplusplus
}
#endif

#endif /* FRAMEWORK_NATIVE_CMD_DUMPSTATE_H_ */
