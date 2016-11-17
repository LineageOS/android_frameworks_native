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
#ifndef FRAMEWORK_NATIVE_CMD_DUMPSTATE_UTIL_H_
#define FRAMEWORK_NATIVE_CMD_DUMPSTATE_UTIL_H_

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
        CommandOptionsValues(int64_t timeout);

        int64_t timeout_;
        bool always_;
        RootMode root_mode_;
        StdoutMode stdout_mode_;
        std::string logging_message_;

        friend class CommandOptions;
        friend class CommandOptionsBuilder;
    };

    CommandOptions(const CommandOptionsValues& values);

    const CommandOptionsValues values;

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
        CommandOptionsBuilder(int64_t timeout);
        CommandOptionsValues values;
        friend class CommandOptions;
    };

    /** Gets the command timeout, in seconds. */
    int64_t Timeout() const;
    /* Checks whether the command should always be run, even on dry-run mode. */
    bool Always() const;
    /** Gets the RootMode of the command. */
    RootMode RootMode() const;
    /** Gets the StdoutMode of the command. */
    StdoutMode StdoutMode() const;
    /** Gets the logging message header, it any. */
    std::string LoggingMessage() const;

    /** Creates a builder with the requied timeout. */
    static CommandOptionsBuilder WithTimeout(int64_t timeout);

    // Common options.
    static CommandOptions DEFAULT;
    static CommandOptions AS_ROOT_5;
    static CommandOptions AS_ROOT_10;
    static CommandOptions AS_ROOT_20;
};

/*
 * Forks a command, waits for it to finish, and returns its status.
 *
 * |fd| file descriptor that receives the command's 'stdout'.
 * |full_command| array containing the command (first entry) and its arguments.
 * Must contain at least one element.
 * |options| optional argument defining the command's behavior.
 * |description| optional description of the command to be used on log messages. If empty,
 * the command path (without arguments) will be used instead.
 */
int RunCommandToFd(int fd, const std::vector<const char*>& full_command,
                   const CommandOptions& options = CommandOptions::DEFAULT,
                   const std::string& description = "");

/*
 * Dumps the contents of a file into a file descriptor.
 *
 * |fd| file descriptor where the file is dumped into.
 * |path| location of the file to be dumped.
 */
int DumpFileToFd(int fd, const std::string& path);

#endif  // FRAMEWORK_NATIVE_CMD_DUMPSTATE_UTIL_H_
