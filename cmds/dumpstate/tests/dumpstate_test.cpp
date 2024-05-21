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

#define LOG_TAG "dumpstate_test"

#include "dumpstate.h"

#include <aidl/android/hardware/dumpstate/IDumpstateDevice.h>
#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <android/hardware/dumpstate/1.1/types.h>
#include <android_tracing.h>
#include <cutils/log.h>
#include <cutils/properties.h>
#include <fcntl.h>
#include <gmock/gmock-matchers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libgen.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <ziparchive/zip_archive.h>

#include <filesystem>
#include <thread>

#include "DumpPool.h"
#include "DumpstateInternal.h"
#include "DumpstateService.h"
#include "android/os/BnDumpstate.h"

namespace android {
namespace os {
namespace dumpstate {

using DumpstateDeviceAidl = ::aidl::android::hardware::dumpstate::IDumpstateDevice;
using ::android::hardware::dumpstate::V1_1::DumpstateMode;
using ::testing::EndsWith;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::IsNull;
using ::testing::NotNull;
using ::testing::StartsWith;
using ::testing::StrEq;
using ::testing::Test;
using ::testing::internal::CaptureStderr;
using ::testing::internal::CaptureStdout;
using ::testing::internal::GetCapturedStderr;
using ::testing::internal::GetCapturedStdout;

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

class DumpstateListenerMock : public IDumpstateListener {
  public:
    MOCK_METHOD1(onProgress, binder::Status(int32_t progress));
    MOCK_METHOD1(onError, binder::Status(int32_t error_code));
    MOCK_METHOD1(onFinished, binder::Status(const std::string& bugreport_file));
    MOCK_METHOD1(onScreenshotTaken, binder::Status(bool success));
    MOCK_METHOD0(onUiIntensiveBugreportDumpsFinished, binder::Status());

  protected:
    MOCK_METHOD0(onAsBinder, IBinder*());
};

static int calls_;

// Base class for all tests in this file
class DumpstateBaseTest : public Test {
  public:
    virtual void SetUp() override {
        calls_++;
        SetDryRun(false);
    }

    void SetDryRun(bool dry_run) const {
        PropertiesHelper::dry_run_ = dry_run;
    }

    void SetBuildType(const std::string& build_type) const {
        PropertiesHelper::build_type_ = build_type;
    }

    void SetUnroot(bool unroot) const {
        PropertiesHelper::unroot_ = unroot;
    }

    void SetParallelRun(bool parallel_run) const {
        PropertiesHelper::parallel_run_ = parallel_run;
    }

    bool IsStandalone() const {
        return calls_ == 1;
    }

    void DropRoot() const {
        DropRootUser();
        uid_t uid = getuid();
        ASSERT_EQ(2000, (int)uid);
    }

  protected:
    const std::string kTestPath = dirname(android::base::GetExecutablePath().c_str());
    const std::string kTestDataPath = kTestPath + "/tests/testdata/";
    const std::string kSimpleCommand = kTestPath + "/dumpstate_test_fixture";
    const std::string kEchoCommand = "/system/bin/echo";

    /*
     * Copies a text file fixture to a temporary file, returning it's path.
     *
     * Useful in cases where the test case changes the content of the tile.
     */
    std::string CopyTextFileFixture(const std::string& relative_name) {
        std::string from = kTestDataPath + relative_name;
        // Not using TemporaryFile because it's deleted at the end, and it's useful to keep it
        // around for poking when the test fails.
        std::string to = kTestDataPath + relative_name + ".tmp";
        ALOGD("CopyTextFileFixture: from %s to %s\n", from.c_str(), to.c_str());
        android::base::RemoveFileIfExists(to);
        CopyTextFile(from, to);
        return to.c_str();
    }

    // Need functions that returns void to use assertions -
    // https://github.com/google/googletest/blob/master/googletest/docs/AdvancedGuide.md#assertion-placement
    void ReadFileToString(const std::string& path, std::string* content) {
        ASSERT_TRUE(android::base::ReadFileToString(path, content))
            << "could not read contents from " << path;
    }
    void WriteStringToFile(const std::string& content, const std::string& path) {
        ASSERT_TRUE(android::base::WriteStringToFile(content, path))
            << "could not write contents to " << path;
    }

  private:
    void CopyTextFile(const std::string& from, const std::string& to) {
        std::string content;
        ReadFileToString(from, &content);
        WriteStringToFile(content, to);
    }
};

class DumpOptionsTest : public Test {
  public:
    virtual ~DumpOptionsTest() {
    }
    virtual void SetUp() {
        options_ = Dumpstate::DumpOptions();
    }
    void TearDown() {
    }
    Dumpstate::DumpOptions options_;
    android::base::unique_fd fd;
};

TEST_F(DumpOptionsTest, InitializeNone) {
    // clang-format off
    char* argv[] = {
        const_cast<char*>("dumpstate")
    };
    // clang-format on

    Dumpstate::RunStatus status = options_.Initialize(ARRAY_SIZE(argv), argv);

    EXPECT_EQ(status, Dumpstate::RunStatus::OK);

    EXPECT_EQ("", options_.out_dir);
    EXPECT_FALSE(options_.stream_to_socket);
    EXPECT_FALSE(options_.progress_updates_to_socket);
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_TRUE(options_.do_vibrate);
    EXPECT_FALSE(options_.do_screenshot);
    EXPECT_FALSE(options_.do_progress_updates);
    EXPECT_FALSE(options_.is_remote_mode);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializeAdbBugreport) {
    // clang-format off
    char* argv[] = {
        const_cast<char*>("dumpstatez"),
        const_cast<char*>("-S"),
    };
    // clang-format on

    Dumpstate::RunStatus status = options_.Initialize(ARRAY_SIZE(argv), argv);

    EXPECT_EQ(status, Dumpstate::RunStatus::OK);
    EXPECT_TRUE(options_.progress_updates_to_socket);

    // Other options retain default values
    EXPECT_TRUE(options_.do_vibrate);
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_FALSE(options_.do_screenshot);
    EXPECT_FALSE(options_.do_progress_updates);
    EXPECT_FALSE(options_.is_remote_mode);
    EXPECT_FALSE(options_.stream_to_socket);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializeAdbShellBugreport) {
    // clang-format off
    char* argv[] = {
        const_cast<char*>("dumpstate"),
        const_cast<char*>("-s"),
    };
    // clang-format on

    Dumpstate::RunStatus status = options_.Initialize(ARRAY_SIZE(argv), argv);

    EXPECT_EQ(status, Dumpstate::RunStatus::OK);
    EXPECT_TRUE(options_.stream_to_socket);

    // Other options retain default values
    EXPECT_TRUE(options_.do_vibrate);
    EXPECT_FALSE(options_.progress_updates_to_socket);
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_FALSE(options_.do_screenshot);
    EXPECT_FALSE(options_.do_progress_updates);
    EXPECT_FALSE(options_.is_remote_mode);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializeFullBugReport) {
    options_.Initialize(Dumpstate::BugreportMode::BUGREPORT_FULL, 0, fd, fd, true, false);
    EXPECT_TRUE(options_.do_screenshot);

    // Other options retain default values
    EXPECT_TRUE(options_.do_vibrate);
    EXPECT_FALSE(options_.progress_updates_to_socket);
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_FALSE(options_.do_progress_updates);
    EXPECT_FALSE(options_.is_remote_mode);
    EXPECT_FALSE(options_.stream_to_socket);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializeInteractiveBugReport) {
    options_.Initialize(Dumpstate::BugreportMode::BUGREPORT_INTERACTIVE, 0, fd, fd, true, false);
    EXPECT_TRUE(options_.do_progress_updates);
    EXPECT_TRUE(options_.do_screenshot);

    // Other options retain default values
    EXPECT_TRUE(options_.do_vibrate);
    EXPECT_FALSE(options_.progress_updates_to_socket);
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_FALSE(options_.is_remote_mode);
    EXPECT_FALSE(options_.stream_to_socket);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializeRemoteBugReport) {
    options_.Initialize(Dumpstate::BugreportMode::BUGREPORT_REMOTE, 0, fd, fd, false, false);
    EXPECT_TRUE(options_.is_remote_mode);
    EXPECT_FALSE(options_.do_vibrate);
    EXPECT_FALSE(options_.do_screenshot);

    // Other options retain default values
    EXPECT_FALSE(options_.progress_updates_to_socket);
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_FALSE(options_.do_progress_updates);
    EXPECT_FALSE(options_.stream_to_socket);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializeWearBugReport) {
    options_.Initialize(Dumpstate::BugreportMode::BUGREPORT_WEAR, 0, fd, fd, true, false);
    EXPECT_TRUE(options_.do_screenshot);
    EXPECT_TRUE(options_.do_progress_updates);


    // Other options retain default values
    EXPECT_FALSE(options_.progress_updates_to_socket);
    EXPECT_FALSE(options_.do_vibrate);
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_FALSE(options_.is_remote_mode);
    EXPECT_FALSE(options_.stream_to_socket);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializeTelephonyBugReport) {
    options_.Initialize(Dumpstate::BugreportMode::BUGREPORT_TELEPHONY, 0, fd, fd, false, false);
    EXPECT_FALSE(options_.do_screenshot);
    EXPECT_TRUE(options_.telephony_only);
    EXPECT_TRUE(options_.do_progress_updates);

    // Other options retain default values
    EXPECT_TRUE(options_.do_vibrate);
    EXPECT_FALSE(options_.progress_updates_to_socket);
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_FALSE(options_.is_remote_mode);
    EXPECT_FALSE(options_.stream_to_socket);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializeWifiBugReport) {
    options_.Initialize(Dumpstate::BugreportMode::BUGREPORT_WIFI, 0, fd, fd, false, false);
    EXPECT_FALSE(options_.do_screenshot);
    EXPECT_TRUE(options_.wifi_only);

    // Other options retain default values
    EXPECT_TRUE(options_.do_vibrate);
    EXPECT_FALSE(options_.progress_updates_to_socket);
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_FALSE(options_.do_progress_updates);
    EXPECT_FALSE(options_.is_remote_mode);
    EXPECT_FALSE(options_.stream_to_socket);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializeLimitedOnlyBugreport) {
    // clang-format off
    char* argv[] = {
        const_cast<char*>("dumpstatez"),
        const_cast<char*>("-S"),
        const_cast<char*>("-q"),
        const_cast<char*>("-L"),
        const_cast<char*>("-o abc")
    };
    // clang-format on

    Dumpstate::RunStatus status = options_.Initialize(ARRAY_SIZE(argv), argv);

    EXPECT_EQ(status, Dumpstate::RunStatus::OK);
    EXPECT_TRUE(options_.progress_updates_to_socket);
    EXPECT_FALSE(options_.do_vibrate);
    EXPECT_TRUE(options_.limited_only);
    EXPECT_EQ(" abc", std::string(options_.out_dir));

    // Other options retain default values
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_FALSE(options_.do_screenshot);
    EXPECT_FALSE(options_.do_progress_updates);
    EXPECT_FALSE(options_.is_remote_mode);
    EXPECT_FALSE(options_.stream_to_socket);
}

TEST_F(DumpOptionsTest, InitializeDefaultBugReport) {
    // default: commandline options are not overridden
    // clang-format off
    char* argv[] = {
        const_cast<char*>("bugreport"),
        const_cast<char*>("-d"),
        const_cast<char*>("-p"),
        const_cast<char*>("-z"),
    };
    // clang-format on
    Dumpstate::RunStatus status = options_.Initialize(ARRAY_SIZE(argv), argv);

    EXPECT_EQ(status, Dumpstate::RunStatus::OK);
    EXPECT_TRUE(options_.do_screenshot);

    // Other options retain default values
    EXPECT_TRUE(options_.do_vibrate);
    EXPECT_FALSE(options_.progress_updates_to_socket);
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_FALSE(options_.do_progress_updates);
    EXPECT_FALSE(options_.is_remote_mode);
    EXPECT_FALSE(options_.stream_to_socket);
    EXPECT_FALSE(options_.wifi_only);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializePartial1) {
    // clang-format off
    char* argv[] = {
        const_cast<char*>("dumpstate"),
        const_cast<char*>("-s"),
        const_cast<char*>("-S"),

    };
    // clang-format on

    Dumpstate::RunStatus status = options_.Initialize(ARRAY_SIZE(argv), argv);

    EXPECT_EQ(status, Dumpstate::RunStatus::OK);
    // TODO: Maybe we should trim the filename
    EXPECT_TRUE(options_.stream_to_socket);
    EXPECT_TRUE(options_.progress_updates_to_socket);

    // Other options retain default values
    EXPECT_FALSE(options_.show_header_only);
    EXPECT_TRUE(options_.do_vibrate);
    EXPECT_FALSE(options_.do_screenshot);
    EXPECT_FALSE(options_.do_progress_updates);
    EXPECT_FALSE(options_.is_remote_mode);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializePartial2) {
    // clang-format off
    char* argv[] = {
        const_cast<char*>("dumpstate"),
        const_cast<char*>("-v"),
        const_cast<char*>("-q"),
        const_cast<char*>("-p"),
        const_cast<char*>("-P"),
        const_cast<char*>("-R"),
    };
    // clang-format on

    Dumpstate::RunStatus status = options_.Initialize(ARRAY_SIZE(argv), argv);

    EXPECT_EQ(status, Dumpstate::RunStatus::OK);
    EXPECT_TRUE(options_.show_header_only);
    EXPECT_FALSE(options_.do_vibrate);
    EXPECT_TRUE(options_.do_screenshot);
    EXPECT_TRUE(options_.do_progress_updates);
    EXPECT_TRUE(options_.is_remote_mode);

    // Other options retain default values
    EXPECT_FALSE(options_.stream_to_socket);
    EXPECT_FALSE(options_.progress_updates_to_socket);
    EXPECT_FALSE(options_.limited_only);
}

TEST_F(DumpOptionsTest, InitializeHelp) {
    // clang-format off
    char* argv[] = {
        const_cast<char*>("dumpstate"),
        const_cast<char*>("-h")
    };
    // clang-format on

    Dumpstate::RunStatus status = options_.Initialize(ARRAY_SIZE(argv), argv);

    // -h is for help.
    EXPECT_EQ(status, Dumpstate::RunStatus::HELP);
}

TEST_F(DumpOptionsTest, InitializeUnknown) {
    // clang-format off
    char* argv[] = {
        const_cast<char*>("dumpstate"),
        const_cast<char*>("-u")  // unknown flag
    };
    // clang-format on

    Dumpstate::RunStatus status = options_.Initialize(ARRAY_SIZE(argv), argv);

    // -u is unknown.
    EXPECT_EQ(status, Dumpstate::RunStatus::INVALID_INPUT);
}

TEST_F(DumpOptionsTest, ValidateOptionsSocketUsage1) {
    options_.progress_updates_to_socket = true;
    options_.stream_to_socket = true;
    EXPECT_FALSE(options_.ValidateOptions());

    options_.stream_to_socket = false;
    EXPECT_TRUE(options_.ValidateOptions());
}

TEST_F(DumpOptionsTest, ValidateOptionsSocketUsage2) {
    options_.do_progress_updates = true;
    // Writing to socket = !writing to file.
    options_.stream_to_socket = true;
    EXPECT_FALSE(options_.ValidateOptions());

    options_.stream_to_socket = false;
    EXPECT_TRUE(options_.ValidateOptions());
}

TEST_F(DumpOptionsTest, ValidateOptionsRemoteMode) {
    options_.do_progress_updates = true;
    options_.is_remote_mode = true;
    EXPECT_FALSE(options_.ValidateOptions());

    options_.do_progress_updates = false;
    EXPECT_TRUE(options_.ValidateOptions());
}

TEST_F(DumpOptionsTest, InitializeBugreportFlags) {
    int flags = Dumpstate::BugreportFlag::BUGREPORT_USE_PREDUMPED_UI_DATA |
                Dumpstate::BugreportFlag::BUGREPORT_FLAG_DEFER_CONSENT;
    options_.Initialize(
      Dumpstate::BugreportMode::BUGREPORT_FULL, flags, fd, fd, true, false);
    EXPECT_TRUE(options_.is_consent_deferred);
    EXPECT_TRUE(options_.use_predumped_ui_data);

    options_.Initialize(
      Dumpstate::BugreportMode::BUGREPORT_FULL, 0, fd, fd, true, false);
    EXPECT_FALSE(options_.is_consent_deferred);
    EXPECT_FALSE(options_.use_predumped_ui_data);
}

class DumpstateTest : public DumpstateBaseTest {
  public:
    void SetUp() {
        DumpstateBaseTest::SetUp();
        SetDryRun(false);
        SetBuildType(android::base::GetProperty("ro.build.type", "(unknown)"));
        ds.progress_.reset(new Progress());
        ds.options_.reset(new Dumpstate::DumpOptions());
    }

    void TearDown() {
        ds.ShutdownDumpPool();
    }

    // Runs a command and capture `stdout` and `stderr`.
    int RunCommand(const std::string& title, const std::vector<std::string>& full_command,
                   const CommandOptions& options = CommandOptions::DEFAULT) {
        CaptureStdout();
        CaptureStderr();
        int status = ds.RunCommand(title, full_command, options);
        out = GetCapturedStdout();
        err = GetCapturedStderr();
        return status;
    }

    // Dumps a file and capture `stdout` and `stderr`.
    int DumpFile(const std::string& title, const std::string& path) {
        CaptureStdout();
        CaptureStderr();
        int status = ds.DumpFile(title, path);
        out = GetCapturedStdout();
        err = GetCapturedStderr();
        return status;
    }

    void SetProgress(long progress, long initial_max) {
        ds.last_reported_percent_progress_ = 0;
        ds.options_->do_progress_updates = true;
        ds.progress_.reset(new Progress(initial_max, progress, 1.2));
    }

    void EnableParallelRunIfNeeded() {
        ds.EnableParallelRunIfNeeded();
    }

    std::string GetProgressMessage(int progress, int max,
            int old_max = 0, bool update_progress = true) {
        EXPECT_EQ(progress, ds.progress_->Get()) << "invalid progress";
        EXPECT_EQ(max, ds.progress_->GetMax()) << "invalid max";

        bool max_increased = old_max > 0;

        std::string message = "";
        if (max_increased) {
            message =
                android::base::StringPrintf("Adjusting max progress from %d to %d\n", old_max, max);
        }

        if (update_progress) {
            message += android::base::StringPrintf("Setting progress: %d/%d (%d%%)\n",
                                                   progress, max, (100 * progress / max));
        }

        return message;
    }

    // `stdout` and `stderr` from the last command ran.
    std::string out, err;

    Dumpstate& ds = Dumpstate::GetInstance();
};

TEST_F(DumpstateTest, RunCommandNoArgs) {
    EXPECT_EQ(-1, RunCommand("", {}));
}

TEST_F(DumpstateTest, RunCommandNoTitle) {
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}));
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateTest, RunCommandWithTitle) {
    EXPECT_EQ(0, RunCommand("I AM GROOT", {kSimpleCommand}));
    EXPECT_THAT(err, StrEq("stderr\n"));
    // The duration may not get output, depending on how long it takes,
    // so we just check the prefix.
    EXPECT_THAT(out,
                StartsWith("------ I AM GROOT (" + kSimpleCommand + ") ------\nstdout\n"));
}

TEST_F(DumpstateTest, RunCommandWithLoggingMessage) {
    EXPECT_EQ(
        0, RunCommand("", {kSimpleCommand},
                      CommandOptions::WithTimeout(10).Log("COMMAND, Y U NO LOG FIRST?").Build()));
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("COMMAND, Y U NO LOG FIRST?stderr\n"));
}

TEST_F(DumpstateTest, RunCommandRedirectStderr) {
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand},
                            CommandOptions::WithTimeout(10).RedirectStderr().Build()));
    EXPECT_THAT(out, IsEmpty());
    EXPECT_THAT(err, StrEq("stdout\nstderr\n"));
}

TEST_F(DumpstateTest, RunCommandWithOneArg) {
    EXPECT_EQ(0, RunCommand("", {kEchoCommand, "one"}));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("one\n"));
}

TEST_F(DumpstateTest, RunCommandWithMultipleArgs) {
    EXPECT_EQ(0, RunCommand("", {kEchoCommand, "one", "is", "the", "loniest", "number"}));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("one is the loniest number\n"));
}

TEST_F(DumpstateTest, RunCommandDryRun) {
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("I AM GROOT", {kSimpleCommand}));
    // The duration may not get output, depending on how long it takes,
    // so we just check the prefix.
    EXPECT_THAT(out, StartsWith("------ I AM GROOT (" + kSimpleCommand +
                                ") ------\n\t(skipped on dry run)\n"));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateTest, RunCommandDryRunNoTitle) {
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}));
    EXPECT_THAT(out, IsEmpty());
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateTest, RunCommandDryRunAlways) {
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}, CommandOptions::WithTimeout(10).Always().Build()));
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateTest, RunCommandNotFound) {
    EXPECT_NE(0, RunCommand("", {"/there/cannot/be/such/command"}));
    EXPECT_THAT(out, StartsWith("*** command '/there/cannot/be/such/command' failed: exit code"));
    EXPECT_THAT(err, StartsWith("execvp on command '/there/cannot/be/such/command' failed"));
}

TEST_F(DumpstateTest, RunCommandFails) {
    EXPECT_EQ(42, RunCommand("", {kSimpleCommand, "--exit", "42"}));
    EXPECT_THAT(out, StrEq("stdout\n*** command '" + kSimpleCommand +
                           " --exit 42' failed: exit code 42\n"));
    EXPECT_THAT(err, StrEq("stderr\n*** command '" + kSimpleCommand +
                           " --exit 42' failed: exit code 42\n"));
}

TEST_F(DumpstateTest, RunCommandCrashes) {
    EXPECT_NE(0, RunCommand("", {kSimpleCommand, "--crash"}));
    // We don't know the exit code, so check just the prefix.
    EXPECT_THAT(
        out, StartsWith("stdout\n*** command '" + kSimpleCommand + " --crash' failed: exit code"));
    EXPECT_THAT(
        err, StartsWith("stderr\n*** command '" + kSimpleCommand + " --crash' failed: exit code"));
}

TEST_F(DumpstateTest, RunCommandTimesout) {
    EXPECT_EQ(-1, RunCommand("", {kSimpleCommand, "--sleep", "2"},
                             CommandOptions::WithTimeout(1).Build()));
    EXPECT_THAT(out, StartsWith("stdout line1\n*** command '" + kSimpleCommand +
                                " --sleep 2' timed out after 1"));
    EXPECT_THAT(err, StartsWith("sleeping for 2s\n*** command '" + kSimpleCommand +
                                " --sleep 2' timed out after 1"));
}

TEST_F(DumpstateTest, RunCommandIsKilled) {
    CaptureStdout();
    CaptureStderr();

    std::thread t([=]() {
        EXPECT_EQ(SIGTERM, ds.RunCommand("", {kSimpleCommand, "--pid", "--sleep", "20"},
                                         CommandOptions::WithTimeout(100).Always().Build()));
    });

    // Capture pid and pre-sleep output.
    sleep(1);  // Wait a little bit to make sure pid and 1st line were printed.
    std::string err = GetCapturedStderr();
    EXPECT_THAT(err, StrEq("sleeping for 20s\n"));

    std::string out = GetCapturedStdout();
    std::vector<std::string> lines = android::base::Split(out, "\n");
    ASSERT_EQ(3, (int)lines.size()) << "Invalid lines before sleep: " << out;

    int pid = atoi(lines[0].c_str());
    EXPECT_THAT(lines[1], StrEq("stdout line1"));
    EXPECT_THAT(lines[2], IsEmpty());  // \n

    // Then kill the process.
    CaptureStdout();
    CaptureStderr();
    ASSERT_EQ(0, kill(pid, SIGTERM)) << "failed to kill pid " << pid;
    t.join();

    // Finally, check output after murder.
    out = GetCapturedStdout();
    err = GetCapturedStderr();

    EXPECT_THAT(out, StrEq("*** command '" + kSimpleCommand +
                           " --pid --sleep 20' failed: killed by signal 15\n"));
    EXPECT_THAT(err, StrEq("*** command '" + kSimpleCommand +
                           " --pid --sleep 20' failed: killed by signal 15\n"));
}

TEST_F(DumpstateTest, RunCommandProgress) {
    sp<DumpstateListenerMock> listener(new DumpstateListenerMock());
    ds.listener_ = listener;
    SetProgress(0, 30);

    EXPECT_CALL(*listener, onProgress(66));  // 20/30 %
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}, CommandOptions::WithTimeout(20).Build()));
    std::string progress_message = GetProgressMessage(20, 30);
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n" + progress_message));

    EXPECT_CALL(*listener, onProgress(80));  // 24/30 %
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}, CommandOptions::WithTimeout(4).Build()));
    progress_message = GetProgressMessage(24, 30);
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n" + progress_message));

    // Make sure command ran while in dry_run is counted.
    SetDryRun(true);
    EXPECT_CALL(*listener, onProgress(90));  // 27/30 %
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}, CommandOptions::WithTimeout(3).Build()));
    progress_message = GetProgressMessage(27, 30);
    EXPECT_THAT(out, IsEmpty());
    EXPECT_THAT(err, StrEq(progress_message));

    SetDryRun(false);
    EXPECT_CALL(*listener, onProgress(96));  // 29/30 %
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}, CommandOptions::WithTimeout(2).Build()));
    progress_message = GetProgressMessage(29, 30);
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n" + progress_message));

    EXPECT_CALL(*listener, onProgress(100));  // 30/30 %
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}, CommandOptions::WithTimeout(1).Build()));
    progress_message = GetProgressMessage(30, 30);
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n" + progress_message));

    ds.listener_.clear();
}

TEST_F(DumpstateTest, RunCommandDropRoot) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE("Skipping DumpstateTest.RunCommandDropRoot() on test suite\n")
        return;
    }
    // First check root case - only available when running with 'adb root'.
    uid_t uid = getuid();
    if (uid == 0) {
        EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"}));
        EXPECT_THAT(out, StrEq("0\nstdout\n"));
        EXPECT_THAT(err, StrEq("stderr\n"));
        return;
    }
    // Then run dropping root.
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).DropRoot().Build()));
    EXPECT_THAT(out, StrEq("2000\nstdout\n"));
    EXPECT_THAT(err, StrEq("drop_root_user(): already running as Shell\nstderr\n"));
}

TEST_F(DumpstateTest, RunCommandAsRootUserBuild) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE("Skipping DumpstateTest.RunCommandAsRootUserBuild() on test suite\n")
        return;
    }
    if (!PropertiesHelper::IsUserBuild()) {
        // Emulates user build if necessarily.
        SetBuildType("user");
    }

    DropRoot();

    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}, CommandOptions::WithTimeout(1).AsRoot().Build()));

    // We don't know the exact path of su, so we just check for the 'root ...' commands
    EXPECT_THAT(out, StartsWith("Skipping"));
    EXPECT_THAT(out, EndsWith("root " + kSimpleCommand + "' on user build.\n"));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateTest, RunCommandAsRootNonUserBuild) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE("Skipping DumpstateTest.RunCommandAsRootNonUserBuild() on test suite\n")
        return;
    }
    if (PropertiesHelper::IsUserBuild()) {
        ALOGI("Skipping RunCommandAsRootNonUserBuild on user builds\n");
        return;
    }

    DropRoot();

    EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).AsRoot().Build()));

    EXPECT_THAT(out, StrEq("0\nstdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateTest, RunCommandAsRootNonUserBuild_withUnroot) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE(
            "Skipping DumpstateTest.RunCommandAsRootNonUserBuild_withUnroot() "
            "on test suite\n")
        return;
    }
    if (PropertiesHelper::IsUserBuild()) {
        ALOGI("Skipping RunCommandAsRootNonUserBuild_withUnroot on user builds\n");
        return;
    }

    // Same test as above, but with unroot property set, which will override su availability.
    SetUnroot(true);
    DropRoot();

    EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).AsRoot().Build()));

    // AsRoot is ineffective.
    EXPECT_THAT(out, StrEq("2000\nstdout\n"));
    EXPECT_THAT(err, StrEq("drop_root_user(): already running as Shell\nstderr\n"));
}

TEST_F(DumpstateTest, RunCommandAsRootIfAvailableOnUserBuild) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE("Skipping DumpstateTest.RunCommandAsRootIfAvailableOnUserBuild() on test suite\n")
        return;
    }
    if (!PropertiesHelper::IsUserBuild()) {
        // Emulates user build if necessarily.
        SetBuildType("user");
    }

    DropRoot();

    EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).AsRootIfAvailable().Build()));

    EXPECT_THAT(out, StrEq("2000\nstdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateTest, RunCommandAsRootIfAvailableOnDebugBuild) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE("Skipping DumpstateTest.RunCommandAsRootIfAvailableOnDebugBuild() on test suite\n")
        return;
    }
    if (PropertiesHelper::IsUserBuild()) {
        ALOGI("Skipping RunCommandAsRootNonUserBuild on user builds\n");
        return;
    }

    DropRoot();

    EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).AsRootIfAvailable().Build()));

    EXPECT_THAT(out, StrEq("0\nstdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateTest, RunCommandAsRootIfAvailableOnDebugBuild_withUnroot) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE(
            "Skipping DumpstateTest.RunCommandAsRootIfAvailableOnDebugBuild_withUnroot() "
            "on test suite\n")
        return;
    }
    if (PropertiesHelper::IsUserBuild()) {
        ALOGI("Skipping RunCommandAsRootIfAvailableOnDebugBuild_withUnroot on user builds\n");
        return;
    }
    // Same test as above, but with unroot property set, which will override su availability.
    SetUnroot(true);

    DropRoot();

    EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).AsRootIfAvailable().Build()));

    // It's a userdebug build, so "su root" should be available, but unroot=true overrides it.
    EXPECT_THAT(out, StrEq("2000\nstdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateTest, DumpFileNotFoundNoTitle) {
    EXPECT_EQ(-1, DumpFile("", "/I/cant/believe/I/exist"));
    EXPECT_THAT(out,
                StrEq("*** Error dumping /I/cant/believe/I/exist: No such file or directory\n"));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateTest, DumpFileNotFoundWithTitle) {
    EXPECT_EQ(-1, DumpFile("Y U NO EXIST?", "/I/cant/believe/I/exist"));
    EXPECT_THAT(err, IsEmpty());
    // The duration may not get output, depending on how long it takes,
    // so we just check the prefix.
    EXPECT_THAT(out, StartsWith("*** Error dumping /I/cant/believe/I/exist (Y U NO EXIST?): No "
                                "such file or directory\n"));
}

TEST_F(DumpstateTest, DumpFileSingleLine) {
    EXPECT_EQ(0, DumpFile("", kTestDataPath + "single-line.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\n"));  // dumpstate adds missing newline
}

TEST_F(DumpstateTest, DumpFileSingleLineWithNewLine) {
    EXPECT_EQ(0, DumpFile("", kTestDataPath + "single-line-with-newline.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\n"));
}

TEST_F(DumpstateTest, DumpFileMultipleLines) {
    EXPECT_EQ(0, DumpFile("", kTestDataPath + "multiple-lines.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\nI AM LINE2\nI AM LINE3\n"));
}

TEST_F(DumpstateTest, DumpFileMultipleLinesWithNewLine) {
    EXPECT_EQ(0, DumpFile("", kTestDataPath + "multiple-lines-with-newline.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\nI AM LINE2\nI AM LINE3\n"));
}

TEST_F(DumpstateTest, DumpFileOnDryRunNoTitle) {
    SetDryRun(true);
    EXPECT_EQ(0, DumpFile("", kTestDataPath + "single-line.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, IsEmpty());
}

TEST_F(DumpstateTest, DumpFileOnDryRun) {
    SetDryRun(true);
    EXPECT_EQ(0, DumpFile("Might as well dump. Dump!", kTestDataPath + "single-line.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(
        out, StartsWith("------ Might as well dump. Dump! (" + kTestDataPath + "single-line.txt:"));
    EXPECT_THAT(out, HasSubstr("\n\t(skipped on dry run)\n"));
}

TEST_F(DumpstateTest, DumpFileUpdateProgress) {
    sp<DumpstateListenerMock> listener(new DumpstateListenerMock());
    ds.listener_ = listener;
    SetProgress(0, 30);

    EXPECT_CALL(*listener, onProgress(16));  // 5/30 %
    EXPECT_EQ(0, DumpFile("", kTestDataPath + "single-line.txt"));

    std::string progress_message = GetProgressMessage(5, 30);  // TODO: unhardcode WEIGHT_FILE (5)?
    EXPECT_THAT(err, StrEq(progress_message));
    EXPECT_THAT(out, StrEq("I AM LINE1\n"));  // dumpstate adds missing newline

    ds.listener_.clear();
}

TEST_F(DumpstateTest, DumpPool_withParallelRunEnabled_notNull) {
    SetParallelRun(true);
    EnableParallelRunIfNeeded();
    EXPECT_TRUE(ds.zip_entry_tasks_);
    EXPECT_TRUE(ds.dump_pool_);
}

TEST_F(DumpstateTest, DumpPool_withParallelRunDisabled_isNull) {
    SetParallelRun(false);
    EnableParallelRunIfNeeded();
    EXPECT_FALSE(ds.zip_entry_tasks_);
    EXPECT_FALSE(ds.dump_pool_);
}

TEST_F(DumpstateTest, PreDumpUiData) {
    // These traces are always enabled, i.e. they are always pre-dumped
    std::vector<std::filesystem::path> uiTraces;
    if (!android_tracing_perfetto_transition_tracing()) {
        uiTraces.push_back(
            std::filesystem::path{"/data/misc/wmtrace/wm_transition_trace.winscope"});
        uiTraces.push_back(
            std::filesystem::path{"/data/misc/wmtrace/shell_transition_trace.winscope"});
    }

    for (const auto traceFile : uiTraces) {
        std::system(("rm -f " + traceFile.string()).c_str());
        EXPECT_FALSE(std::filesystem::exists(traceFile)) << traceFile << " was not deleted.";

        Dumpstate& ds_ = Dumpstate::GetInstance();
        ds_.PreDumpUiData();
        EXPECT_TRUE(std::filesystem::exists(traceFile)) << traceFile << " was not created.";
    }
}

class ZippedBugReportStreamTest : public DumpstateBaseTest {
  public:
    void SetUp() {
        DumpstateBaseTest::SetUp();
        ds_.options_.reset(new Dumpstate::DumpOptions());
    }
    void TearDown() {
        CloseArchive(handle_);
    }

    // Set bugreport mode and options before here.
    void GenerateBugreport() {
        ds_.Initialize();
        EXPECT_EQ(Dumpstate::RunStatus::OK, ds_.Run(/*calling_uid=*/-1, /*calling_package=*/""));
    }

    // Most bugreports droproot, ensure the file can be opened by shell to verify file content.
    void CreateFd(const std::string& path, android::base::unique_fd* out_fd) {
        out_fd->reset(TEMP_FAILURE_RETRY(open(path.c_str(),
                                              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                                              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)));
        ASSERT_GE(out_fd->get(), 0) << "could not create FD for path " << path;
    }

    void VerifyEntry(const ZipArchiveHandle archive, const std::string_view entry_name,
                     ZipEntry* data) {
        int32_t e = FindEntry(archive, entry_name, data);
        EXPECT_EQ(0, e) << ErrorCodeString(e) << " entry name: " << entry_name;
    }

    // While testing dumpstate in process, using STDOUT may get confused about
    // the internal fd redirection. Redirect to a dedicate fd to save content.
    void RedirectOutputToFd(android::base::unique_fd& ufd) {
        ds_.open_socket_fn_ = [&](const char*) -> int { return ufd.release(); };
    };

    Dumpstate& ds_ = Dumpstate::GetInstance();
    ZipArchiveHandle handle_;
};

// Generate a quick LimitedOnly report redirected to a file, open it and verify entry exist.
// TODO: broken test tracked in b/249983726
TEST_F(ZippedBugReportStreamTest, DISABLED_StreamLimitedOnlyReport) {
    std::string out_path = kTestDataPath + "StreamLimitedOnlyReportOut.zip";
    android::base::unique_fd out_fd;
    CreateFd(out_path, &out_fd);
    ds_.options_->limited_only = true;
    ds_.options_->stream_to_socket = true;
    RedirectOutputToFd(out_fd);

    GenerateBugreport();
    OpenArchive(out_path.c_str(), &handle_);

    ZipEntry entry;
    VerifyEntry(handle_, "main_entry.txt", &entry);
    std::string bugreport_txt_name;
    bugreport_txt_name.resize(entry.uncompressed_length);
    ExtractToMemory(handle_, &entry, reinterpret_cast<uint8_t*>(bugreport_txt_name.data()),
                    entry.uncompressed_length);
    EXPECT_THAT(bugreport_txt_name,
                testing::ContainsRegex("(bugreport-.+(-[[:digit:]]+){6}\\.txt)"));
    VerifyEntry(handle_, bugreport_txt_name, &entry);
}

class ProgressTest : public DumpstateBaseTest {
  public:
    Progress GetInstance(int32_t max, double growth_factor, const std::string& path = "") {
        return Progress(max, growth_factor, path);
    }

    void AssertStats(const std::string& path, int32_t expected_runs, int32_t expected_average) {
        std::string expected_content =
            android::base::StringPrintf("%d %d\n", expected_runs, expected_average);
        std::string actual_content;
        ReadFileToString(path, &actual_content);
        ASSERT_THAT(actual_content, StrEq(expected_content)) << "invalid stats on " << path;
    }
};

TEST_F(ProgressTest, SimpleTest) {
    Progress progress;
    EXPECT_EQ(0, progress.Get());
    EXPECT_EQ(Progress::kDefaultMax, progress.GetInitialMax());
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());

    bool max_increased = progress.Inc(1);
    EXPECT_EQ(1, progress.Get());
    EXPECT_EQ(Progress::kDefaultMax, progress.GetInitialMax());
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());
    EXPECT_FALSE(max_increased);

    // Ignore negative increase.
    max_increased = progress.Inc(-1);
    EXPECT_EQ(1, progress.Get());
    EXPECT_EQ(Progress::kDefaultMax, progress.GetInitialMax());
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());
    EXPECT_FALSE(max_increased);
}

TEST_F(ProgressTest, MaxGrowsInsideNewRange) {
    Progress progress = GetInstance(10, 1.2);  // 20% growth factor
    EXPECT_EQ(0, progress.Get());
    EXPECT_EQ(10, progress.GetInitialMax());
    EXPECT_EQ(10, progress.GetMax());

    // No increase
    bool max_increased = progress.Inc(10);
    EXPECT_EQ(10, progress.Get());
    EXPECT_EQ(10, progress.GetMax());
    EXPECT_FALSE(max_increased);

    // Increase, with new value < max*20%
    max_increased = progress.Inc(1);
    EXPECT_EQ(11, progress.Get());
    EXPECT_EQ(13, progress.GetMax());  // 11 average * 20% growth = 13.2 = 13
    EXPECT_TRUE(max_increased);
}

TEST_F(ProgressTest, MaxGrowsOutsideNewRange) {
    Progress progress = GetInstance(10, 1.2);  // 20% growth factor
    EXPECT_EQ(0, progress.Get());
    EXPECT_EQ(10, progress.GetInitialMax());
    EXPECT_EQ(10, progress.GetMax());

    // No increase
    bool max_increased = progress.Inc(10);
    EXPECT_EQ(10, progress.Get());
    EXPECT_EQ(10, progress.GetMax());
    EXPECT_FALSE(max_increased);

    // Increase, with new value > max*20%
    max_increased = progress.Inc(5);
    EXPECT_EQ(15, progress.Get());
    EXPECT_EQ(18, progress.GetMax());  // 15 average * 20% growth = 18
    EXPECT_TRUE(max_increased);
}

TEST_F(ProgressTest, InvalidPath) {
    Progress progress("/devil/null");
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());
}

TEST_F(ProgressTest, EmptyFile) {
    Progress progress(CopyTextFileFixture("empty-file.txt"));
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());
}

TEST_F(ProgressTest, InvalidLine1stEntryNAN) {
    Progress progress(CopyTextFileFixture("stats-invalid-1st-NAN.txt"));
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());
}

TEST_F(ProgressTest, InvalidLine2ndEntryNAN) {
    Progress progress(CopyTextFileFixture("stats-invalid-2nd-NAN.txt"));
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());
}

TEST_F(ProgressTest, InvalidLineBothNAN) {
    Progress progress(CopyTextFileFixture("stats-invalid-both-NAN.txt"));
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());
}

TEST_F(ProgressTest, InvalidLine1stEntryNegative) {
    Progress progress(CopyTextFileFixture("stats-invalid-1st-negative.txt"));
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());
}

TEST_F(ProgressTest, InvalidLine2ndEntryNegative) {
    Progress progress(CopyTextFileFixture("stats-invalid-2nd-negative.txt"));
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());
}

TEST_F(ProgressTest, InvalidLine1stEntryTooBig) {
    Progress progress(CopyTextFileFixture("stats-invalid-1st-too-big.txt"));
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());
}

TEST_F(ProgressTest, InvalidLine2ndEntryTooBig) {
    Progress progress(CopyTextFileFixture("stats-invalid-2nd-too-big.txt"));
    EXPECT_EQ(Progress::kDefaultMax, progress.GetMax());
}

// Tests stats are properly saved when the file does not exists.
TEST_F(ProgressTest, FirstTime) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it's failing when running as suite
        MYLOGE("Skipping ProgressTest.FirstTime() on test suite\n")
        return;
    }

    std::string path = kTestDataPath + "FirstTime.txt";
    android::base::RemoveFileIfExists(path);

    Progress run1(path);
    EXPECT_EQ(0, run1.Get());
    EXPECT_EQ(Progress::kDefaultMax, run1.GetInitialMax());
    EXPECT_EQ(Progress::kDefaultMax, run1.GetMax());

    bool max_increased = run1.Inc(20);
    EXPECT_EQ(20, run1.Get());
    EXPECT_EQ(Progress::kDefaultMax, run1.GetMax());
    EXPECT_FALSE(max_increased);

    run1.Save();
    AssertStats(path, 1, 20);
}

// Tests what happens when the persistent settings contains the average duration of 1 run.
// Data on file is 1 run and 109 average.
TEST_F(ProgressTest, SecondTime) {
    std::string path = CopyTextFileFixture("stats-one-run-no-newline.txt");

    Progress run1 = GetInstance(-42, 1.2, path);
    EXPECT_EQ(0, run1.Get());
    EXPECT_EQ(10, run1.GetInitialMax());
    EXPECT_EQ(10, run1.GetMax());

    bool max_increased = run1.Inc(20);
    EXPECT_EQ(20, run1.Get());
    EXPECT_EQ(24, run1.GetMax());
    EXPECT_TRUE(max_increased);

    // Average now is 2 runs and (10 + 20)/ 2 = 15
    run1.Save();
    AssertStats(path, 2, 15);

    Progress run2 = GetInstance(-42, 1.2, path);
    EXPECT_EQ(0, run2.Get());
    EXPECT_EQ(15, run2.GetInitialMax());
    EXPECT_EQ(15, run2.GetMax());

    max_increased = run2.Inc(25);
    EXPECT_EQ(25, run2.Get());
    EXPECT_EQ(30, run2.GetMax());
    EXPECT_TRUE(max_increased);

    // Average now is 3 runs and (15 * 2 + 25)/ 3 = 18.33 = 18
    run2.Save();
    AssertStats(path, 3, 18);

    Progress run3 = GetInstance(-42, 1.2, path);
    EXPECT_EQ(0, run3.Get());
    EXPECT_EQ(18, run3.GetInitialMax());
    EXPECT_EQ(18, run3.GetMax());

    // Make sure average decreases as well
    max_increased = run3.Inc(5);
    EXPECT_EQ(5, run3.Get());
    EXPECT_EQ(18, run3.GetMax());
    EXPECT_FALSE(max_increased);

    // Average now is 4 runs and (18 * 3 + 5)/ 4 = 14.75 = 14
    run3.Save();
    AssertStats(path, 4, 14);
}

// Tests what happens when the persistent settings contains the average duration of 2 runs.
// Data on file is 2 runs and 15 average.
TEST_F(ProgressTest, ThirdTime) {
    std::string path = CopyTextFileFixture("stats-two-runs.txt");
    AssertStats(path, 2, 15);  // Sanity check

    Progress run1 = GetInstance(-42, 1.2, path);
    EXPECT_EQ(0, run1.Get());
    EXPECT_EQ(15, run1.GetInitialMax());
    EXPECT_EQ(15, run1.GetMax());

    bool max_increased = run1.Inc(20);
    EXPECT_EQ(20, run1.Get());
    EXPECT_EQ(24, run1.GetMax());
    EXPECT_TRUE(max_increased);

    // Average now is 3 runs and (15 * 2 + 20)/ 3 = 16.66 = 16
    run1.Save();
    AssertStats(path, 3, 16);
}

class DumpstateUtilTest : public DumpstateBaseTest {
  public:
    void SetUp() {
        DumpstateBaseTest::SetUp();
        SetDryRun(false);
    }

    void CaptureFdOut() {
        ReadFileToString(path_, &out);
    }

    void CreateFd(const std::string& name) {
        path_ = kTestDataPath + name;
        MYLOGD("Creating fd for file %s\n", path_.c_str());

        fd = TEMP_FAILURE_RETRY(open(path_.c_str(),
                                     O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                                     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
        ASSERT_GE(fd, 0) << "could not create FD for path " << path_;
    }

    // Runs a command into the `fd` and capture `stderr`.
    int RunCommand(const std::string& title, const std::vector<std::string>& full_command,
                   const CommandOptions& options = CommandOptions::DEFAULT) {
        CaptureStderr();
        int status = RunCommandToFd(fd, title, full_command, options);
        close(fd);

        CaptureFdOut();
        err = GetCapturedStderr();
        return status;
    }

    // Dumps a file and into the `fd` and `stderr`.
    int DumpFile(const std::string& title, const std::string& path) {
        CaptureStderr();
        int status = DumpFileToFd(fd, title, path);
        close(fd);

        CaptureFdOut();
        err = GetCapturedStderr();
        return status;
    }

    int fd;

    // 'fd` output and `stderr` from the last command ran.
    std::string out, err;

  private:
    std::string path_;
};

TEST_F(DumpstateUtilTest, RunCommandNoArgs) {
    CreateFd("RunCommandNoArgs.txt");
    EXPECT_EQ(-1, RunCommand("", {}));
}

TEST_F(DumpstateUtilTest, RunCommandNoTitle) {
    CreateFd("RunCommandWithNoArgs.txt");
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}));
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateUtilTest, RunCommandWithTitle) {
    CreateFd("RunCommandWithNoArgs.txt");
    EXPECT_EQ(0, RunCommand("I AM GROOT", {kSimpleCommand}));
    EXPECT_THAT(out, StrEq("------ I AM GROOT (" + kSimpleCommand + ") ------\nstdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateUtilTest, RunCommandWithOneArg) {
    CreateFd("RunCommandWithOneArg.txt");
    EXPECT_EQ(0, RunCommand("", {kEchoCommand, "one"}));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("one\n"));
}

TEST_F(DumpstateUtilTest, RunCommandWithMultipleArgs) {
    CreateFd("RunCommandWithMultipleArgs.txt");
    EXPECT_EQ(0, RunCommand("", {kEchoCommand, "one", "is", "the", "loniest", "number"}));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("one is the loniest number\n"));
}

TEST_F(DumpstateUtilTest, RunCommandWithLoggingMessage) {
    CreateFd("RunCommandWithLoggingMessage.txt");
    EXPECT_EQ(
        0, RunCommand("", {kSimpleCommand},
                      CommandOptions::WithTimeout(10).Log("COMMAND, Y U NO LOG FIRST?").Build()));
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("COMMAND, Y U NO LOG FIRST?stderr\n"));
}

TEST_F(DumpstateUtilTest, RunCommandRedirectStderr) {
    CreateFd("RunCommandRedirectStderr.txt");
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand},
                            CommandOptions::WithTimeout(10).RedirectStderr().Build()));
    EXPECT_THAT(out, IsEmpty());
    EXPECT_THAT(err, StrEq("stdout\nstderr\n"));
}

TEST_F(DumpstateUtilTest, RunCommandDryRun) {
    CreateFd("RunCommandDryRun.txt");
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("I AM GROOT", {kSimpleCommand}));
    EXPECT_THAT(out, StrEq(android::base::StringPrintf(
                         "------ I AM GROOT (%s) ------\n\t(skipped on dry run)\n",
                         kSimpleCommand.c_str())));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateUtilTest, RunCommandDryRunNoTitle) {
    CreateFd("RunCommandDryRun.txt");
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}));
    EXPECT_THAT(
        out, StrEq(android::base::StringPrintf("%s: skipped on dry run\n", kSimpleCommand.c_str())));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateUtilTest, RunCommandDryRunAlways) {
    CreateFd("RunCommandDryRunAlways.txt");
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}, CommandOptions::WithTimeout(10).Always().Build()));
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateUtilTest, RunCommandNotFound) {
    CreateFd("RunCommandNotFound.txt");
    EXPECT_NE(0, RunCommand("", {"/there/cannot/be/such/command"}));
    EXPECT_THAT(out, StartsWith("*** command '/there/cannot/be/such/command' failed: exit code"));
    EXPECT_THAT(err, StartsWith("execvp on command '/there/cannot/be/such/command' failed"));
}

TEST_F(DumpstateUtilTest, RunCommandFails) {
    CreateFd("RunCommandFails.txt");
    EXPECT_EQ(42, RunCommand("", {kSimpleCommand, "--exit", "42"}));
    EXPECT_THAT(out, StrEq("stdout\n*** command '" + kSimpleCommand +
                           " --exit 42' failed: exit code 42\n"));
    EXPECT_THAT(err, StrEq("stderr\n*** command '" + kSimpleCommand +
                           " --exit 42' failed: exit code 42\n"));
}

TEST_F(DumpstateUtilTest, RunCommandCrashes) {
    CreateFd("RunCommandCrashes.txt");
    EXPECT_NE(0, RunCommand("", {kSimpleCommand, "--crash"}));
    // We don't know the exit code, so check just the prefix.
    EXPECT_THAT(
        out, StartsWith("stdout\n*** command '" + kSimpleCommand + " --crash' failed: exit code"));
    EXPECT_THAT(
        err, StartsWith("stderr\n*** command '" + kSimpleCommand + " --crash' failed: exit code"));
}

TEST_F(DumpstateUtilTest, RunCommandTimesoutWithSec) {
    CreateFd("RunCommandTimesout.txt");
    EXPECT_EQ(-1, RunCommand("", {kSimpleCommand, "--sleep", "2"},
                             CommandOptions::WithTimeout(1).Build()));
    EXPECT_THAT(out, StartsWith("stdout line1\n*** command '" + kSimpleCommand +
                                " --sleep 2' timed out after 1"));
    EXPECT_THAT(err, StartsWith("sleeping for 2s\n*** command '" + kSimpleCommand +
                                " --sleep 2' timed out after 1"));
}

TEST_F(DumpstateUtilTest, RunCommandTimesoutWithMsec) {
    CreateFd("RunCommandTimesout.txt");
    EXPECT_EQ(-1, RunCommand("", {kSimpleCommand, "--sleep", "2"},
                             CommandOptions::WithTimeoutInMs(1000).Build()));
    EXPECT_THAT(out, StartsWith("stdout line1\n*** command '" + kSimpleCommand +
                                " --sleep 2' timed out after 1"));
    EXPECT_THAT(err, StartsWith("sleeping for 2s\n*** command '" + kSimpleCommand +
                                " --sleep 2' timed out after 1"));
}


TEST_F(DumpstateUtilTest, RunCommandIsKilled) {
    CreateFd("RunCommandIsKilled.txt");
    CaptureStderr();

    std::thread t([=]() {
        EXPECT_EQ(SIGTERM, RunCommandToFd(fd, "", {kSimpleCommand, "--pid", "--sleep", "20"},
                                          CommandOptions::WithTimeout(100).Always().Build()));
    });

    // Capture pid and pre-sleep output.
    sleep(1);  // Wait a little bit to make sure pid and 1st line were printed.
    std::string err = GetCapturedStderr();
    EXPECT_THAT(err, StrEq("sleeping for 20s\n"));

    CaptureFdOut();
    std::vector<std::string> lines = android::base::Split(out, "\n");
    ASSERT_EQ(3, (int)lines.size()) << "Invalid lines before sleep: " << out;

    int pid = atoi(lines[0].c_str());
    EXPECT_THAT(lines[1], StrEq("stdout line1"));
    EXPECT_THAT(lines[2], IsEmpty());  // \n

    // Then kill the process.
    CaptureFdOut();
    CaptureStderr();
    ASSERT_EQ(0, kill(pid, SIGTERM)) << "failed to kill pid " << pid;
    t.join();

    // Finally, check output after murder.
    CaptureFdOut();
    err = GetCapturedStderr();

    // out starts with the pid, which is an unknown
    EXPECT_THAT(out, EndsWith("stdout line1\n*** command '" + kSimpleCommand +
                              " --pid --sleep 20' failed: killed by signal 15\n"));
    EXPECT_THAT(err, StrEq("*** command '" + kSimpleCommand +
                           " --pid --sleep 20' failed: killed by signal 15\n"));
}

TEST_F(DumpstateUtilTest, RunCommandAsRootUserBuild) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE("Skipping DumpstateUtilTest.RunCommandAsRootUserBuild() on test suite\n")
        return;
    }
    CreateFd("RunCommandAsRootUserBuild.txt");
    if (!PropertiesHelper::IsUserBuild()) {
        // Emulates user build if necessarily.
        SetBuildType("user");
    }

    DropRoot();

    EXPECT_EQ(0, RunCommand("", {kSimpleCommand}, CommandOptions::WithTimeout(1).AsRoot().Build()));

    // We don't know the exact path of su, so we just check for the 'root ...' commands
    EXPECT_THAT(out, StartsWith("Skipping"));
    EXPECT_THAT(out, EndsWith("root " + kSimpleCommand + "' on user build.\n"));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateUtilTest, RunCommandAsRootNonUserBuild) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE("Skipping DumpstateUtilTest.RunCommandAsRootNonUserBuild() on test suite\n")
        return;
    }
    CreateFd("RunCommandAsRootNonUserBuild.txt");
    if (PropertiesHelper::IsUserBuild()) {
        ALOGI("Skipping RunCommandAsRootNonUserBuild on user builds\n");
        return;
    }

    DropRoot();

    EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).AsRoot().Build()));

    EXPECT_THAT(out, StrEq("0\nstdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}


TEST_F(DumpstateUtilTest, RunCommandAsRootIfAvailableOnUserBuild) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE("Skipping DumpstateUtilTest.RunCommandAsRootIfAvailableOnUserBuild() on test suite\n")
        return;
    }
    CreateFd("RunCommandAsRootIfAvailableOnUserBuild.txt");
    if (!PropertiesHelper::IsUserBuild()) {
        // Emulates user build if necessarily.
        SetBuildType("user");
    }

    DropRoot();

    EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).AsRootIfAvailable().Build()));

    EXPECT_THAT(out, StrEq("2000\nstdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateUtilTest, RunCommandAsRootIfAvailableOnDebugBuild) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE("Skipping DumpstateUtilTest.RunCommandAsRootIfAvailableOnDebugBuild() on test suite\n")
        return;
    }
    CreateFd("RunCommandAsRootIfAvailableOnDebugBuild.txt");
    if (PropertiesHelper::IsUserBuild()) {
        ALOGI("Skipping RunCommandAsRootNonUserBuild on user builds\n");
        return;
    }

    DropRoot();

    EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).AsRootIfAvailable().Build()));

    EXPECT_THAT(out, StrEq("0\nstdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateUtilTest, RunCommandDropRoot) {
    if (!IsStandalone()) {
        // TODO: temporarily disabled because it might cause other tests to fail after dropping
        // to Shell - need to refactor tests to avoid this problem)
        MYLOGE("Skipping DumpstateUtilTest.RunCommandDropRoot() on test suite\n")
        return;
    }
    CreateFd("RunCommandDropRoot.txt");
    // First check root case - only available when running with 'adb root'.
    uid_t uid = getuid();
    if (uid == 0) {
        EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"}));
        EXPECT_THAT(out, StrEq("0\nstdout\n"));
        EXPECT_THAT(err, StrEq("stderr\n"));
        return;
    }
    // Then run dropping root.
    EXPECT_EQ(0, RunCommand("", {kSimpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).DropRoot().Build()));
    EXPECT_THAT(out, StrEq("2000\nstdout\n"));
    EXPECT_THAT(err, StrEq("drop_root_user(): already running as Shell\nstderr\n"));
}

TEST_F(DumpstateUtilTest, DumpFileNotFoundNoTitle) {
    CreateFd("DumpFileNotFound.txt");
    EXPECT_EQ(-1, DumpFile("", "/I/cant/believe/I/exist"));
    EXPECT_THAT(out,
                StrEq("*** Error dumping /I/cant/believe/I/exist: No such file or directory\n"));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateUtilTest, DumpFileNotFoundWithTitle) {
    CreateFd("DumpFileNotFound.txt");
    EXPECT_EQ(-1, DumpFile("Y U NO EXIST?", "/I/cant/believe/I/exist"));
    EXPECT_THAT(out, StrEq("*** Error dumping /I/cant/believe/I/exist (Y U NO EXIST?): No such "
                           "file or directory\n"));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateUtilTest, DumpFileSingleLine) {
    CreateFd("DumpFileSingleLine.txt");
    EXPECT_EQ(0, DumpFile("", kTestDataPath + "single-line.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\n"));  // dumpstate adds missing newline
}

TEST_F(DumpstateUtilTest, DumpFileSingleLineWithNewLine) {
    CreateFd("DumpFileSingleLineWithNewLine.txt");
    EXPECT_EQ(0, DumpFile("", kTestDataPath + "single-line-with-newline.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\n"));
}

TEST_F(DumpstateUtilTest, DumpFileMultipleLines) {
    CreateFd("DumpFileMultipleLines.txt");
    EXPECT_EQ(0, DumpFile("", kTestDataPath + "multiple-lines.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\nI AM LINE2\nI AM LINE3\n"));
}

TEST_F(DumpstateUtilTest, DumpFileMultipleLinesWithNewLine) {
    CreateFd("DumpFileMultipleLinesWithNewLine.txt");
    EXPECT_EQ(0, DumpFile("", kTestDataPath + "multiple-lines-with-newline.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\nI AM LINE2\nI AM LINE3\n"));
}

TEST_F(DumpstateUtilTest, DumpFileOnDryRunNoTitle) {
    CreateFd("DumpFileOnDryRun.txt");
    SetDryRun(true);
    std::string path = kTestDataPath + "single-line.txt";
    EXPECT_EQ(0, DumpFile("", kTestDataPath + "single-line.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq(path + ": skipped on dry run\n"));
}

TEST_F(DumpstateUtilTest, DumpFileOnDryRun) {
    CreateFd("DumpFileOnDryRun.txt");
    SetDryRun(true);
    std::string path = kTestDataPath + "single-line.txt";
    EXPECT_EQ(0, DumpFile("Might as well dump. Dump!", kTestDataPath + "single-line.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(
        out, StartsWith("------ Might as well dump. Dump! (" + kTestDataPath + "single-line.txt:"));
    EXPECT_THAT(out, EndsWith("skipped on dry run\n"));
}

class DumpPoolTest : public DumpstateBaseTest {
  public:
    void SetUp() {
        dump_pool_ = std::make_unique<DumpPool>(kTestDataPath);
        DumpstateBaseTest::SetUp();
        CreateOutputFile();
    }

    void CreateOutputFile() {
        out_path_ = kTestDataPath + "out.txt";
        out_fd_.reset(TEMP_FAILURE_RETRY(open(out_path_.c_str(),
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)));
        ASSERT_GE(out_fd_.get(), 0) << "could not create FD for path "
                << out_path_;
    }

    int getTempFileCounts(const std::string& folder) {
        int count = 0;
        std::unique_ptr<DIR, decltype(&closedir)> dir_ptr(opendir(folder.c_str()),
                &closedir);
        if (!dir_ptr) {
            return -1;
        }
        int dir_fd = dirfd(dir_ptr.get());
        if (dir_fd < 0) {
            return -1;
        }

        struct dirent* de;
        while ((de = readdir(dir_ptr.get()))) {
            if (de->d_type != DT_REG) {
                continue;
            }
            std::string file_name(de->d_name);
            if (file_name.find(DumpPool::PREFIX_TMPFILE_NAME) != 0) {
                continue;
            }
            count++;
        }
        return count;
    }

    void setLogDuration(bool log_duration) {
        dump_pool_->setLogDuration(log_duration);
    }

    std::unique_ptr<DumpPool> dump_pool_;
    android::base::unique_fd out_fd_;
    std::string out_path_;
};

TEST_F(DumpPoolTest, EnqueueTaskWithFd) {
    auto dump_func_1 = [](int out_fd) {
        dprintf(out_fd, "A");
    };
    auto dump_func_2 = [](int out_fd) {
        dprintf(out_fd, "B");
        sleep(1);
    };
    auto dump_func_3 = [](int out_fd) {
        dprintf(out_fd, "C");
    };
    setLogDuration(/* log_duration = */false);
    auto t1 = dump_pool_->enqueueTaskWithFd("", dump_func_1, std::placeholders::_1);
    auto t2 = dump_pool_->enqueueTaskWithFd("", dump_func_2, std::placeholders::_1);
    auto t3 = dump_pool_->enqueueTaskWithFd("", dump_func_3, std::placeholders::_1);

    WaitForTask(std::move(t1), "", out_fd_.get());
    WaitForTask(std::move(t2), "", out_fd_.get());
    WaitForTask(std::move(t3), "", out_fd_.get());

    std::string result;
    ReadFileToString(out_path_, &result);
    EXPECT_THAT(result, StrEq("A\nB\nC\n"));
    EXPECT_THAT(getTempFileCounts(kTestDataPath), Eq(0));
}

TEST_F(DumpPoolTest, EnqueueTask_withDurationLog) {
    bool run_1 = false;
    auto dump_func_1 = [&]() {
        run_1 = true;
    };

    auto t1 = dump_pool_->enqueueTask(/* duration_title = */"1", dump_func_1);
    WaitForTask(std::move(t1), "", out_fd_.get());

    std::string result;
    ReadFileToString(out_path_, &result);
    EXPECT_TRUE(run_1);
    EXPECT_THAT(result, StrEq("------ 0.000s was the duration of '1' ------\n"));
    EXPECT_THAT(getTempFileCounts(kTestDataPath), Eq(0));
}

class TaskQueueTest : public DumpstateBaseTest {
public:
    void SetUp() {
        DumpstateBaseTest::SetUp();
    }

    TaskQueue task_queue_;
};

TEST_F(TaskQueueTest, runTask) {
    bool is_task1_run = false;
    bool is_task2_run = false;
    auto task_1 = [&](bool task_cancelled) {
        if (task_cancelled) {
            return;
        }
        is_task1_run = true;
    };
    auto task_2 = [&](bool task_cancelled) {
        if (task_cancelled) {
            return;
        }
        is_task2_run = true;
    };
    task_queue_.add(task_1, std::placeholders::_1);
    task_queue_.add(task_2, std::placeholders::_1);

    task_queue_.run(/* do_cancel = */false);

    EXPECT_TRUE(is_task1_run);
    EXPECT_TRUE(is_task2_run);
}

TEST_F(TaskQueueTest, runTask_withCancelled) {
    bool is_task1_cancelled = false;
    bool is_task2_cancelled = false;
    auto task_1 = [&](bool task_cancelled) {
        is_task1_cancelled = task_cancelled;
    };
    auto task_2 = [&](bool task_cancelled) {
        is_task2_cancelled = task_cancelled;
    };
    task_queue_.add(task_1, std::placeholders::_1);
    task_queue_.add(task_2, std::placeholders::_1);

    task_queue_.run(/* do_cancel = */true);

    EXPECT_TRUE(is_task1_cancelled);
    EXPECT_TRUE(is_task2_cancelled);
}


}  // namespace dumpstate
}  // namespace os
}  // namespace android
