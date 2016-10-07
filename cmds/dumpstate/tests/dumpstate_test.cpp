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

#include "dumpstate.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <libgen.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <thread>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#define LOG_TAG "dumpstate"
#include <cutils/log.h>

using ::testing::EndsWith;
using ::testing::IsEmpty;
using ::testing::StrEq;
using ::testing::StartsWith;
using ::testing::Test;
using ::testing::internal::CaptureStderr;
using ::testing::internal::CaptureStdout;
using ::testing::internal::GetCapturedStderr;
using ::testing::internal::GetCapturedStdout;

// Not used on test cases yet...
void dumpstate_board(void) {
}

class DumpstateTest : public Test {
  public:
    void SetUp() {
        SetDryRun(false);
        SetBuildType(android::base::GetProperty("ro.build.type", "(unknown)"));
        ds.updateProgress_ = false;
    }

    // Runs a command and capture `stdout` and `stderr`.
    int RunCommand(const std::string& title, const std::vector<std::string>& fullCommand,
                   const CommandOptions& options = CommandOptions::DEFAULT) {
        CaptureStdout();
        CaptureStderr();
        int status = ds.RunCommand(title, fullCommand, options);
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

    void SetDryRun(bool dryRun) {
        ALOGD("Setting dryRun_ to %s\n", dryRun ? "true" : "false");
        ds.dryRun_ = dryRun;
    }

    void SetBuildType(const std::string& buildType) {
        ALOGD("Setting buildType_ to '%s'\n", buildType.c_str());
        ds.buildType_ = buildType;
    }

    bool IsUserBuild() {
        return "user" == android::base::GetProperty("ro.build.type", "(unknown)");
    }

    void DropRoot() {
        drop_root_user();
        uid_t uid = getuid();
        ASSERT_EQ(2000, (int)uid);
    }

    // TODO: remove when progress is set by Binder callbacks.
    void AssertSystemProperty(const std::string& key, const std::string& expectedValue) {
        std::string actualValue = android::base::GetProperty(key, "not set");
        EXPECT_THAT(expectedValue, StrEq(actualValue)) << "invalid value for property " << key;
    }

    std::string GetProgressMessage(int progress, int weightTotal, int oldWeightTotal = 0) {
        EXPECT_EQ(progress, ds.progress_) << "invalid progress";
        EXPECT_EQ(weightTotal, ds.weightTotal_) << "invalid weightTotal";

        AssertSystemProperty(android::base::StringPrintf("dumpstate.%d.progress", getpid()),
                             std::to_string(progress));

        bool maxIncreased = oldWeightTotal > 0;

        std::string adjustmentMessage = "";
        if (maxIncreased) {
            AssertSystemProperty(android::base::StringPrintf("dumpstate.%d.max", getpid()),
                                 std::to_string(weightTotal));
            adjustmentMessage = android::base::StringPrintf(
                "Adjusting total weight from %d to %d\n", oldWeightTotal, weightTotal);
        }

        return android::base::StringPrintf("%sSetting progress (dumpstate.%d.progress): %d/%d\n",
                                           adjustmentMessage.c_str(), getpid(), progress,
                                           weightTotal);
    }

    // `stdout` and `stderr` from the last command ran.
    std::string out, err;

    std::string testPath = dirname(android::base::GetExecutablePath().c_str());
    std::string fixturesPath = testPath + "/../dumpstate_test_fixture/";
    std::string testDataPath = fixturesPath + "/testdata/";
    std::string simpleCommand = fixturesPath + "dumpstate_test_fixture";
    std::string echoCommand = "/system/bin/echo";

    Dumpstate& ds = Dumpstate::GetInstance();
};

TEST_F(DumpstateTest, RunCommandNoArgs) {
    EXPECT_EQ(-1, RunCommand("", {}));
}

TEST_F(DumpstateTest, RunCommandNoTitle) {
    EXPECT_EQ(0, RunCommand("", {simpleCommand}));
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateTest, RunCommandWithTitle) {
    EXPECT_EQ(0, RunCommand("I AM GROOT", {simpleCommand}));
    EXPECT_THAT(err, StrEq("stderr\n"));
    // We don't know the exact duration, so we check the prefix and suffix
    EXPECT_THAT(out,
                StartsWith("------ I AM GROOT (" + simpleCommand + ") ------\nstdout\n------"));
    EXPECT_THAT(out, EndsWith("s was the duration of 'I AM GROOT' ------\n"));
}

TEST_F(DumpstateTest, RunCommandWithLoggingMessage) {
    EXPECT_EQ(
        0, RunCommand("", {simpleCommand},
                      CommandOptions::WithTimeout(10).Log("COMMAND, Y U NO LOG FIRST?").Build()));
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("COMMAND, Y U NO LOG FIRST?stderr\n"));
}

TEST_F(DumpstateTest, RunCommandRedirectStderr) {
    EXPECT_EQ(0, RunCommand("", {simpleCommand},
                            CommandOptions::WithTimeout(10).RedirectStderr().Build()));
    EXPECT_THAT(out, IsEmpty());
    EXPECT_THAT(err, StrEq("stdout\nstderr\n"));
}

TEST_F(DumpstateTest, RunCommandWithOneArg) {
    EXPECT_EQ(0, RunCommand("", {echoCommand, "one"}));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("one\n"));
}

TEST_F(DumpstateTest, RunCommandWithMultipleArgs) {
    EXPECT_EQ(0, RunCommand("", {echoCommand, "one", "is", "the", "loniest", "number"}));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("one is the loniest number\n"));
}

TEST_F(DumpstateTest, RunCommandDryRun) {
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("I AM GROOT", {simpleCommand}));
    // We don't know the exact duration, so we check the prefix and suffix
    EXPECT_THAT(out, StartsWith("------ I AM GROOT (" + simpleCommand +
                                ") ------\n\t(skipped on dry run)\n------"));
    EXPECT_THAT(out, EndsWith("s was the duration of 'I AM GROOT' ------\n"));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateTest, RunCommandDryRunNoTitle) {
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("", {simpleCommand}));
    EXPECT_THAT(out, IsEmpty());
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateTest, RunCommandDryRunAlways) {
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("", {simpleCommand}, CommandOptions::WithTimeout(10).Always().Build()));
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateTest, RunCommandNotFound) {
    EXPECT_NE(0, RunCommand("", {"/there/cannot/be/such/command"}));
    EXPECT_THAT(out, StartsWith("*** command '/there/cannot/be/such/command' failed: exit code"));
    EXPECT_THAT(err, StartsWith("execvp on command '/there/cannot/be/such/command' failed"));
}

TEST_F(DumpstateTest, RunCommandFails) {
    EXPECT_EQ(42, RunCommand("", {simpleCommand, "--exit", "42"}));
    EXPECT_THAT(
        out, StrEq("stdout\n*** command '" + simpleCommand + " --exit 42' failed: exit code 42\n"));
    EXPECT_THAT(
        err, StrEq("stderr\n*** command '" + simpleCommand + " --exit 42' failed: exit code 42\n"));
}

TEST_F(DumpstateTest, RunCommandCrashes) {
    EXPECT_NE(0, RunCommand("", {simpleCommand, "--crash"}));
    // We don't know the exit code, so check just the prefix.
    EXPECT_THAT(
        out, StartsWith("stdout\n*** command '" + simpleCommand + " --crash' failed: exit code"));
    EXPECT_THAT(
        err, StartsWith("stderr\n*** command '" + simpleCommand + " --crash' failed: exit code"));
}

TEST_F(DumpstateTest, RunCommandTimesout) {
    EXPECT_EQ(-1, RunCommand("", {simpleCommand, "--sleep", "2"},
                             CommandOptions::WithTimeout(1).Build()));
    EXPECT_THAT(out, StartsWith("stdout line1\n*** command '" + simpleCommand +
                                " --sleep 2' timed out after 1"));
    EXPECT_THAT(err, StartsWith("sleeping for 2s\n*** command '" + simpleCommand +
                                " --sleep 2' timed out after 1"));
}

TEST_F(DumpstateTest, RunCommandIsKilled) {
    CaptureStdout();
    CaptureStderr();

    std::thread t([=]() {
        EXPECT_EQ(SIGTERM, ds.RunCommand("", {simpleCommand, "--pid", "--sleep", "20"},
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

    EXPECT_THAT(out, StrEq("*** command '" + simpleCommand +
                           " --pid --sleep 20' failed: killed by signal 15\n"));
    EXPECT_THAT(err, StrEq("*** command '" + simpleCommand +
                           " --pid --sleep 20' failed: killed by signal 15\n"));
}

TEST_F(DumpstateTest, RunCommandProgress) {
    ds.updateProgress_ = true;
    ds.progress_ = 0;
    ds.weightTotal_ = 30;

    EXPECT_EQ(0, RunCommand("", {simpleCommand}, CommandOptions::WithTimeout(20).Build()));
    std::string progressMessage = GetProgressMessage(20, 30);
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n" + progressMessage));

    EXPECT_EQ(0, RunCommand("", {simpleCommand}, CommandOptions::WithTimeout(10).Build()));
    progressMessage = GetProgressMessage(30, 30);
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n" + progressMessage));

    // Run a command that will increase maximum timeout.
    EXPECT_EQ(0, RunCommand("", {simpleCommand}, CommandOptions::WithTimeout(1).Build()));
    progressMessage = GetProgressMessage(31, 36, 30);  // 20% increase
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n" + progressMessage));

    // Make sure command ran while in dryRun is counted.
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("", {simpleCommand}, CommandOptions::WithTimeout(4).Build()));
    progressMessage = GetProgressMessage(35, 36);
    EXPECT_THAT(out, IsEmpty());
    EXPECT_THAT(err, StrEq(progressMessage));
}

TEST_F(DumpstateTest, RunCommandDropRoot) {
    // First check root case - only available when running with 'adb root'.
    uid_t uid = getuid();
    if (uid == 0) {
        EXPECT_EQ(0, RunCommand("", {simpleCommand, "--uid"}));
        EXPECT_THAT(out, StrEq("0\nstdout\n"));
        EXPECT_THAT(err, StrEq("stderr\n"));
        return;
    }
    // Then drop root.

    EXPECT_EQ(0, RunCommand("", {simpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).DropRoot().Build()));
    EXPECT_THAT(out, StrEq("2000\nstdout\n"));
    EXPECT_THAT(err, StrEq("drop_root_user(): already running as Shell\nstderr\n"));
}

TEST_F(DumpstateTest, RunCommandAsRootUserBuild) {
    if (!IsUserBuild()) {
        // Emulates user build if necessarily.
        SetBuildType("user");
    }

    DropRoot();

    EXPECT_EQ(0, RunCommand("", {simpleCommand}, CommandOptions::WithTimeout(1).AsRoot().Build()));

    // We don't know the exact path of su, so we just check for the 'root ...' commands
    EXPECT_THAT(out, StartsWith("Skipping"));
    EXPECT_THAT(out, EndsWith("root " + simpleCommand + "' on user build.\n"));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateTest, RunCommandAsRootNonUserBuild) {
    if (IsUserBuild()) {
        ALOGI("Skipping RunCommandAsRootNonUserBuild on user builds\n");
        return;
    }

    DropRoot();

    EXPECT_EQ(0, RunCommand("", {simpleCommand, "--uid"},
                            CommandOptions::WithTimeout(1).AsRoot().Build()));

    EXPECT_THAT(out, StrEq("0\nstdout\n"));
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
    // We don't know the exact duration, so we check the prefix and suffix
    EXPECT_THAT(out, StartsWith("*** Error dumping /I/cant/believe/I/exist (Y U NO EXIST?): No "
                                "such file or directory\n"));
    EXPECT_THAT(out, EndsWith("s was the duration of 'Y U NO EXIST?' ------\n"));
}

TEST_F(DumpstateTest, DumpFileSingleLine) {
    EXPECT_EQ(0, DumpFile("", testDataPath + "single-line.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\n"));  // dumpstate adds missing newline
}

TEST_F(DumpstateTest, DumpFileSingleLineWithNewLine) {
    EXPECT_EQ(0, DumpFile("", testDataPath + "single-line-with-newline.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\n"));
}

TEST_F(DumpstateTest, DumpFileMultipleLines) {
    EXPECT_EQ(0, DumpFile("", testDataPath + "multiple-lines.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\nI AM LINE2\nI AM LINE3\n"));
}

TEST_F(DumpstateTest, DumpFileMultipleLinesWithNewLine) {
    EXPECT_EQ(0, DumpFile("", testDataPath + "multiple-lines-with-newline.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("I AM LINE1\nI AM LINE2\nI AM LINE3\n"));
}

TEST_F(DumpstateTest, DumpFileOnDryRunNoTitle) {
    SetDryRun(true);
    EXPECT_EQ(0, DumpFile("", testDataPath + "single-line.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, IsEmpty());
}

TEST_F(DumpstateTest, DumpFileOnDryRun) {
    SetDryRun(true);
    EXPECT_EQ(0, DumpFile("Might as well dump. Dump!", testDataPath + "single-line.txt"));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StartsWith("------ Might as well dump. Dump! (" + testDataPath +
                                "single-line.txt) ------\n\t(skipped on dry run)\n------"));
    EXPECT_THAT(out, EndsWith("s was the duration of 'Might as well dump. Dump!' ------\n"));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateTest, DumpFileUpdateProgress) {
    ds.updateProgress_ = true;
    ds.progress_ = 0;
    ds.weightTotal_ = 30;

    EXPECT_EQ(0, DumpFile("", testDataPath + "single-line.txt"));

    std::string progressMessage = GetProgressMessage(5, 30);  // TODO: unhardcode WEIGHT_FILE (5)?

    EXPECT_THAT(err, StrEq(progressMessage));
    EXPECT_THAT(out, StrEq("I AM LINE1\n"));  // dumpstate adds missing newline
}
