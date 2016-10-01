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
#include <unistd.h>

#include <android-base/file.h>

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
    }

    // Runs a command and capture `stdout` and `stderr`.
    int RunCommand(const std::string& title, const std::vector<std::string>& fullCommand,
                   const CommandOptions& options = CommandOptions::DEFAULT) {
        CaptureStdout();
        CaptureStderr();
        int status = ds_.RunCommand(title, fullCommand, options);
        out = GetCapturedStdout();
        err = GetCapturedStderr();
        return status;
    }

    // `stdout` and `stderr` from the last command ran.
    std::string out, err;

    std::string testPath = dirname(android::base::GetExecutablePath().c_str());
    std::string simpleBin = testPath + "/../dumpstate_test_fixture/dumpstate_test_fixture";

    void SetDryRun(bool dryRun) {
        ds_.dryRun_ = dryRun;
    }

  private:
    Dumpstate& ds_ = Dumpstate::GetInstance();
};

TEST_F(DumpstateTest, RunCommandNoArgs) {
    EXPECT_EQ(-1, RunCommand("", {}));
}

TEST_F(DumpstateTest, RunCommandNoTitle) {
    EXPECT_EQ(0, RunCommand("", {simpleBin}));
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

TEST_F(DumpstateTest, RunCommandWithTitle) {
    EXPECT_EQ(0, RunCommand("I AM GROOT", {simpleBin}));
    EXPECT_THAT(err, StrEq("stderr\n"));
    // We don't know the exact duration, so we check the prefix and suffix
    EXPECT_THAT(out, StartsWith("------ I AM GROOT (" + simpleBin + ") ------\nstdout\n------"));
    EXPECT_THAT(out, EndsWith("s was the duration of 'I AM GROOT' ------\n"));
}

TEST_F(DumpstateTest, RunCommandRedirectStderr) {
    EXPECT_EQ(
        0, RunCommand("", {simpleBin}, CommandOptions::WithTimeout(10).RedirectStderr().Build()));
    EXPECT_THAT(out, IsEmpty());
    EXPECT_THAT(err, StrEq("stderr\nstdout\n"));
}

TEST_F(DumpstateTest, RunCommandWithOneArg) {
    EXPECT_EQ(0, RunCommand("", {simpleBin, "one"}));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("one\n"));
}

TEST_F(DumpstateTest, RunCommandWithNoArgs) {
    EXPECT_EQ(0, RunCommand("", {simpleBin, "one", "is", "the", "loniest", "number"}));
    EXPECT_THAT(err, IsEmpty());
    EXPECT_THAT(out, StrEq("one is the loniest number\n"));
}

TEST_F(DumpstateTest, RunCommandDryRun) {
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("I AM GROOT", {simpleBin}));
    // We don't know the exact duration, so we check the prefix and suffix
    EXPECT_THAT(out, StartsWith("------ I AM GROOT (" + simpleBin +
                                ") ------\n\t(skipped on dry run)\n------"));
    EXPECT_THAT(out, EndsWith("s was the duration of 'I AM GROOT' ------\n"));
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateTest, RunCommandDryRunNoTitle) {
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("", {simpleBin}));
    EXPECT_THAT(out, IsEmpty());
    EXPECT_THAT(err, IsEmpty());
}

TEST_F(DumpstateTest, RunCommandDryRunAlways) {
    SetDryRun(true);
    EXPECT_EQ(0, RunCommand("", {simpleBin}, CommandOptions::WithTimeout(10).Always().Build()));
    EXPECT_THAT(out, StrEq("stdout\n"));
    EXPECT_THAT(err, StrEq("stderr\n"));
}

// TODO: add test for other scenarios:
// - AsRoot()
// - DropRoot
// - WithLoggingMessage()
// - command does not exist (invalid path)
// - command times out
// - command exits with a different value
// - command is killed before timed out
// - test progress

// TODO: test DumpFile()
