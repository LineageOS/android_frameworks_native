/*
 * Copyright 2023 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "TransactionTraceWriterTest"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <filesystem>

#include "TestableSurfaceFlinger.h"

namespace android {

class TransactionTraceWriterTest : public testing::Test {
protected:
    std::string mFilename = "/data/local/tmp/testfile_transaction_trace.winscope";

    void SetUp() { mFlinger.initTransactionTraceWriter(); }
    void TearDown() { std::filesystem::remove(mFilename); }

    void verifyTraceFile() {
        std::fstream file(mFilename, std::ios::in);
        ASSERT_TRUE(file.is_open());
        std::string line;
        char magicNumber[8];
        file.read(magicNumber, 8);
        EXPECT_EQ("\tTNXTRAC", std::string(magicNumber, magicNumber + 8));
    }

    TestableSurfaceFlinger mFlinger;
};

// Check that a new file is written if overwrite=true and no file exists.
TEST_F(TransactionTraceWriterTest, canWriteToFile_overwriteTrue) {
    TransactionTraceWriter::getInstance().invokeForTest(mFilename, /* overwrite */ true);
    EXPECT_EQ(access(mFilename.c_str(), F_OK), 0);
    verifyTraceFile();
}

// Check that a new file is written if overwrite=false and no file exists.
TEST_F(TransactionTraceWriterTest, canWriteToFile_overwriteFalse) {
    TransactionTraceWriter::getInstance().invokeForTest(mFilename, /* overwrite */ false);
    EXPECT_EQ(access(mFilename.c_str(), F_OK), 0);
    verifyTraceFile();
}

// Check that an existing file is overwritten when overwrite=true.
TEST_F(TransactionTraceWriterTest, canOverwriteFile) {
    std::string testLine = "test";
    {
        std::ofstream file(mFilename, std::ios::out);
        file << testLine;
    }
    TransactionTraceWriter::getInstance().invokeForTest(mFilename, /* overwrite */ true);
    verifyTraceFile();
}

// Check that an existing file isn't overwritten when it is new and overwrite=false.
TEST_F(TransactionTraceWriterTest, doNotOverwriteFile) {
    std::string testLine = "test";
    {
        std::ofstream file(mFilename, std::ios::out);
        file << testLine;
    }
    TransactionTraceWriter::getInstance().invokeForTest(mFilename, /* overwrite */ false);
    {
        std::fstream file(mFilename, std::ios::in);
        ASSERT_TRUE(file.is_open());
        std::string line;
        std::getline(file, line);
        EXPECT_EQ(line, testLine);
    }
}

// Check that an existing file is overwritten when it is old and overwrite=false.
TEST_F(TransactionTraceWriterTest, overwriteOldFile) {
    std::string testLine = "test";
    {
        std::ofstream file(mFilename, std::ios::out);
        file << testLine;
    }

    // Update file modification time to 15 minutes ago.
    using Clock = std::filesystem::file_time_type::clock;
    std::error_code error;
    std::filesystem::last_write_time(mFilename, Clock::now() - std::chrono::minutes{15}, error);
    ASSERT_EQ(error.value(), 0);

    TransactionTraceWriter::getInstance().invokeForTest(mFilename, /* overwrite */ false);
    verifyTraceFile();
}

// Check we cannot write to file if the trace write is disabled.
TEST_F(TransactionTraceWriterTest, canDisableTraceWriter) {
    TransactionTraceWriter::getInstance().disable();
    TransactionTraceWriter::getInstance().invokeForTest(mFilename, /* overwrite */ true);
    EXPECT_NE(access(mFilename.c_str(), F_OK), 0);

    TransactionTraceWriter::getInstance().enable();
    TransactionTraceWriter::getInstance().invokeForTest(mFilename, /* overwrite */ true);
    EXPECT_EQ(access(mFilename.c_str(), F_OK), 0);
    verifyTraceFile();
}

} // namespace android