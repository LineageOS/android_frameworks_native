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

TEST_F(TransactionTraceWriterTest, canWriteToFile) {
    TransactionTraceWriter::getInstance().invokeForTest(mFilename, /* overwrite */ true);
    EXPECT_EQ(access(mFilename.c_str(), F_OK), 0);
    verifyTraceFile();
}

TEST_F(TransactionTraceWriterTest, canOverwriteFile) {
    std::string testLine = "test";
    {
        std::ofstream file(mFilename, std::ios::out);
        file << testLine;
    }
    TransactionTraceWriter::getInstance().invokeForTest(mFilename, /* overwrite */ true);
    verifyTraceFile();
}

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
} // namespace android