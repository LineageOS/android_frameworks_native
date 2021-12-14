/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <stdlib.h>
#include <string.h>

#include "restorable_file.h"
#include "unique_file.h"
#include "utils.h"

#undef LOG_TAG
#define LOG_TAG "installd_file_test"

namespace {

constexpr char kFileTestDir[] = "/data/local/tmp/installd_file_test_data";
constexpr char kTmpFileSuffix[] = ".tmp";
constexpr char kBackupFileSuffix[] = ".backup";

void UnlinkWithAssert(const std::string& path) {
    ASSERT_EQ(0, unlink(path.c_str()));
}

} // namespace

namespace android {
namespace installd {

// Add these as macros as functions make it hard to tell where the failure has happened.
#define ASSERT_FILE_NOT_EXISTING(path)           \
    {                                            \
        struct stat st;                          \
        ASSERT_NE(0, ::stat(path.c_str(), &st)); \
    }
#define ASSERT_FILE_EXISTING(path)               \
    {                                            \
        struct stat st;                          \
        ASSERT_EQ(0, ::stat(path.c_str(), &st)); \
    }
#define ASSERT_FILE_CONTENT(path, expectedContent) ASSERT_EQ(expectedContent, ReadTestFile(path))
#define ASSERT_FILE_OPEN(path, fd)       \
    {                                    \
        fd = open(path.c_str(), O_RDWR); \
        ASSERT_TRUE(fd >= 0);            \
    }
#define ASSERT_WRITE_TO_FD(fd, content) \
    ASSERT_TRUE(android::base::WriteStringToFd(content, android::base::borrowed_fd(fd)))

class FileTest : public testing::Test {
protected:
    virtual void SetUp() {
        setenv("ANDROID_LOG_TAGS", "*:v", 1);
        android::base::InitLogging(nullptr);

        ASSERT_EQ(0, create_dir_if_needed(kFileTestDir, 0777));
    }

    virtual void TearDown() {
        system(android::base::StringPrintf("rm -rf %s", kFileTestDir).c_str());
    }

    std::string GetTestFilePath(const std::string& fileName) {
        return android::base::StringPrintf("%s/%s", kFileTestDir, fileName.c_str());
    }

    void CreateTestFileWithContents(const std::string& path, const std::string& content) {
        ALOGI("CreateTestFileWithContents:%s", path.c_str());
        ASSERT_TRUE(android::base::WriteStringToFile(content, path));
    }

    std::string GetTestName() {
        std::string name(testing::UnitTest::GetInstance()->current_test_info()->name());
        return name;
    }

    std::string ReadTestFile(const std::string& path) {
        std::string content;
        bool r = android::base::ReadFileToString(path, &content);
        if (!r) {
            PLOG(ERROR) << "Cannot read file:" << path;
        }
        return content;
    }
};

TEST_F(FileTest, TestUniqueFileMoveConstruction) {
    const int fd = 101;
    std::string testFile = GetTestFilePath(GetTestName());
    UniqueFile uf1(fd, testFile);
    uf1.DisableAutoClose();

    UniqueFile uf2(std::move(uf1));

    ASSERT_EQ(fd, uf2.fd());
    ASSERT_EQ(testFile, uf2.path());
}

TEST_F(FileTest, TestUniqueFileAssignment) {
    const int fd1 = 101;
    const int fd2 = 102;
    std::string testFile1 = GetTestFilePath(GetTestName());
    std::string testFile2 = GetTestFilePath(GetTestName() + "2");

    UniqueFile uf1(fd1, testFile1);
    uf1.DisableAutoClose();

    UniqueFile uf2(fd2, testFile2);
    uf2.DisableAutoClose();

    ASSERT_EQ(fd2, uf2.fd());
    ASSERT_EQ(testFile2, uf2.path());

    uf2 = std::move(uf1);

    ASSERT_EQ(fd1, uf2.fd());
    ASSERT_EQ(testFile1, uf2.path());
}

TEST_F(FileTest, TestUniqueFileCleanup) {
    std::string testFile = GetTestFilePath(GetTestName());
    CreateTestFileWithContents(testFile, "OriginalContent");

    int fd;
    ASSERT_FILE_OPEN(testFile, fd);

    { UniqueFile uf = UniqueFile(fd, testFile, UnlinkWithAssert); }

    ASSERT_FILE_NOT_EXISTING(testFile);
}

TEST_F(FileTest, TestUniqueFileNoCleanup) {
    std::string testFile = GetTestFilePath(GetTestName());
    CreateTestFileWithContents(testFile, "OriginalContent");

    int fd;
    ASSERT_FILE_OPEN(testFile, fd);

    {
        UniqueFile uf = UniqueFile(fd, testFile, UnlinkWithAssert);
        uf.DisableCleanup();
    }

    ASSERT_FILE_CONTENT(testFile, "OriginalContent");
}

TEST_F(FileTest, TestUniqueFileFd) {
    std::string testFile = GetTestFilePath(GetTestName());
    CreateTestFileWithContents(testFile, "OriginalContent");

    int fd;
    ASSERT_FILE_OPEN(testFile, fd);

    UniqueFile uf(fd, testFile, UnlinkWithAssert);

    ASSERT_EQ(fd, uf.fd());

    uf.reset();

    ASSERT_EQ(-1, uf.fd());
}

TEST_F(FileTest, TestRestorableFileMoveConstruction) {
    std::string testFile = GetTestFilePath(GetTestName());

    RestorableFile rf1 = RestorableFile::CreateWritableFile(testFile, 0600);
    int fd = rf1.fd();

    RestorableFile rf2(std::move(rf1));

    ASSERT_EQ(fd, rf2.fd());
    ASSERT_EQ(testFile, rf2.path());
}

TEST_F(FileTest, TestRestorableFileAssignment) {
    std::string testFile1 = GetTestFilePath(GetTestName());
    std::string testFile2 = GetTestFilePath(GetTestName() + "2");

    RestorableFile rf1 = RestorableFile::CreateWritableFile(testFile1, 0600);
    int fd1 = rf1.fd();

    RestorableFile rf2 = RestorableFile::CreateWritableFile(testFile2, 0600);
    int fd2 = rf2.fd();

    ASSERT_EQ(fd2, rf2.fd());
    ASSERT_EQ(testFile2, rf2.path());

    rf2 = std::move(rf1);

    ASSERT_EQ(fd1, rf2.fd());
    ASSERT_EQ(testFile1, rf2.path());
}

TEST_F(FileTest, TestRestorableFileVerifyUniqueFileWithReset) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);

        ASSERT_FILE_EXISTING(tmpFile);

        const UniqueFile& uf = rf.GetUniqueFile();

        ASSERT_EQ(rf.fd(), uf.fd());
        ASSERT_EQ(rf.path(), uf.path());

        rf.reset();

        ASSERT_EQ(rf.fd(), uf.fd());
        ASSERT_EQ(rf.path(), uf.path());
        ASSERT_EQ(-1, rf.fd());
        ASSERT_TRUE(rf.path().empty());
    }
}

TEST_F(FileTest, TestRestorableFileVerifyUniqueFileWithCommit) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    std::string backupFile = testFile + kBackupFileSuffix;

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);

        ASSERT_FILE_EXISTING(tmpFile);

        const UniqueFile& uf = rf.GetUniqueFile();

        ASSERT_EQ(rf.fd(), uf.fd());
        ASSERT_EQ(rf.path(), uf.path());

        ASSERT_TRUE(rf.CreateBackupFile());

        ASSERT_FILE_NOT_EXISTING(backupFile);

        rf.CommitWorkFile();

        ASSERT_EQ(rf.fd(), uf.fd());
        ASSERT_EQ(rf.path(), uf.path());
        ASSERT_EQ(-1, rf.fd());
        ASSERT_EQ(testFile, rf.path());
    }
}

TEST_F(FileTest, TestRestorableFileNewFileNotCommitted) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);

        ASSERT_FILE_EXISTING(tmpFile);
        ASSERT_FILE_NOT_EXISTING(testFile);

        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");

        ASSERT_FILE_CONTENT(tmpFile, "NewContent");
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(testFile);
}

TEST_F(FileTest, TestRestorableFileNotCommittedWithOriginal) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");

        ASSERT_FILE_CONTENT(tmpFile, "NewContent");
        ASSERT_FILE_EXISTING(testFile);
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_CONTENT(testFile, "OriginalContent");
}

TEST_F(FileTest, TestRestorableFileNotCommittedWithOriginalAndOldTmp) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + kTmpFileSuffix, "OldTmp");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");

        ASSERT_FILE_CONTENT(tmpFile, "NewContent");
        ASSERT_FILE_EXISTING(testFile);
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_CONTENT(testFile, "OriginalContent");
}

TEST_F(FileTest, TestRestorableFileNewFileCommitted) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    std::string backupFile = testFile + kBackupFileSuffix;

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);

        ASSERT_FILE_EXISTING(tmpFile);
        ASSERT_FILE_NOT_EXISTING(testFile);

        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");
        ASSERT_FILE_CONTENT(tmpFile, "NewContent");

        ASSERT_TRUE(rf.CreateBackupFile());

        ASSERT_FILE_NOT_EXISTING(backupFile);

        ASSERT_TRUE(rf.CommitWorkFile());
        rf.RemoveBackupFile();

        ASSERT_FILE_CONTENT(testFile, "NewContent");
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(backupFile);
    ASSERT_FILE_CONTENT(testFile, "NewContent");
}

TEST_F(FileTest, TestRestorableFileCommittedWithOriginal) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    std::string backupFile = testFile + kBackupFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");
        ASSERT_FILE_CONTENT(tmpFile, "NewContent");

        ASSERT_TRUE(rf.CreateBackupFile());

        ASSERT_FILE_NOT_EXISTING(testFile);
        ASSERT_FILE_EXISTING(backupFile);

        ASSERT_TRUE(rf.CommitWorkFile());

        ASSERT_FILE_EXISTING(backupFile);
        ASSERT_FILE_CONTENT(testFile, "NewContent");

        rf.RemoveBackupFile();

        ASSERT_FILE_NOT_EXISTING(backupFile);
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_CONTENT(testFile, "NewContent");
}

TEST_F(FileTest, TestRestorableFileCommittedWithOriginalAndOldTmp) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + kTmpFileSuffix, "OldTmp");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");
        ASSERT_FILE_CONTENT(tmpFile, "NewContent");

        ASSERT_TRUE(rf.CommitWorkFile());

        ASSERT_FILE_CONTENT(testFile, "NewContent");
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_CONTENT(testFile, "NewContent");
}

TEST_F(FileTest, TestRestorableFileCommitFailureNoOriginal) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    std::string backupFile = testFile + kBackupFileSuffix;

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");

        ASSERT_TRUE(rf.CreateBackupFile());

        ASSERT_FILE_NOT_EXISTING(testFile);
        ASSERT_FILE_NOT_EXISTING(backupFile);

        // Now remove tmp file to force commit failure.
        close(rf.fd());
        ASSERT_EQ(0, unlink(tmpFile.c_str()));
        ASSERT_FILE_NOT_EXISTING(tmpFile);

        ASSERT_FALSE(rf.CommitWorkFile());

        ASSERT_EQ(-1, rf.fd());
        ASSERT_EQ(testFile, rf.path());
        ASSERT_FILE_NOT_EXISTING(testFile);
        ASSERT_FILE_NOT_EXISTING(tmpFile);

        ASSERT_TRUE(rf.RestoreBackupFile());
    }

    ASSERT_FILE_NOT_EXISTING(testFile);
    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(backupFile);
}

TEST_F(FileTest, TestRestorableFileCommitFailureAndRollback) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    std::string backupFile = testFile + kBackupFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");

        ASSERT_TRUE(rf.CreateBackupFile());

        ASSERT_FILE_NOT_EXISTING(testFile);
        ASSERT_FILE_EXISTING(backupFile);

        // Now remove tmp file to force commit failure.
        close(rf.fd());
        ASSERT_EQ(0, unlink(tmpFile.c_str()));
        ASSERT_FILE_NOT_EXISTING(tmpFile);

        ASSERT_FALSE(rf.CommitWorkFile());

        ASSERT_EQ(-1, rf.fd());
        ASSERT_EQ(testFile, rf.path());
        ASSERT_FILE_NOT_EXISTING(testFile);
        ASSERT_FILE_NOT_EXISTING(tmpFile);
        ASSERT_FILE_EXISTING(backupFile);

        ASSERT_TRUE(rf.RestoreBackupFile());
    }

    ASSERT_FILE_EXISTING(testFile);
    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(backupFile);
}

TEST_F(FileTest, TestRestorableFileResetAndRemoveAllFiles) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    std::string backupFile = testFile + kBackupFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");

        ASSERT_TRUE(rf.CreateBackupFile());

        ASSERT_FILE_NOT_EXISTING(testFile);
        ASSERT_FILE_EXISTING(backupFile);

        rf.ResetAndRemoveAllFiles();

        ASSERT_EQ(-1, rf.fd());
        ASSERT_FILE_NOT_EXISTING(tmpFile);
        ASSERT_FILE_NOT_EXISTING(testFile);
        ASSERT_FILE_NOT_EXISTING(backupFile);
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(testFile);
    ASSERT_FILE_NOT_EXISTING(backupFile);
}

TEST_F(FileTest, TestRestorableFileRemoveFileAndTmpFileWithContentFile) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    std::string backupFile = testFile + kBackupFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");

    RestorableFile::RemoveAllFiles(testFile);

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(testFile);
    ASSERT_FILE_NOT_EXISTING(backupFile);
}

TEST_F(FileTest, TestRestorableFileRemoveFileAndTmpFileWithContentAndTmpFile) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    std::string backupFile = testFile + kBackupFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + kTmpFileSuffix, "TmpContent");

    RestorableFile::RemoveAllFiles(testFile);

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(testFile);
    ASSERT_FILE_NOT_EXISTING(backupFile);
}

} // namespace installd
} // namespace android
