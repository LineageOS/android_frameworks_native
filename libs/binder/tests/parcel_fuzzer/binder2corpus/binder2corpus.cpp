/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "../../FileUtils.h"

#include <android-base/logging.h>
#include <binder/RecordedTransaction.h>
#include <binder/unique_fd.h>

#include <fuzzseeds/random_parcel_seeds.h>

#include <sys/prctl.h>
#include <sys/stat.h>

using android::generateSeedsFromRecording;
using android::status_t;
using android::binder::unique_fd;
using android::binder::debug::RecordedTransaction;

status_t generateCorpus(const char* recordingPath, const char* corpusDir) {
    unique_fd fd(open(recordingPath, O_RDONLY));
    if (!fd.ok()) {
        std::cerr << "Failed to open recording file at path " << recordingPath
                  << " with error: " << strerror(errno) << '\n';
        return android::BAD_VALUE;
    }

    if (auto res = mkdir(corpusDir, 0766); res != 0) {
        std::cerr
                << "Failed to create corpus directory at path. Delete directory if already exists: "
                << corpusDir << std::endl;
        return android::BAD_VALUE;
    }

    int transactionNumber = 0;
    while (auto transaction = RecordedTransaction::fromFile(fd)) {
        ++transactionNumber;
        std::string filePath = std::string(corpusDir) + std::string("transaction_") +
                std::to_string(transactionNumber);
        constexpr int openFlags = O_WRONLY | O_CREAT | O_BINARY | O_CLOEXEC;
        unique_fd corpusFd(open(filePath.c_str(), openFlags, 0666));
        if (!corpusFd.ok()) {
            std::cerr << "Failed to open fd. Path " << filePath
                      << " with error: " << strerror(errno) << std::endl;
            return android::UNKNOWN_ERROR;
        }
        generateSeedsFromRecording(corpusFd, transaction.value());
    }

    if (transactionNumber == 0) {
        std::cerr << "No valid transaction has been found in recording file:  " << recordingPath
                  << std::endl;
        return android::BAD_VALUE;
    }

    return android::NO_ERROR;
}

void printHelp(const char* toolName) {
    std::cout << "Usage: \n\n"
              << toolName
              << " <recording_path> <destination_directory> \n\n*Use "
                 "record_binder tool for recording binder transactions."
              << std::endl;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        printHelp(argv[0]);
        return 1;
    }
    const char* sourcePath = argv[1];
    const char* corpusDir = argv[2];
    if (android::NO_ERROR != generateCorpus(sourcePath, corpusDir)) {
        std::cerr << "Failed to generate fuzzer corpus." << std::endl;
        return 1;
    }
    return 0;
}
