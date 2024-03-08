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

#include <binder/RecordedTransaction.h>
#include <filesystem>

#include "fuzzer/FuzzedDataProvider.h"

using android::binder::unique_fd;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::FILE* intermediateFile = std::tmpfile();
    fwrite(data, sizeof(uint8_t), size, intermediateFile);
    rewind(intermediateFile);
    int fileNumber = fileno(intermediateFile);

    unique_fd fd(dup(fileNumber));

    auto transaction = android::binder::debug::RecordedTransaction::fromFile(fd);

    std::fclose(intermediateFile);

    if (transaction.has_value()) {
        intermediateFile = std::tmpfile();

        unique_fd fdForWriting(dup(fileno(intermediateFile)));
        auto writeStatus [[maybe_unused]] = transaction.value().dumpToFile(fdForWriting);

        std::fclose(intermediateFile);
    }

    return 0;
}
