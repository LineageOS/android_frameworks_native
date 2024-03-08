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
#include <fuzzbinder/random_parcel.h>
#include <filesystem>
#include <string>

#include "fuzzer/FuzzedDataProvider.h"

using android::fillRandomParcel;
using android::binder::unique_fd;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider = FuzzedDataProvider(data, size);

    android::String16 interfaceName =
            android::String16(provider.ConsumeRandomLengthString().c_str());

    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    time_t sec = provider.ConsumeIntegral<time_t>();
    long nsec = provider.ConsumeIntegral<long>();
    timespec timestamp = {.tv_sec = sec, .tv_nsec = nsec};
    android::status_t transactionStatus = provider.ConsumeIntegral<android::status_t>();

    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(
            provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes()));

    // same options so that FDs and binders could be shared in both Parcels
    android::RandomParcelOptions options;

    android::Parcel p0, p1;
    fillRandomParcel(&p0, FuzzedDataProvider(bytes.data(), bytes.size()), &options);
    fillRandomParcel(&p1, std::move(provider), &options);

    auto transaction =
            android::binder::debug::RecordedTransaction::fromDetails(interfaceName, code, flags,
                                                                     timestamp, p0, p1,
                                                                     transactionStatus);

    if (transaction.has_value()) {
        std::FILE* intermediateFile = std::tmpfile();
        unique_fd fdForWriting(dup(fileno(intermediateFile)));
        auto writeStatus [[maybe_unused]] = transaction.value().dumpToFile(fdForWriting);

        std::fclose(intermediateFile);
    }

    return 0;
}
