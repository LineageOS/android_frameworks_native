/*
 * Copyright (C) 2022, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <android-base/unique_fd.h>
#include <binder/Parcel.h>
#include <mutex>

namespace android {

namespace binder::debug {

// Warning: Transactions are sequentially recorded to the file descriptor in a
// non-stable format. A detailed description of the recording format can be found in
// BinderRecordReplay.cpp.

class RecordedTransaction {
public:
    // Filled with the first transaction from fd.
    static std::optional<RecordedTransaction> fromFile(const android::base::unique_fd& fd);
    // Filled with the arguments.
    static std::optional<RecordedTransaction> fromDetails(uint32_t code, uint32_t flags,
                                                          const Parcel& data, const Parcel& reply,
                                                          status_t err);
    RecordedTransaction(RecordedTransaction&& t) noexcept;

    [[nodiscard]] status_t dumpToFile(const android::base::unique_fd& fd) const;

    uint32_t getCode() const;
    uint32_t getFlags() const;
    uint64_t getDataSize() const;
    uint64_t getReplySize() const;
    int32_t getReturnedStatus() const;
    uint32_t getVersion() const;
    const Parcel& getDataParcel() const;
    const Parcel& getReplyParcel() const;

private:
    RecordedTransaction() = default;

#pragma clang diagnostic push
#pragma clang diagnostic error "-Wpadded"
    struct TransactionHeader {
        uint32_t code = 0;
        uint32_t flags = 0;
        uint64_t dataSize = 0;
        uint64_t replySize = 0;
        int32_t statusReturned = 0;
        uint32_t version = 0; // !0 iff Rpc
    };
#pragma clang diagnostic pop
    static_assert(sizeof(TransactionHeader) == 32);
    static_assert(sizeof(TransactionHeader) % 8 == 0);

    TransactionHeader mHeader;
    Parcel mSent;
    Parcel mReply;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-private-field"
    uint8_t mReserved[40];
#pragma clang diagnostic pop
};

} // namespace binder::debug

} // namespace android
