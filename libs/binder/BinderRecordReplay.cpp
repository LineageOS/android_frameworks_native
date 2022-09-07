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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <binder/BinderRecordReplay.h>
#include <algorithm>

using android::Parcel;
using android::base::unique_fd;
using android::binder::debug::RecordedTransaction;

#define PADDING8(s) ((8 - (s) % 8) % 8)

static_assert(PADDING8(0) == 0);
static_assert(PADDING8(1) == 7);
static_assert(PADDING8(7) == 1);
static_assert(PADDING8(8) == 0);

// Transactions are sequentially recorded to the file descriptor in the following format:
//
// RecordedTransaction.TransactionHeader  (32 bytes)
// Sent Parcel data                       (getDataSize() bytes)
// padding                                (enough bytes to align the reply Parcel data to 8 bytes)
// Reply Parcel data                      (getReplySize() bytes)
// padding                                (enough bytes to align the next header to 8 bytes)
// [repeats with next transaction]
//
// Warning: This format is non-stable

RecordedTransaction::RecordedTransaction(RecordedTransaction&& t) noexcept {
    mHeader = {t.getCode(),      t.getFlags(),          t.getDataSize(),
               t.getReplySize(), t.getReturnedStatus(), t.getVersion()};
    mSent.setData(t.getDataParcel().data(), t.getDataSize());
    mReply.setData(t.getReplyParcel().data(), t.getReplySize());
}

std::optional<RecordedTransaction> RecordedTransaction::fromDetails(uint32_t code, uint32_t flags,
                                                                    const Parcel& dataParcel,
                                                                    const Parcel& replyParcel,
                                                                    status_t err) {
    RecordedTransaction t;
    t.mHeader = {code,
                 flags,
                 static_cast<uint64_t>(dataParcel.dataSize()),
                 static_cast<uint64_t>(replyParcel.dataSize()),
                 static_cast<int32_t>(err),
                 dataParcel.isForRpc() ? static_cast<uint32_t>(1) : static_cast<uint32_t>(0)};

    if (t.mSent.setData(dataParcel.data(), t.getDataSize()) != android::NO_ERROR) {
        LOG(INFO) << "Failed to set sent parcel data.";
        return std::nullopt;
    }

    if (t.mReply.setData(replyParcel.data(), t.getReplySize()) != android::NO_ERROR) {
        LOG(INFO) << "Failed to set reply parcel data.";
        return std::nullopt;
    }

    return std::optional<RecordedTransaction>(std::move(t));
}

std::optional<RecordedTransaction> RecordedTransaction::fromFile(const unique_fd& fd) {
    RecordedTransaction t;
    if (!android::base::ReadFully(fd, &t.mHeader, sizeof(mHeader))) {
        LOG(INFO) << "Failed to read transactionHeader from fd " << fd.get();
        return std::nullopt;
    }
    if (t.getVersion() != 0) {
        LOG(INFO) << "File corrupted: transaction version is not 0.";
        return std::nullopt;
    }

    std::vector<uint8_t> bytes;
    bytes.resize(t.getDataSize());
    if (!android::base::ReadFully(fd, bytes.data(), t.getDataSize())) {
        LOG(INFO) << "Failed to read sent parcel data from fd " << fd.get();
        return std::nullopt;
    }
    if (t.mSent.setData(bytes.data(), t.getDataSize()) != android::NO_ERROR) {
        LOG(INFO) << "Failed to set sent parcel data.";
        return std::nullopt;
    }

    uint8_t padding[7];
    if (!android::base::ReadFully(fd, padding, PADDING8(t.getDataSize()))) {
        LOG(INFO) << "Failed to read sent parcel padding from fd " << fd.get();
        return std::nullopt;
    }
    if (std::any_of(padding, padding + 7, [](uint8_t i) { return i != 0; })) {
        LOG(INFO) << "File corrupted: padding isn't 0.";
        return std::nullopt;
    }

    bytes.resize(t.getReplySize());
    if (!android::base::ReadFully(fd, bytes.data(), t.getReplySize())) {
        LOG(INFO) << "Failed to read reply parcel data from fd " << fd.get();
        return std::nullopt;
    }
    if (t.mReply.setData(bytes.data(), t.getReplySize()) != android::NO_ERROR) {
        LOG(INFO) << "Failed to set reply parcel data.";
        return std::nullopt;
    }

    if (!android::base::ReadFully(fd, padding, PADDING8(t.getReplySize()))) {
        LOG(INFO) << "Failed to read parcel padding from fd " << fd.get();
        return std::nullopt;
    }
    if (std::any_of(padding, padding + 7, [](uint8_t i) { return i != 0; })) {
        LOG(INFO) << "File corrupted: padding isn't 0.";
        return std::nullopt;
    }

    return std::optional<RecordedTransaction>(std::move(t));
}

android::status_t RecordedTransaction::dumpToFile(const unique_fd& fd) const {
    if (!android::base::WriteFully(fd, &mHeader, sizeof(mHeader))) {
        LOG(INFO) << "Failed to write transactionHeader to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (!android::base::WriteFully(fd, mSent.data(), getDataSize())) {
        LOG(INFO) << "Failed to write sent parcel data to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    const uint8_t zeros[7] = {0};
    if (!android::base::WriteFully(fd, zeros, PADDING8(getDataSize()))) {
        LOG(INFO) << "Failed to write sent parcel padding to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (!android::base::WriteFully(fd, mReply.data(), getReplySize())) {
        LOG(INFO) << "Failed to write reply parcel data to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (!android::base::WriteFully(fd, zeros, PADDING8(getReplySize()))) {
        LOG(INFO) << "Failed to write reply parcel padding to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    return NO_ERROR;
}

uint32_t RecordedTransaction::getCode() const {
    return mHeader.code;
}

uint32_t RecordedTransaction::getFlags() const {
    return mHeader.flags;
}

uint64_t RecordedTransaction::getDataSize() const {
    return mHeader.dataSize;
}

uint64_t RecordedTransaction::getReplySize() const {
    return mHeader.replySize;
}

int32_t RecordedTransaction::getReturnedStatus() const {
    return mHeader.statusReturned;
}

uint32_t RecordedTransaction::getVersion() const {
    return mHeader.version;
}

const Parcel& RecordedTransaction::getDataParcel() const {
    return mSent;
}

const Parcel& RecordedTransaction::getReplyParcel() const {
    return mReply;
}
