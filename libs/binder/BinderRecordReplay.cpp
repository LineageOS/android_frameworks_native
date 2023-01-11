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
#include <android-base/unique_fd.h>
#include <binder/BinderRecordReplay.h>
#include <algorithm>

using android::Parcel;
using android::base::borrowed_fd;
using android::base::unique_fd;
using android::binder::debug::RecordedTransaction;

#define PADDING8(s) ((8 - (s) % 8) % 8)

static_assert(PADDING8(0) == 0);
static_assert(PADDING8(1) == 7);
static_assert(PADDING8(7) == 1);
static_assert(PADDING8(8) == 0);

// Transactions are sequentially recorded to a file descriptor.
//
// An individual RecordedTransaction is written with the following format:
//
// WARNING: Though the following format is designed to be stable and
// extensible, it is under active development and should be considered
// unstable until this warning is removed.
//
// A RecordedTransaction is written to a file as a sequence of Chunks.
//
// A Chunk consists of a ChunkDescriptor, Data, and Padding.
//
// Data and Padding may each be zero-length as specified by the
// ChunkDescriptor.
//
// The ChunkDescriptor identifies the type of data in the chunk, the size of
// the data in bytes, and the number of zero-bytes padding to land on an
// 8-byte boundary by the end of the Chunk.
//
// ┌───────────────────────────┐
// │Chunk                      │
// │┌─────────────────────────┐│
// ││ChunkDescriptor          ││
// ││┌───────────┬───────────┐││
// │││chunkType  │paddingSize│││
// │││uint32_t   │uint32_t   ├┼┼───┐
// ││├───────────┴───────────┤││   │
// │││dataSize               │││   │
// │││uint64_t               ├┼┼─┐ │
// ││└───────────────────────┘││ │ │
// │└─────────────────────────┘│ │ │
// │┌─────────────────────────┐│ │ │
// ││Data                     ││ │ │
// ││bytes * dataSize         │◀─┘ │
// │└─────────────────────────┘│   │
// │┌─────────────────────────┐│   │
// ││Padding                  ││   │
// ││bytes * paddingSize      │◀───┘
// │└─────────────────────────┘│
// └───────────────────────────┘
//
// A RecordedTransaction is written as a Header Chunk with fields about the
// transaction, a Data Parcel chunk, a Reply Parcel Chunk, and an End Chunk.
// ┌──────────────────────┐
// │     Header Chunk     │
// ├──────────────────────┤
// │  Sent Parcel Chunk   │
// ├──────────────────────┤
// │  Reply Parcel Chunk  │
// ├──────────────────────┤
// ║      End Chunk       ║
// ╚══════════════════════╝
//
// On reading a RecordedTransaction, an unrecognized chunk is skipped using
// the size information in the ChunkDescriptor. Chunks are read and either
// assimilated or skipped until an End Chunk is encountered. This has three
// notable implications:
//
// 1. Older and newer implementations should be able to read one another's
//    Transactions, though there will be loss of information.
// 2. With the exception of the End Chunk, Chunks can appear in any
//    order and even repeat, though this is not recommended.
// 3. If any Chunk is repeated, old values will be overwritten by versions
//    encountered later in the file.
//
// No effort is made to ensure the expected chunks are present. A single
// End Chunk may therefore produce a empty, meaningless RecordedTransaction.

RecordedTransaction::RecordedTransaction(RecordedTransaction&& t) noexcept {
    mHeader = t.mHeader;
    mSent.setData(t.getDataParcel().data(), t.getDataParcel().dataSize());
    mReply.setData(t.getReplyParcel().data(), t.getReplyParcel().dataSize());
}

std::optional<RecordedTransaction> RecordedTransaction::fromDetails(uint32_t code, uint32_t flags,
                                                                    timespec timestamp,
                                                                    const Parcel& dataParcel,
                                                                    const Parcel& replyParcel,
                                                                    status_t err) {
    RecordedTransaction t;
    t.mHeader = {code,
                 flags,
                 static_cast<int32_t>(err),
                 dataParcel.isForRpc() ? static_cast<uint32_t>(1) : static_cast<uint32_t>(0),
                 static_cast<int64_t>(timestamp.tv_sec),
                 static_cast<int32_t>(timestamp.tv_nsec),
                 0};

    if (t.mSent.setData(dataParcel.data(), dataParcel.dataSize()) != android::NO_ERROR) {
        LOG(INFO) << "Failed to set sent parcel data.";
        return std::nullopt;
    }

    if (t.mReply.setData(replyParcel.data(), replyParcel.dataSize()) != android::NO_ERROR) {
        LOG(INFO) << "Failed to set reply parcel data.";
        return std::nullopt;
    }

    return std::optional<RecordedTransaction>(std::move(t));
}

enum {
    HEADER_CHUNK = 0x00000001,
    DATA_PARCEL_CHUNK = 0x00000002,
    REPLY_PARCEL_CHUNK = 0x00000003,
    INVALID_CHUNK = 0x00fffffe,
    END_CHUNK = 0x00ffffff,
};

struct ChunkDescriptor {
    uint32_t chunkType = 0;
    uint32_t padding = 0;
    uint32_t dataSize = 0;
    uint32_t reserved = 0; // Future checksum
};

static android::status_t readChunkDescriptor(borrowed_fd fd, ChunkDescriptor* chunkOut) {
    if (!android::base::ReadFully(fd, chunkOut, sizeof(ChunkDescriptor))) {
        LOG(INFO) << "Failed to read Chunk Descriptor from fd " << fd.get();
        return android::UNKNOWN_ERROR;
    }
    if (PADDING8(chunkOut->dataSize) != chunkOut->padding) {
        chunkOut->chunkType = INVALID_CHUNK;
        LOG(INFO) << "Chunk data and padding sizes do not align." << fd.get();
        return android::BAD_VALUE;
    }
    return android::NO_ERROR;
}

std::optional<RecordedTransaction> RecordedTransaction::fromFile(const unique_fd& fd) {
    RecordedTransaction t;
    ChunkDescriptor chunk;

    do {
        if (NO_ERROR != readChunkDescriptor(fd, &chunk)) {
            LOG(INFO) << "Failed to read chunk descriptor.";
            return std::nullopt;
        }
        switch (chunk.chunkType) {
            case HEADER_CHUNK: {
                if (chunk.dataSize != static_cast<uint32_t>(sizeof(TransactionHeader))) {
                    LOG(INFO) << "Header Chunk indicated size " << chunk.dataSize << "; Expected "
                              << sizeof(TransactionHeader) << ".";
                    return std::nullopt;
                }
                if (!android::base::ReadFully(fd, &t.mHeader, chunk.dataSize)) {
                    LOG(INFO) << "Failed to read transactionHeader from fd " << fd.get();
                    return std::nullopt;
                }
                lseek(fd.get(), chunk.padding, SEEK_CUR);
                break;
            }
            case DATA_PARCEL_CHUNK: {
                std::vector<uint8_t> bytes;
                bytes.resize(chunk.dataSize);
                if (!android::base::ReadFully(fd, bytes.data(), chunk.dataSize)) {
                    LOG(INFO) << "Failed to read sent parcel data from fd " << fd.get();
                    return std::nullopt;
                }
                if (t.mSent.setData(bytes.data(), chunk.dataSize) != android::NO_ERROR) {
                    LOG(INFO) << "Failed to set sent parcel data.";
                    return std::nullopt;
                }
                lseek(fd.get(), chunk.padding, SEEK_CUR);
                break;
            }
            case REPLY_PARCEL_CHUNK: {
                std::vector<uint8_t> bytes;
                bytes.resize(chunk.dataSize);
                if (!android::base::ReadFully(fd, bytes.data(), chunk.dataSize)) {
                    LOG(INFO) << "Failed to read reply parcel data from fd " << fd.get();
                    return std::nullopt;
                }
                if (t.mReply.setData(bytes.data(), chunk.dataSize) != android::NO_ERROR) {
                    LOG(INFO) << "Failed to set reply parcel data.";
                    return std::nullopt;
                }
                lseek(fd.get(), chunk.padding, SEEK_CUR);
                break;
            }
            case INVALID_CHUNK:
                LOG(INFO) << "Invalid chunk.";
                return std::nullopt;
            case END_CHUNK:
                LOG(INFO) << "Read end chunk";
                FALLTHROUGH_INTENDED;
            default:
                // Unrecognized or skippable chunk
                lseek(fd.get(), chunk.dataSize + chunk.padding, SEEK_CUR);
                break;
        }
    } while (chunk.chunkType != END_CHUNK);

    return std::optional<RecordedTransaction>(std::move(t));
}

android::status_t RecordedTransaction::writeChunk(borrowed_fd fd, uint32_t chunkType,
                                                  size_t byteCount, const uint8_t* data) const {
    // Write Chunk Descriptor
    // - Chunk Type
    if (!android::base::WriteFully(fd, &chunkType, sizeof(uint32_t))) {
        LOG(INFO) << "Failed to write chunk header to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    // - Chunk Data Padding Size
    uint32_t additionalPaddingCount = static_cast<uint32_t>(PADDING8(byteCount));
    if (!android::base::WriteFully(fd, &additionalPaddingCount, sizeof(uint32_t))) {
        LOG(INFO) << "Failed to write chunk padding size to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    // - Chunk Data Size
    uint64_t byteCountToWrite = (uint64_t)byteCount;
    if (!android::base::WriteFully(fd, &byteCountToWrite, sizeof(uint64_t))) {
        LOG(INFO) << "Failed to write chunk size to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (byteCount == 0) {
        return NO_ERROR;
    }

    if (!android::base::WriteFully(fd, data, byteCount)) {
        LOG(INFO) << "Failed to write chunk data to fd " << fd.get();
        return UNKNOWN_ERROR;
    }

    const uint8_t zeros[7] = {0};
    if (!android::base::WriteFully(fd, zeros, additionalPaddingCount)) {
        LOG(INFO) << "Failed to write chunk padding to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    return NO_ERROR;
}

android::status_t RecordedTransaction::dumpToFile(const unique_fd& fd) const {
    if (NO_ERROR !=
        writeChunk(fd, HEADER_CHUNK, sizeof(TransactionHeader),
                   reinterpret_cast<const uint8_t*>(&mHeader))) {
        LOG(INFO) << "Failed to write transactionHeader to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (NO_ERROR != writeChunk(fd, DATA_PARCEL_CHUNK, mSent.dataSize(), mSent.data())) {
        LOG(INFO) << "Failed to write sent Parcel to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (NO_ERROR != writeChunk(fd, REPLY_PARCEL_CHUNK, mReply.dataSize(), mReply.data())) {
        LOG(INFO) << "Failed to write reply Parcel to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (NO_ERROR != writeChunk(fd, END_CHUNK, 0, NULL)) {
        LOG(INFO) << "Failed to write end chunk to fd " << fd.get();
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

int32_t RecordedTransaction::getReturnedStatus() const {
    return mHeader.statusReturned;
}

timespec RecordedTransaction::getTimestamp() const {
    time_t sec = mHeader.timestampSeconds;
    int32_t nsec = mHeader.timestampNanoseconds;
    return (timespec){.tv_sec = sec, .tv_nsec = nsec};
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
