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

#include <linux/android/binder.h>

#include <android-base/logging.h>

#include <binder/Parcel.h>
#include <binder/RecordedTransaction.h>

#include <fuzzseeds/random_parcel_seeds.h>

#include <stack>
#include <string>
#include "../../file.h"

using android::binder::borrowed_fd;
using android::binder::WriteFully;
using std::stack;

extern size_t kRandomInterfaceLength;
// Keep this in sync with max_length in random_binder.cpp while creating a RandomBinder
std::string kRandomInterfaceName(kRandomInterfaceLength, 'i');

namespace android {
namespace impl {
template <typename T>
std::vector<uint8_t> reverseBytes(T min, T max, T val) {
    uint64_t range = static_cast<uint64_t>(max) - min;
    uint64_t result = val - min;
    size_t offset = 0;

    std::vector<uint8_t> reverseData;
    uint8_t reversed = 0;
    reversed |= result;

    while (offset < sizeof(T) * CHAR_BIT && (range >> offset) > 0) {
        reverseData.push_back(reversed);
        reversed = 0;
        reversed |= (result >> CHAR_BIT);
        result = result >> CHAR_BIT;
        offset += CHAR_BIT;
    }

    return std::move(reverseData);
}

template <typename T>
void writeReversedBuffer(std::vector<uint8_t>& integralBuffer, T min, T max, T val) {
    std::vector<uint8_t> reversedData = reverseBytes(min, max, val);
    // ConsumeIntegral Calls read buffer from the end. Keep inserting at the front of the buffer
    // so that we can align fuzzService operations with seed generation for readability.
    integralBuffer.insert(integralBuffer.begin(), reversedData.begin(), reversedData.end());
}

template <typename T>
void writeReversedBuffer(std::vector<uint8_t>& integralBuffer, T val) {
    // For ConsumeIntegral<T>() calls, FuzzedDataProvider uses numeric limits min and max
    // as range
    writeReversedBuffer(integralBuffer, std::numeric_limits<T>::min(),
                        std::numeric_limits<T>::max(), val);
}

} // namespace impl

struct ProviderMetadata {
    size_t position;
    size_t value;

    ProviderMetadata() {
        value = 0;
        position = 0;
    }
};

// Assuming current seed path is inside the fillRandomParcel function, start of the loop.
void writeRandomBinder(borrowed_fd fd, vector<uint8_t>& fillParcelBuffer,
                       stack<ProviderMetadata>& remainingPositions) {
    // Choose 2 index in array
    size_t fillFuncIndex = 2;
    impl::writeReversedBuffer(fillParcelBuffer, static_cast<size_t>(0), static_cast<size_t>(2),
                              fillFuncIndex);

    // navigate to getRandomBinder. provide consume bool false
    bool flag = false;
    impl::writeReversedBuffer(fillParcelBuffer, flag);

    // selecting RandomBinder, other binders in the list are not recorded as KernelObjects
    size_t randomBinderIndex = 0;
    impl::writeReversedBuffer(fillParcelBuffer, static_cast<size_t>(0), static_cast<size_t>(2),
                              randomBinderIndex);

    // write random string of length 100 in actual buffer array.
    CHECK(WriteFully(fd, kRandomInterfaceName.c_str(), kRandomInterfaceName.size())) << fd.get();

    // These will be bytes which are used inside of RandomBinder
    // simplest path for these bytes is going to be consume bool -> return random status
    vector<uint8_t> randomBinderBuffer;

    bool returnRandomInt = true;
    impl::writeReversedBuffer(randomBinderBuffer, returnRandomInt);

    status_t randomStatus = 0;
    impl::writeReversedBuffer(randomBinderBuffer, randomStatus);

    // write integral in range to consume bytes for random binder
    ProviderMetadata providerData;
    providerData.position = fillParcelBuffer.size();
    providerData.value = randomBinderBuffer.size();
    remainingPositions.push(providerData);

    // Write to fd
    CHECK(WriteFully(fd, randomBinderBuffer.data(), randomBinderBuffer.size())) << fd.get();
}

// Assuming current seed path is inside the fillRandomParcelFunction, start of the loop.
void writeRandomFd(vector<uint8_t>& fillParcelBuffer) {
    // path to random fd
    size_t fillFuncIndex = 1;
    impl::writeReversedBuffer(fillParcelBuffer, static_cast<size_t>(0), static_cast<size_t>(2),
                              fillFuncIndex);

    bool flag = false;
    impl::writeReversedBuffer(fillParcelBuffer, flag);

    // go for /dev/null index 1
    size_t fdIndex = 1;
    impl::writeReversedBuffer(fillParcelBuffer, static_cast<size_t>(0), static_cast<size_t>(3),
                              fdIndex);
}

void writeParcelData(borrowed_fd fd, vector<uint8_t>& fillParcelBuffer,
                     stack<ProviderMetadata>& remainingPositions, const uint8_t* data, size_t start,
                     size_t length) {
    // need to write parcel data till next offset with instructions to pick random bytes till offset
    size_t fillFuncIndex = 0;
    impl::writeReversedBuffer(fillParcelBuffer, static_cast<size_t>(0), static_cast<size_t>(2),
                              fillFuncIndex);

    // provide how much bytes to read in control buffer
    ProviderMetadata providerData;
    providerData.position = fillParcelBuffer.size();
    providerData.value = length;
    remainingPositions.push(providerData);

    // provide actual bytes
    CHECK(WriteFully(fd, data + start, length)) << fd.get();
}

/**
 *   Generate sequence of copy data, write fd and write binder instructions and required data.
 *   Data which will be read using consumeBytes is written to fd directly. Data which is read in
 *   form integer is consumed from rear end FuzzedDataProvider. So insert it in fillParcelBuffer and
 *   then write to fd
 */
size_t regenerateParcel(borrowed_fd fd, vector<uint8_t>& fillParcelBuffer, const Parcel& p,
                        size_t dataSize, const vector<uint64_t>& objectOffsets) {
    stack<ProviderMetadata> remainingPositions;
    size_t copiedDataPosition = 0;
    const uint8_t* parcelData = p.data();
    size_t numBinders = 0;
    size_t numFds = 0;

    for (auto offset : objectOffsets) {
        // Check what type of object is present here
        const flat_binder_object* flatObject =
                reinterpret_cast<const flat_binder_object*>(parcelData + offset);
        // Copy till the object offset
        writeParcelData(fd, fillParcelBuffer, remainingPositions, parcelData, copiedDataPosition,
                        offset - copiedDataPosition);
        copiedDataPosition = offset;
        if (flatObject->hdr.type == BINDER_TYPE_BINDER ||
            flatObject->hdr.type == BINDER_TYPE_HANDLE) {
            writeRandomBinder(fd, fillParcelBuffer, remainingPositions);
            numBinders++;
            // In case of binder, stability is written after the binder object.
            // We want to move the copiedDataPosition further to account for this stability field
            copiedDataPosition += sizeof(int32_t) + sizeof(flat_binder_object);
        } else if (flatObject->hdr.type == BINDER_TYPE_FD) {
            writeRandomFd(fillParcelBuffer);
            numFds++;
            copiedDataPosition += sizeof(flat_binder_object);
        }
    }

    if (copiedDataPosition < dataSize) {
        // copy remaining data from recorded parcel -> last Object to end of the data
        writeParcelData(fd, fillParcelBuffer, remainingPositions, parcelData, copiedDataPosition,
                        dataSize - copiedDataPosition);
    }

    // We need to write bytes for selecting integer within range of  0 to provide.remaining_bytes()
    // is called.
    size_t totalWrittenBytes = dataSize - (sizeof(flat_binder_object) * objectOffsets.size()) -
            (sizeof(int32_t) * numBinders) +
            (kRandomInterfaceName.size() /*Interface String*/ + sizeof(bool) + sizeof(status_t)) *
                    numBinders;

    // Code in fuzzService relies on provider.remaining_bytes() to select random bytes using
    // consume integer. use the calculated remaining_bytes to generate byte buffer which can
    // generate required fds and binders in fillRandomParcel function.
    while (!remainingPositions.empty()) {
        auto meta = remainingPositions.top();
        remainingPositions.pop();
        size_t remainingBytes = totalWrittenBytes + fillParcelBuffer.size() - meta.position;

        vector<uint8_t> remReversedBytes;
        impl::writeReversedBuffer(remReversedBytes, static_cast<size_t>(0), remainingBytes,
                                  meta.value);
        // Check the order of buffer which is being written
        fillParcelBuffer.insert(fillParcelBuffer.end() - meta.position, remReversedBytes.begin(),
                                remReversedBytes.end());
    }

    return totalWrittenBytes;
}

/**
 * Current corpus format
 * |Reserved bytes(8)|parcel data|fillParcelBuffer|integralBuffer|
 */
void generateSeedsFromRecording(borrowed_fd fd,
                                const binder::debug::RecordedTransaction& transaction) {
    // Write Reserved bytes for future use
    std::vector<uint8_t> reservedBytes(8);
    CHECK(WriteFully(fd, reservedBytes.data(), reservedBytes.size())) << fd.get();

    std::vector<uint8_t> integralBuffer;

    // Write UID array : Array elements are initialized in the order that they are declared
    // UID array index 2 element
    // int64_t aidRoot = 0;
    impl::writeReversedBuffer(integralBuffer, static_cast<int64_t>(AID_ROOT) << 32,
                              static_cast<int64_t>(AID_USER) << 32,
                              static_cast<int64_t>(AID_ROOT) << 32);

    // UID array index 3 element
    impl::writeReversedBuffer(integralBuffer, static_cast<int64_t>(AID_ROOT) << 32);

    // always pick AID_ROOT -> index 0
    size_t uidIndex = 0;
    impl::writeReversedBuffer(integralBuffer, static_cast<size_t>(0), static_cast<size_t>(3),
                              uidIndex);

    // Never set uid in seed corpus
    uint8_t writeUid = 0;
    impl::writeReversedBuffer(integralBuffer, writeUid);

    // Read random code. this will be from recorded transaction
    uint8_t selectCode = 1;
    impl::writeReversedBuffer(integralBuffer, selectCode);

    // Get from recorded transaction
    uint32_t code = transaction.getCode();
    impl::writeReversedBuffer(integralBuffer, code);

    // Get from recorded transaction
    uint32_t flags = transaction.getFlags();
    impl::writeReversedBuffer(integralBuffer, flags);

    // always fuzz primary binder
    size_t extraBindersIndex = 0;
    impl::writeReversedBuffer(integralBuffer, static_cast<size_t>(0), static_cast<size_t>(0),
                              extraBindersIndex);

    const Parcel& dataParcel = transaction.getDataParcel();

    // This buffer holds the bytes which will be used for fillRandomParcel API
    std::vector<uint8_t> fillParcelBuffer;

    // Don't take rpc path
    uint8_t rpcBranch = 0;
    impl::writeReversedBuffer(fillParcelBuffer, rpcBranch);

    // Implicit branch on this path -> options->writeHeader(p, provider)
    uint8_t writeHeaderInternal = 0;
    impl::writeReversedBuffer(fillParcelBuffer, writeHeaderInternal);

    auto objectMetadata = transaction.getObjectOffsets();
    size_t toWrite = regenerateParcel(fd, fillParcelBuffer, dataParcel, dataParcel.dataBufferSize(),
                                      objectMetadata);

    // Write Fill Parcel buffer size in integralBuffer so that fuzzService knows size of data
    size_t subDataSize = toWrite + fillParcelBuffer.size();
    impl::writeReversedBuffer(integralBuffer, static_cast<size_t>(0), subDataSize, subDataSize);

    // Write fill parcel buffer
    CHECK(WriteFully(fd, fillParcelBuffer.data(), fillParcelBuffer.size())) << fd.get();

    // Write the integralBuffer to data
    CHECK(WriteFully(fd, integralBuffer.data(), integralBuffer.size())) << fd.get();
}
} // namespace android
