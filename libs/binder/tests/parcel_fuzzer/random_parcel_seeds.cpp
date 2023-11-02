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

#include <android-base/logging.h>

#include <binder/RecordedTransaction.h>

#include <fuzzseeds/random_parcel_seeds.h>

#include "../../file.h"

using android::binder::borrowed_fd;
using android::binder::WriteFully;

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

    // Choose to write data in parcel
    size_t fillFuncIndex = 0;
    impl::writeReversedBuffer(fillParcelBuffer, static_cast<size_t>(0), static_cast<size_t>(2),
                              fillFuncIndex);

    // Write parcel data size from recorded transaction
    size_t toWrite = transaction.getDataParcel().dataBufferSize();
    impl::writeReversedBuffer(fillParcelBuffer, static_cast<size_t>(0), toWrite, toWrite);

    // Write parcel data with size towrite from recorded transaction
    CHECK(WriteFully(fd, dataParcel.data(), toWrite)) << fd.get();

    // Write Fill Parcel buffer size in integralBuffer so that fuzzService knows size of data
    size_t subDataSize = toWrite + fillParcelBuffer.size();
    impl::writeReversedBuffer(integralBuffer, static_cast<size_t>(0), subDataSize, subDataSize);

    // Write fill parcel buffer
    CHECK(WriteFully(fd, fillParcelBuffer.data(), fillParcelBuffer.size())) << fd.get();

    // Write the integralBuffer to data
    CHECK(WriteFully(fd, integralBuffer.data(), integralBuffer.size())) << fd.get();
}
} // namespace android
