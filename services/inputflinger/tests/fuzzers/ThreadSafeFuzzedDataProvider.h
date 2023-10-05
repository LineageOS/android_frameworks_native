/*
 * Copyright 2022 The Android Open Source Project
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

#include <fuzzer/FuzzedDataProvider.h>

/**
 * A thread-safe interface to the FuzzedDataProvider
 */
class ThreadSafeFuzzedDataProvider : FuzzedDataProvider {
private:
    std::mutex mLock;

public:
    ThreadSafeFuzzedDataProvider(const uint8_t* data, size_t size)
          : FuzzedDataProvider(data, size) {}

    template <typename T>
    std::vector<T> ConsumeBytes(size_t num_bytes) {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeBytes<T>(num_bytes);
    }

    template <typename T>
    std::vector<T> ConsumeBytesWithTerminator(size_t num_bytes, T terminator) {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeBytesWithTerminator<T>(num_bytes, terminator);
    }

    template <typename T>
    std::vector<T> ConsumeRemainingBytes() {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeRemainingBytes<T>();
    }

    std::string ConsumeBytesAsString(size_t num_bytes) {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeBytesAsString(num_bytes);
    }

    std::string ConsumeRandomLengthString(size_t max_length) {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeRandomLengthString(max_length);
    }

    std::string ConsumeRandomLengthString() {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeRandomLengthString();
    }

    std::string ConsumeRemainingBytesAsString() {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeRemainingBytesAsString();
    }

    template <typename T>
    T ConsumeIntegral() {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeIntegral<T>();
    }

    template <typename T>
    T ConsumeIntegralInRange(T min, T max) {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeIntegralInRange<T>(min, max);
    }

    template <typename T>
    T ConsumeFloatingPoint() {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeFloatingPoint<T>();
    }

    template <typename T>
    T ConsumeFloatingPointInRange(T min, T max) {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeFloatingPointInRange<T>(min, max);
    }

    template <typename T>
    T ConsumeProbability() {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeProbability<T>();
    }

    bool ConsumeBool() {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeBool();
    }

    template <typename T>
    T ConsumeEnum() {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeEnum<T>();
    }

    template <typename T, size_t size>
    T PickValueInArray(const T (&array)[size]) {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::PickValueInArray(array);
    }

    template <typename T, size_t size>
    T PickValueInArray(const std::array<T, size>& array) {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::PickValueInArray(array);
    }

    template <typename T>
    T PickValueInArray(std::initializer_list<const T> list) {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::PickValueInArray(list);
    }

    size_t ConsumeData(void* destination, size_t num_bytes) {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::ConsumeData(destination, num_bytes);
    }

    size_t remaining_bytes() {
        std::scoped_lock _l(mLock);
        return FuzzedDataProvider::remaining_bytes();
    }
};
