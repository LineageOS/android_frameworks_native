/*
 * Copyright 2023 The Android Open Source Project
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

#pragma once

#include <stddef.h>
#include <array>

namespace android::utils {

template <class T, size_t SIZE>
class RingBuffer {
    RingBuffer(const RingBuffer&) = delete;
    void operator=(const RingBuffer&) = delete;

public:
    RingBuffer() = default;
    ~RingBuffer() = default;

    constexpr size_t capacity() const { return SIZE; }

    size_t size() const { return mCount; }

    T& next() {
        mHead = static_cast<size_t>(mHead + 1) % SIZE;
        if (mCount < SIZE) {
            mCount++;
        }
        return mBuffer[static_cast<size_t>(mHead)];
    }

    T& front() { return (*this)[0]; }

    T& back() { return (*this)[size() - 1]; }

    T& operator[](size_t index) {
        return mBuffer[(static_cast<size_t>(mHead + 1) + index) % mCount];
    }

    const T& operator[](size_t index) const {
        return mBuffer[(static_cast<size_t>(mHead + 1) + index) % mCount];
    }

    void clear() {
        mCount = 0;
        mHead = -1;
    }

private:
    std::array<T, SIZE> mBuffer;
    int mHead = -1;
    size_t mCount = 0;
};

} // namespace android::utils
