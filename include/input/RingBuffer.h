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

#pragma once

#include <algorithm>
#include <compare>
#include <cstddef>
#include <iterator>
#include <memory>
#include <type_traits>
#include <utility>

#include <android-base/stringprintf.h>

namespace android {

// A fixed-size ring buffer of elements.
//
// Elements can only be removed from the front/back or added to the front/back, but with O(1)
// performance. Elements from the opposing side are evicted when new elements are pushed onto a full
// buffer.
template <typename T>
class RingBuffer {
public:
    using value_type = T;
    using size_type = size_t;
    using difference_type = ptrdiff_t;
    using reference = value_type&;
    using const_reference = const value_type&;
    using pointer = value_type*;
    using const_pointer = const value_type*;

    template <typename U>
    class Iterator;
    using iterator = Iterator<T>;
    using const_iterator = Iterator<const T>;

    // Creates an empty ring buffer that can hold some capacity.
    explicit RingBuffer(size_type capacity)
          : mBuffer(std::allocator<value_type>().allocate(capacity)), mCapacity(capacity) {}

    // Creates a full ring buffer holding a fixed number of elements initialised to some value.
    explicit RingBuffer(size_type count, const_reference value) : RingBuffer(count) {
        while (count) {
            pushBack(value);
            --count;
        }
    }

    RingBuffer(const RingBuffer& other) : RingBuffer(other.capacity()) {
        for (const auto& element : other) {
            pushBack(element);
        }
    }

    RingBuffer(RingBuffer&& other) noexcept { *this = std::move(other); }

    ~RingBuffer() {
        if (mBuffer) {
            clear();
            std::allocator<value_type>().deallocate(mBuffer, mCapacity);
        }
    }

    RingBuffer& operator=(const RingBuffer& other) { return *this = RingBuffer(other); }

    RingBuffer& operator=(RingBuffer&& other) noexcept {
        if (this == &other) {
            return *this;
        }
        if (mBuffer) {
            clear();
            std::allocator<value_type>().deallocate(mBuffer, mCapacity);
        }
        mBuffer = std::move(other.mBuffer);
        mCapacity = other.mCapacity;
        mBegin = other.mBegin;
        mSize = other.mSize;
        other.mBuffer = nullptr;
        other.mCapacity = 0;
        other.mBegin = 0;
        other.mSize = 0;
        return *this;
    }

    iterator begin() { return {*this, 0}; }
    const_iterator begin() const { return {*this, 0}; }
    iterator end() { return {*this, mSize}; }
    const_iterator end() const { return {*this, mSize}; }

    reference front() { return mBuffer[mBegin]; }
    const_reference front() const { return mBuffer[mBegin]; }
    reference back() { return mBuffer[bufferIndex(mSize - 1)]; }
    const_reference back() const { return mBuffer[bufferIndex(mSize - 1)]; }

    reference operator[](size_type i) { return mBuffer[bufferIndex(i)]; }
    const_reference operator[](size_type i) const { return mBuffer[bufferIndex(i)]; }

    // Removes all elements from the buffer.
    void clear() {
        std::destroy(begin(), end());
        mSize = 0;
    }

    // Removes and returns the first element from the buffer.
    value_type popFront() {
        value_type element = mBuffer[mBegin];
        std::destroy_at(std::addressof(mBuffer[mBegin]));
        mBegin = next(mBegin);
        --mSize;
        return element;
    }

    // Removes and returns the last element from the buffer.
    value_type popBack() {
        size_type backIndex = bufferIndex(mSize - 1);
        value_type element = mBuffer[backIndex];
        std::destroy_at(std::addressof(mBuffer[backIndex]));
        --mSize;
        return element;
    }

    // Adds an element to the front of the buffer.
    void pushFront(const value_type& element) { pushFront(value_type(element)); }
    void pushFront(value_type&& element) {
        mBegin = previous(mBegin);
        if (size() == capacity()) {
            mBuffer[mBegin] = std::forward<value_type>(element);
        } else {
            // The space at mBuffer[mBegin] is uninitialised.
            // TODO: Use std::construct_at when it becomes available.
            new (std::addressof(mBuffer[mBegin])) value_type(std::forward<value_type>(element));
            ++mSize;
        }
    }

    // Adds an element to the back of the buffer.
    void pushBack(const value_type& element) { pushBack(value_type(element)); }
    void pushBack(value_type&& element) {
        if (size() == capacity()) {
            mBuffer[mBegin] = std::forward<value_type>(element);
            mBegin = next(mBegin);
        } else {
            // The space at mBuffer[...] is uninitialised.
            // TODO: Use std::construct_at when it becomes available.
            new (std::addressof(mBuffer[bufferIndex(mSize)]))
                    value_type(std::forward<value_type>(element));
            ++mSize;
        }
    }

    bool empty() const { return mSize == 0; }
    size_type capacity() const { return mCapacity; }
    size_type size() const { return mSize; }

    void swap(RingBuffer& other) noexcept {
        using std::swap;
        swap(mBuffer, other.mBuffer);
        swap(mCapacity, other.mCapacity);
        swap(mBegin, other.mBegin);
        swap(mSize, other.mSize);
    }

    friend void swap(RingBuffer& lhs, RingBuffer& rhs) noexcept { lhs.swap(rhs); }

    template <typename U>
    class Iterator {
    private:
        using ContainerType = std::conditional_t<std::is_const_v<U>, const RingBuffer, RingBuffer>;

    public:
        using iterator_category = std::random_access_iterator_tag;
        using size_type = ContainerType::size_type;
        using difference_type = ContainerType::difference_type;
        using value_type = std::remove_cv_t<U>;
        using pointer = U*;
        using reference = U&;

        Iterator(ContainerType& container, size_type index)
              : mContainer(container), mIndex(index) {}

        Iterator(const Iterator&) = default;
        Iterator& operator=(const Iterator&) = default;

        Iterator& operator++() {
            ++mIndex;
            return *this;
        }

        Iterator operator++(int) {
            Iterator iterator(*this);
            ++(*this);
            return iterator;
        }

        Iterator& operator--() {
            --mIndex;
            return *this;
        }

        Iterator operator--(int) {
            Iterator iterator(*this);
            --(*this);
            return iterator;
        }

        Iterator& operator+=(difference_type n) {
            mIndex += n;
            return *this;
        }

        Iterator operator+(difference_type n) {
            Iterator iterator(*this);
            return iterator += n;
        }

        Iterator& operator-=(difference_type n) { return *this += -n; }

        Iterator operator-(difference_type n) {
            Iterator iterator(*this);
            return iterator -= n;
        }

        difference_type operator-(const Iterator& other) { return mIndex - other.mIndex; }

        bool operator==(const Iterator& rhs) const { return mIndex == rhs.mIndex; }

        bool operator!=(const Iterator& rhs) const { return !(*this == rhs); }

        friend auto operator<=>(const Iterator& lhs, const Iterator& rhs) {
            return lhs.mIndex <=> rhs.mIndex;
        }

        reference operator[](difference_type n) { return *(*this + n); }

        reference operator*() const { return mContainer[mIndex]; }
        pointer operator->() const { return std::addressof(mContainer[mIndex]); }

    private:
        ContainerType& mContainer;
        size_type mIndex = 0;
    };

private:
    // Returns the index of the next element in mBuffer.
    size_type next(size_type index) const {
        if (index == capacity() - 1) {
            return 0;
        } else {
            return index + 1;
        }
    }

    // Returns the index of the previous element in mBuffer.
    size_type previous(size_type index) const {
        if (index == 0) {
            return capacity() - 1;
        } else {
            return index - 1;
        }
    }

    // Converts the index of an element in [0, size()] to its corresponding index in mBuffer.
    size_type bufferIndex(size_type elementIndex) const {
        if (elementIndex > size()) {
            abort();
        }
        size_type index = mBegin + elementIndex;
        if (index >= capacity()) {
            index -= capacity();
        }
        if (index >= capacity()) {
            abort();
        }
        return index;
    }

    pointer mBuffer = nullptr;
    size_type mCapacity = 0; // Total capacity of mBuffer.
    size_type mBegin = 0;    // Index of the first initialised element in mBuffer.
    size_type mSize = 0;     // Total number of initialised elements.
};

} // namespace android
