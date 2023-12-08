/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <condition_variable>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include "android-base/thread_annotations.h"

namespace android {

/**
 * A thread-safe FIFO queue. This list-backed queue stores up to <i>capacity</i> objects if
 * a capacity is provided at construction, and is otherwise unbounded.
 * Objects can always be added. Objects are added immediately.
 * If the queue is full, new objects cannot be added.
 *
 * The action of retrieving an object will block until an element is available.
 */
template <class T>
class BlockingQueue {
public:
    explicit BlockingQueue() = default;

    explicit BlockingQueue(size_t capacity) : mCapacity(capacity){};

    /**
     * Retrieve and remove the oldest object.
     * Blocks execution indefinitely while queue is empty.
     */
    T pop() {
        std::unique_lock lock(mLock);
        android::base::ScopedLockAssertion assumeLock(mLock);
        mHasElements.wait(lock, [this]() REQUIRES(mLock) { return !this->mQueue.empty(); });
        T t = std::move(mQueue.front());
        mQueue.erase(mQueue.begin());
        return t;
    };

    /**
     * Retrieve and remove the oldest object.
     * Blocks execution for the given duration while queue is empty, and returns std::nullopt
     * if the queue was empty for the entire duration.
     */
    std::optional<T> popWithTimeout(std::chrono::nanoseconds duration) {
        std::unique_lock lock(mLock);
        android::base::ScopedLockAssertion assumeLock(mLock);
        if (!mHasElements.wait_for(lock, duration,
                                   [this]() REQUIRES(mLock) { return !this->mQueue.empty(); })) {
            return {};
        }
        T t = std::move(mQueue.front());
        mQueue.erase(mQueue.begin());
        return t;
    };

    /**
     * Add a new object to the queue.
     * Does not block.
     * Return true if an element was successfully added.
     * Return false if the queue is full.
     */
    bool push(T&& t) {
        { // acquire lock
            std::scoped_lock lock(mLock);
            if (mCapacity && mQueue.size() == mCapacity) {
                return false;
            }
            mQueue.push_back(std::move(t));
        } // release lock
        mHasElements.notify_one();
        return true;
    };

    /**
     * Construct a new object into the queue.
     * Does not block.
     * Return true if an element was successfully added.
     * Return false if the queue is full.
     */
    template <class... Args>
    bool emplace(Args&&... args) {
        { // acquire lock
            std::scoped_lock lock(mLock);
            if (mCapacity && mQueue.size() == mCapacity) {
                return false;
            }
            mQueue.emplace_back(args...);
        } // release lock
        mHasElements.notify_one();
        return true;
    };

    void erase_if(const std::function<bool(const T&)>& pred) {
        std::scoped_lock lock(mLock);
        std::erase_if(mQueue, pred);
    }

    /**
     * Remove all elements.
     * Does not block.
     */
    void clear() {
        std::scoped_lock lock(mLock);
        mQueue.clear();
    };

    /**
     * How many elements are currently stored in the queue.
     * Primary used for debugging.
     * Does not block.
     */
    size_t size() {
        std::scoped_lock lock(mLock);
        return mQueue.size();
    }

private:
    const std::optional<size_t> mCapacity;
    /**
     * Used to signal that mQueue is non-empty.
     */
    std::condition_variable mHasElements;
    /**
     * Lock for accessing and waiting on elements.
     */
    std::mutex mLock;
    std::list<T> mQueue GUARDED_BY(mLock);
};

} // namespace android
