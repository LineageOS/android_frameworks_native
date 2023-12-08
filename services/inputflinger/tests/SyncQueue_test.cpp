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

#include "../SyncQueue.h"

#include <gtest/gtest.h>
#include <thread>

namespace android {

// --- SyncQueueTest ---

// Validate basic pop and push operation.
TEST(SyncQueueTest, AddAndRemove) {
    SyncQueue<int> queue;

    queue.push(1);
    ASSERT_EQ(queue.pop(), 1);

    queue.push(3);
    ASSERT_EQ(queue.pop(), 3);

    ASSERT_EQ(std::nullopt, queue.pop());
}

// Make sure the queue maintains FIFO order.
// Add elements and remove them, and check the order.
TEST(SyncQueueTest, isFIFO) {
    SyncQueue<int> queue;

    constexpr int numItems = 10;
    for (int i = 0; i < numItems; i++) {
        queue.push(static_cast<int>(i));
    }
    for (int i = 0; i < numItems; i++) {
        ASSERT_EQ(queue.pop(), static_cast<int>(i));
    }
}

// Make sure the queue has strict capacity limits.
TEST(SyncQueueTest, QueueReachesCapacity) {
    constexpr size_t capacity = 3;
    SyncQueue<int> queue(capacity);

    // First 3 elements should be added successfully
    ASSERT_TRUE(queue.push(1));
    ASSERT_TRUE(queue.push(2));
    ASSERT_TRUE(queue.push(3));
    ASSERT_FALSE(queue.push(4)) << "Queue should reach capacity at size " << capacity;
}

TEST(SyncQueueTest, AllowsMultipleThreads) {
    SyncQueue<int> queue;

    // Test with a large number of items to increase likelihood that threads overlap
    constexpr int numItems = 100;

    // Fill queue from a different thread
    std::thread fillQueue([&queue]() {
        for (int i = 0; i < numItems; i++) {
            queue.push(static_cast<int>(i));
        }
    });

    // Make sure all elements are received in correct order
    for (int i = 0; i < numItems; i++) {
        // Since popping races with the thread that's filling the queue,
        // keep popping until we get something back
        std::optional<int> popped;
        do {
            popped = queue.pop();
        } while (!popped);
        ASSERT_EQ(popped, static_cast<int>(i));
    }

    fillQueue.join();
}

} // namespace android
