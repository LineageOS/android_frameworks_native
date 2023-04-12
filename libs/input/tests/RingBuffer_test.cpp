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

#include <algorithm>
#include <iterator>
#include <memory>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <input/RingBuffer.h>

namespace android {
namespace {

using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::SizeIs;

TEST(RingBufferTest, PushPop) {
    RingBuffer<int> buffer(/*capacity=*/3);

    buffer.pushBack(1);
    buffer.pushBack(2);
    buffer.pushBack(3);
    EXPECT_THAT(buffer, ElementsAre(1, 2, 3));

    buffer.pushBack(4);
    EXPECT_THAT(buffer, ElementsAre(2, 3, 4));

    buffer.pushFront(1);
    EXPECT_THAT(buffer, ElementsAre(1, 2, 3));

    EXPECT_EQ(1, buffer.popFront());
    EXPECT_THAT(buffer, ElementsAre(2, 3));

    buffer.pushBack(4);
    EXPECT_THAT(buffer, ElementsAre(2, 3, 4));

    buffer.pushBack(5);
    EXPECT_THAT(buffer, ElementsAre(3, 4, 5));

    EXPECT_EQ(5, buffer.popBack());
    EXPECT_THAT(buffer, ElementsAre(3, 4));

    EXPECT_EQ(4, buffer.popBack());
    EXPECT_THAT(buffer, ElementsAre(3));

    EXPECT_EQ(3, buffer.popBack());
    EXPECT_THAT(buffer, ElementsAre());

    buffer.pushBack(1);
    EXPECT_THAT(buffer, ElementsAre(1));

    EXPECT_EQ(1, buffer.popFront());
    EXPECT_THAT(buffer, ElementsAre());
}

TEST(RingBufferTest, ObjectType) {
    RingBuffer<std::unique_ptr<int>> buffer(/*capacity=*/2);
    buffer.pushBack(std::make_unique<int>(1));
    buffer.pushBack(std::make_unique<int>(2));
    buffer.pushBack(std::make_unique<int>(3));

    EXPECT_EQ(2, *buffer[0]);
    EXPECT_EQ(3, *buffer[1]);
}

TEST(RingBufferTest, ConstructConstantValue) {
    RingBuffer<int> buffer(/*count=*/3, /*value=*/10);
    EXPECT_THAT(buffer, ElementsAre(10, 10, 10));
    EXPECT_EQ(3u, buffer.capacity());
}

TEST(RingBufferTest, Assignment) {
    RingBuffer<int> a(/*capacity=*/2);
    a.pushBack(1);
    a.pushBack(2);

    RingBuffer<int> b(/*capacity=*/3);
    b.pushBack(10);
    b.pushBack(20);
    b.pushBack(30);

    std::swap(a, b);
    EXPECT_THAT(a, ElementsAre(10, 20, 30));
    EXPECT_THAT(b, ElementsAre(1, 2));

    a = b;
    EXPECT_THAT(a, ElementsAreArray(b));

    RingBuffer<int> c(b);
    EXPECT_THAT(c, ElementsAreArray(b));

    RingBuffer<int> d(std::move(b));
    EXPECT_EQ(0u, b.capacity());
    EXPECT_THAT(b, ElementsAre());
    EXPECT_THAT(d, ElementsAre(1, 2));

    b = std::move(d);
    EXPECT_THAT(b, ElementsAre(1, 2));
    EXPECT_THAT(d, ElementsAre());
    EXPECT_EQ(0u, d.capacity());
}

TEST(RingBufferTest, FrontBackAccess) {
    RingBuffer<int> buffer(/*capacity=*/2);
    buffer.pushBack(1);
    EXPECT_EQ(1, buffer.front());
    EXPECT_EQ(1, buffer.back());

    buffer.pushFront(0);
    EXPECT_EQ(0, buffer.front());
    EXPECT_EQ(1, buffer.back());

    buffer.pushFront(-1);
    EXPECT_EQ(-1, buffer.front());
    EXPECT_EQ(0, buffer.back());
}

TEST(RingBufferTest, Subscripting) {
    RingBuffer<int> buffer(/*capacity=*/2);
    buffer.pushBack(1);
    EXPECT_EQ(1, buffer[0]);

    buffer.pushFront(0);
    EXPECT_EQ(0, buffer[0]);
    EXPECT_EQ(1, buffer[1]);

    buffer.pushFront(-1);
    EXPECT_EQ(-1, buffer[0]);
    EXPECT_EQ(0, buffer[1]);
}

TEST(RingBufferTest, Iterator) {
    RingBuffer<int> buffer(/*capacity=*/3);
    buffer.pushFront(2);
    buffer.pushBack(3);

    auto begin = buffer.begin();
    auto end = buffer.end();

    EXPECT_NE(begin, end);
    EXPECT_LE(begin, end);
    EXPECT_GT(end, begin);
    EXPECT_EQ(end, begin + 2);
    EXPECT_EQ(begin, end - 2);

    EXPECT_EQ(2, end - begin);
    EXPECT_EQ(1, end - (begin + 1));

    EXPECT_EQ(2, *begin);
    ++begin;
    EXPECT_EQ(3, *begin);
    --begin;
    EXPECT_EQ(2, *begin);
    begin += 1;
    EXPECT_EQ(3, *begin);
    begin += -1;
    EXPECT_EQ(2, *begin);
    begin -= -1;
    EXPECT_EQ(3, *begin);
}

TEST(RingBufferTest, Clear) {
    RingBuffer<int> buffer(/*capacity=*/2);
    EXPECT_THAT(buffer, ElementsAre());

    buffer.pushBack(1);
    EXPECT_THAT(buffer, ElementsAre(1));

    buffer.clear();
    EXPECT_THAT(buffer, ElementsAre());
    EXPECT_THAT(buffer, SizeIs(0));
    EXPECT_THAT(buffer, IsEmpty());

    buffer.pushFront(1);
    EXPECT_THAT(buffer, ElementsAre(1));
}

TEST(RingBufferTest, SizeAndIsEmpty) {
    RingBuffer<int> buffer(/*capacity=*/2);
    EXPECT_THAT(buffer, SizeIs(0));
    EXPECT_THAT(buffer, IsEmpty());

    buffer.pushBack(1);
    EXPECT_THAT(buffer, SizeIs(1));
    EXPECT_THAT(buffer, Not(IsEmpty()));

    buffer.pushBack(2);
    EXPECT_THAT(buffer, SizeIs(2));
    EXPECT_THAT(buffer, Not(IsEmpty()));

    buffer.pushBack(3);
    EXPECT_THAT(buffer, SizeIs(2));
    EXPECT_THAT(buffer, Not(IsEmpty()));

    buffer.popFront();
    EXPECT_THAT(buffer, SizeIs(1));
    EXPECT_THAT(buffer, Not(IsEmpty()));

    buffer.popBack();
    EXPECT_THAT(buffer, SizeIs(0));
    EXPECT_THAT(buffer, IsEmpty());
}

} // namespace
} // namespace android
