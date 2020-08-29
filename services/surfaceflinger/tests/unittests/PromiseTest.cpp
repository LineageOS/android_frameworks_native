/*
 * Copyright 2020 The Android Open Source Project
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
#include <future>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "Promise.h"

namespace android {
namespace {

using Bytes = std::vector<uint8_t>;

Bytes decrement(Bytes bytes) {
    std::transform(bytes.begin(), bytes.end(), bytes.begin(), [](auto b) { return b - 1; });
    return bytes;
}

} // namespace

TEST(PromiseTest, yield) {
    EXPECT_EQ(42, promise::yield(42).get());

    auto ptr = std::make_unique<char>('!');
    auto future = promise::yield(std::move(ptr));
    EXPECT_EQ('!', *future.get());
}

TEST(PromiseTest, chain) {
    std::packaged_task<const char*()> fetchString([] { return "ifmmp-"; });

    std::packaged_task<Bytes(std::string)> appendString([](std::string str) {
        str += "!xpsme";
        return Bytes{str.begin(), str.end()};
    });

    std::packaged_task<std::future<Bytes>(Bytes)> decrementBytes(
            [](Bytes bytes) { return promise::defer(decrement, std::move(bytes)); });

    auto fetch = fetchString.get_future();
    std::thread fetchThread(std::move(fetchString));

    std::thread appendThread, decrementThread;

    EXPECT_EQ("hello, world",
              promise::chain(std::move(fetch))
                      .then([](const char* str) { return std::string(str); })
                      .then([&](std::string str) {
                          auto append = appendString.get_future();
                          appendThread = std::thread(std::move(appendString), std::move(str));
                          return append;
                      })
                      .then([&](Bytes bytes) {
                          auto decrement = decrementBytes.get_future();
                          decrementThread = std::thread(std::move(decrementBytes),
                                                        std::move(bytes));
                          return decrement;
                      })
                      .then([](std::future<Bytes> bytes) { return bytes; })
                      .then([](const Bytes& bytes) {
                          return std::string(bytes.begin(), bytes.end());
                      })
                      .get());

    fetchThread.join();
    appendThread.join();
    decrementThread.join();
}

} // namespace android
