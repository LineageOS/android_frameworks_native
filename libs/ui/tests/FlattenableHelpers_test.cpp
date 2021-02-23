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

#define LOG_TAG "FlattenableHelpersTest"

#include <ui/FlattenableHelpers.h>

#include <gtest/gtest.h>
#include <utils/Flattenable.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace android {

namespace {

struct TestLightFlattenable : LightFlattenable<TestLightFlattenable> {
    std::unique_ptr<int32_t> ptr;

    bool isFixedSize() const { return true; }
    size_t getFlattenedSize() const { return sizeof(int32_t); }

    status_t flatten(void* buffer, size_t size) const {
        FlattenableUtils::write(buffer, size, *ptr);
        return OK;
    }

    status_t unflatten(void const* buffer, size_t size) {
        int32_t value;
        FlattenableUtils::read(buffer, size, value);
        ptr = std::make_unique<int32_t>(value);
        return OK;
    }
};

class FlattenableHelpersTest : public testing::Test {
public:
    template <class T>
    void testWriteThenRead(const T& value, size_t bufferSize) {
        std::vector<int8_t> buffer(bufferSize);
        auto rawBuffer = reinterpret_cast<void*>(buffer.data());
        size_t size = buffer.size();
        ASSERT_EQ(OK, FlattenableHelpers::flatten(&rawBuffer, &size, value));

        auto rawReadBuffer = reinterpret_cast<const void*>(buffer.data());
        size = buffer.size();
        T valueRead;
        ASSERT_EQ(OK, FlattenableHelpers::unflatten(&rawReadBuffer, &size, &valueRead));
        EXPECT_EQ(value, valueRead);
    }

    template <class T>
    void testTriviallyCopyable(const T& value) {
        testWriteThenRead(value, sizeof(T));
    }

    template <class T>
    void testWriteThenRead(const T& value) {
        testWriteThenRead(value, FlattenableHelpers::getFlattenedSize(value));
    }
};

TEST_F(FlattenableHelpersTest, TriviallyCopyable) {
    testTriviallyCopyable(42);
    testTriviallyCopyable(1LL << 63);
    testTriviallyCopyable(false);
    testTriviallyCopyable(true);
    testTriviallyCopyable(std::optional<int>());
    testTriviallyCopyable(std::optional<int>(4));
}

TEST_F(FlattenableHelpersTest, String) {
    testWriteThenRead(std::string("Android"));
    testWriteThenRead(std::string());
}

TEST_F(FlattenableHelpersTest, Vector) {
    testWriteThenRead(std::vector<int>({1, 2, 3}));
    testWriteThenRead(std::vector<int>());
}

TEST_F(FlattenableHelpersTest, OptionalOfLightFlattenable) {
    std::vector<size_t> buffer;
    constexpr int kInternalValue = 16;
    {
        std::optional<TestLightFlattenable> value =
                TestLightFlattenable{.ptr = std::make_unique<int32_t>(kInternalValue)};
        buffer.assign(FlattenableHelpers::getFlattenedSize(value), 0);
        void* rawBuffer = reinterpret_cast<void*>(buffer.data());
        size_t size = buffer.size();
        ASSERT_EQ(OK, FlattenableHelpers::flatten(&rawBuffer, &size, value));
    }

    const void* rawReadBuffer = reinterpret_cast<const void*>(buffer.data());
    size_t size = buffer.size();
    std::optional<TestLightFlattenable> valueRead;
    ASSERT_EQ(OK, FlattenableHelpers::unflatten(&rawReadBuffer, &size, &valueRead));
    ASSERT_TRUE(valueRead.has_value());
    EXPECT_EQ(kInternalValue, *valueRead->ptr);
}

TEST_F(FlattenableHelpersTest, NullOptionalOfLightFlattenable) {
    std::vector<size_t> buffer;
    {
        std::optional<TestLightFlattenable> value;
        buffer.assign(FlattenableHelpers::getFlattenedSize(value), 0);
        void* rawBuffer = reinterpret_cast<void*>(buffer.data());
        size_t size = buffer.size();
        ASSERT_EQ(OK, FlattenableHelpers::flatten(&rawBuffer, &size, value));
    }

    const void* rawReadBuffer = reinterpret_cast<const void*>(buffer.data());
    size_t size = buffer.size();
    std::optional<TestLightFlattenable> valueRead;
    ASSERT_EQ(OK, FlattenableHelpers::unflatten(&rawReadBuffer, &size, &valueRead));
    ASSERT_FALSE(valueRead.has_value());
}

// If a struct is both trivially copyable and light flattenable we should treat it
// as LigthFlattenable.
TEST_F(FlattenableHelpersTest, TriviallyCopyableAndLightFlattenableIsFlattenedAsLightFlattenable) {
    static constexpr int32_t kSizeTag = 1234567;
    static constexpr int32_t kFlattenTag = 987654;
    static constexpr int32_t kUnflattenTag = 5926582;

    struct LightFlattenableAndTriviallyCopyable
          : LightFlattenable<LightFlattenableAndTriviallyCopyable> {
        int32_t value;

        bool isFixedSize() const { return true; }
        size_t getFlattenedSize() const { return kSizeTag; }

        status_t flatten(void* buffer, size_t size) const {
            FlattenableUtils::write(buffer, size, kFlattenTag);
            return OK;
        }

        status_t unflatten(void const*, size_t) {
            value = kUnflattenTag;
            return OK;
        }
    };

    {
        // Verify that getFlattenedSize uses the LightFlattenable overload
        LightFlattenableAndTriviallyCopyable foo;
        EXPECT_EQ(kSizeTag, FlattenableHelpers::getFlattenedSize(foo));
    }

    {
        // Verify that flatten uses the LightFlattenable overload
        std::vector<int8_t> buffer(sizeof(int32_t));
        auto rawBuffer = reinterpret_cast<void*>(buffer.data());
        size_t size = buffer.size();
        LightFlattenableAndTriviallyCopyable foo;
        ASSERT_EQ(OK, FlattenableHelpers::flatten(&rawBuffer, &size, foo));

        auto rawReadBuffer = reinterpret_cast<const void*>(buffer.data());
        int32_t value;
        FlattenableHelpers::unflatten(&rawReadBuffer, &size, &value);
        EXPECT_EQ(kFlattenTag, value);
    }

    {
        // Verify that unflatten uses the LightFlattenable overload
        std::vector<int8_t> buffer(sizeof(int32_t));
        auto rawBuffer = reinterpret_cast<void*>(buffer.data());
        size_t size = buffer.size();
        int32_t value = 4;
        ASSERT_EQ(OK, FlattenableHelpers::flatten(&rawBuffer, &size, value));

        auto rawReadBuffer = reinterpret_cast<const void*>(buffer.data());

        LightFlattenableAndTriviallyCopyable foo;
        FlattenableHelpers::unflatten(&rawReadBuffer, &size, &foo);
        EXPECT_EQ(kUnflattenTag, foo.value);
    }
}

} // namespace
} // namespace android
