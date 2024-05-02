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

#include <ftl/algorithm.h>
#include <ftl/non_null.h>
#include <gtest/gtest.h>

#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <vector>

namespace android::test {
namespace {

void get_length(const ftl::NonNull<std::shared_ptr<std::string>>& string_ptr,
                ftl::NonNull<std::size_t*> length_ptr) {
  // No need for `nullptr` checks.
  *length_ptr = string_ptr->length();
}

using Pair = std::pair<ftl::NonNull<std::shared_ptr<int>>, std::shared_ptr<int>>;

Pair dupe_if(ftl::NonNull<std::unique_ptr<int>> non_null_ptr, bool condition) {
  // Move the underlying pointer out, so `non_null_ptr` must not be accessed after this point.
  auto unique_ptr = std::move(non_null_ptr).take();

  auto non_null_shared_ptr = ftl::as_non_null(std::shared_ptr<int>(std::move(unique_ptr)));
  auto nullable_shared_ptr = condition ? non_null_shared_ptr.get() : nullptr;

  return {std::move(non_null_shared_ptr), std::move(nullable_shared_ptr)};
}

}  // namespace

// Keep in sync with example usage in header file.
TEST(NonNull, Example) {
  const auto string_ptr = ftl::as_non_null(std::make_shared<std::string>("android"));
  std::size_t size{};
  get_length(string_ptr, ftl::as_non_null(&size));
  EXPECT_EQ(size, 7u);

  auto ptr = ftl::as_non_null(std::make_unique<int>(42));
  const auto [ptr1, ptr2] = dupe_if(std::move(ptr), true);
  EXPECT_EQ(ptr1.get(), ptr2);
}

namespace {

constexpr std::string_view kApple = "apple";
constexpr std::string_view kOrange = "orange";

using StringViewPtr = ftl::NonNull<const std::string_view*>;
constexpr StringViewPtr kApplePtr = ftl::as_non_null(&kApple);
constexpr StringViewPtr kOrangePtr = ftl::as_non_null(&kOrange);

constexpr StringViewPtr longest(StringViewPtr ptr1, StringViewPtr ptr2) {
  return ptr1->length() > ptr2->length() ? ptr1 : ptr2;
}

static_assert(longest(kApplePtr, kOrangePtr) == kOrangePtr);

static_assert(static_cast<bool>(kApplePtr));

static_assert(std::is_same_v<decltype(ftl::as_non_null(std::declval<const int* const>())),
                             ftl::NonNull<const int*>>);

}  // namespace

TEST(NonNull, SwapRawPtr) {
  int i1 = 123;
  int i2 = 456;
  auto ptr1 = ftl::as_non_null(&i1);
  auto ptr2 = ftl::as_non_null(&i2);

  std::swap(ptr1, ptr2);

  EXPECT_EQ(*ptr1, 456);
  EXPECT_EQ(*ptr2, 123);
}

TEST(NonNull, SwapSmartPtr) {
  auto ptr1 = ftl::as_non_null(std::make_shared<int>(123));
  auto ptr2 = ftl::as_non_null(std::make_shared<int>(456));

  std::swap(ptr1, ptr2);

  EXPECT_EQ(*ptr1, 456);
  EXPECT_EQ(*ptr2, 123);
}

TEST(NonNull, VectorOfRawPtr) {
  int i = 1;
  std::vector<ftl::NonNull<int*>> vpi;
  vpi.push_back(ftl::as_non_null(&i));
  EXPECT_FALSE(ftl::contains(vpi, nullptr));
  EXPECT_TRUE(ftl::contains(vpi, &i));
  EXPECT_TRUE(ftl::contains(vpi, vpi.front()));
}

TEST(NonNull, VectorOfSmartPtr) {
  std::vector<ftl::NonNull<std::shared_ptr<int>>> vpi;
  vpi.push_back(ftl::as_non_null(std::make_shared<int>(2)));
  EXPECT_FALSE(ftl::contains(vpi, nullptr));
  EXPECT_TRUE(ftl::contains(vpi, vpi.front().get()));
  EXPECT_TRUE(ftl::contains(vpi, vpi.front()));
}

TEST(NonNull, SetOfRawPtr) {
  int i = 1;
  std::set<ftl::NonNull<int*>> spi;
  spi.insert(ftl::as_non_null(&i));
  EXPECT_FALSE(ftl::contains(spi, nullptr));
  EXPECT_TRUE(ftl::contains(spi, &i));
  EXPECT_TRUE(ftl::contains(spi, *spi.begin()));
}

TEST(NonNull, SetOfSmartPtr) {
  std::set<ftl::NonNull<std::shared_ptr<int>>> spi;
  spi.insert(ftl::as_non_null(std::make_shared<int>(2)));
  EXPECT_FALSE(ftl::contains(spi, nullptr));
  EXPECT_TRUE(ftl::contains(spi, spi.begin()->get()));
  EXPECT_TRUE(ftl::contains(spi, *spi.begin()));
}

TEST(NonNull, UnorderedSetOfRawPtr) {
  int i = 1;
  std::unordered_set<ftl::NonNull<int*>> spi;
  spi.insert(ftl::as_non_null(&i));
  EXPECT_FALSE(ftl::contains(spi, nullptr));
  EXPECT_TRUE(ftl::contains(spi, &i));
  EXPECT_TRUE(ftl::contains(spi, *spi.begin()));
}

TEST(NonNull, UnorderedSetOfSmartPtr) {
  std::unordered_set<ftl::NonNull<std::shared_ptr<int>>> spi;
  spi.insert(ftl::as_non_null(std::make_shared<int>(2)));
  EXPECT_FALSE(ftl::contains(spi, nullptr));
  EXPECT_TRUE(ftl::contains(spi, spi.begin()->get()));
  EXPECT_TRUE(ftl::contains(spi, *spi.begin()));
}

}  // namespace android::test
