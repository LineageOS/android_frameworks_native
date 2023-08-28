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

#include <ftl/non_null.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <string_view>

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
  std::size_t size;
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

}  // namespace
}  // namespace android::test
