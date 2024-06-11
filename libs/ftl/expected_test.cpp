/*
 * Copyright 2024 The Android Open Source Project
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

#include <ftl/expected.h>
#include <ftl/optional.h>
#include <ftl/unit.h>
#include <gtest/gtest.h>

#include <cctype>
#include <string>
#include <system_error>

namespace android::test {

using IntExp = ftl::Expected<int, std::errc>;
using StringExp = ftl::Expected<std::string, std::errc>;

using namespace std::string_literals;

TEST(Expected, Construct) {
  // Default value.
  EXPECT_TRUE(IntExp().has_value());
  EXPECT_EQ(IntExp(), IntExp(0));

  EXPECT_TRUE(StringExp().has_value());
  EXPECT_EQ(StringExp(), StringExp(""));

  // Value.
  ASSERT_TRUE(IntExp(42).has_value());
  EXPECT_EQ(42, IntExp(42).value());

  ASSERT_TRUE(StringExp("test").has_value());
  EXPECT_EQ("test"s, StringExp("test").value());

  // Error.
  const auto exp = StringExp(ftl::Unexpected(std::errc::invalid_argument));
  ASSERT_FALSE(exp.has_value());
  EXPECT_EQ(std::errc::invalid_argument, exp.error());
}

TEST(Expected, HasError) {
  EXPECT_FALSE(IntExp(123).has_error([](auto) { return true; }));
  EXPECT_FALSE(IntExp(ftl::Unexpected(std::errc::io_error)).has_error([](auto) { return false; }));

  EXPECT_TRUE(StringExp(ftl::Unexpected(std::errc::permission_denied)).has_error([](auto e) {
    return e == std::errc::permission_denied;
  }));
}

TEST(Expected, ValueOpt) {
  EXPECT_EQ(ftl::Optional(-1), IntExp(-1).value_opt());
  EXPECT_EQ(std::nullopt, IntExp(ftl::Unexpected(std::errc::broken_pipe)).value_opt());

  {
    const StringExp exp("foo"s);
    EXPECT_EQ(ftl::Optional('f'),
              exp.value_opt().transform([](const auto& s) { return s.front(); }));
    EXPECT_EQ("foo"s, exp.value());
  }
  {
    StringExp exp("foobar"s);
    EXPECT_EQ(ftl::Optional(6), std::move(exp).value_opt().transform(&std::string::length));
    EXPECT_TRUE(exp.value().empty());
  }
}

namespace {

IntExp increment_try(IntExp exp) {
  const int i = FTL_TRY(exp);
  return IntExp(i + 1);
}

std::errc increment_expect(IntExp exp, int& out) {
  const int i = FTL_EXPECT(exp);
  out = i + 1;
  return std::errc::operation_in_progress;
}

StringExp repeat_try(StringExp exp) {
  const std::string str = FTL_TRY(exp);
  return StringExp(str + str);
}

std::errc repeat_expect(StringExp exp, std::string& out) {
  const std::string str = FTL_EXPECT(exp);
  out = str + str;
  return std::errc::operation_in_progress;
}

void uppercase(char& c, ftl::Optional<char> opt) {
  c = std::toupper(FTL_TRY(std::move(opt).ok_or(ftl::Unit())));
}

}  // namespace

// Keep in sync with example usage in header file.
TEST(Expected, Try) {
  EXPECT_EQ(IntExp(100), increment_try(IntExp(99)));
  EXPECT_TRUE(increment_try(ftl::Unexpected(std::errc::value_too_large)).has_error([](std::errc e) {
    return e == std::errc::value_too_large;
  }));

  EXPECT_EQ(StringExp("haha"s), repeat_try(StringExp("ha"s)));
  EXPECT_TRUE(repeat_try(ftl::Unexpected(std::errc::bad_message)).has_error([](std::errc e) {
    return e == std::errc::bad_message;
  }));

  char c = '?';
  uppercase(c, std::nullopt);
  EXPECT_EQ(c, '?');

  uppercase(c, 'a');
  EXPECT_EQ(c, 'A');
}

TEST(Expected, Expect) {
  int i = 0;
  EXPECT_EQ(std::errc::operation_in_progress, increment_expect(IntExp(99), i));
  EXPECT_EQ(100, i);
  EXPECT_EQ(std::errc::value_too_large,
            increment_expect(ftl::Unexpected(std::errc::value_too_large), i));
  EXPECT_EQ(100, i);

  std::string str;
  EXPECT_EQ(std::errc::operation_in_progress, repeat_expect(StringExp("ha"s), str));
  EXPECT_EQ("haha"s, str);
  EXPECT_EQ(std::errc::bad_message, repeat_expect(ftl::Unexpected(std::errc::bad_message), str));
  EXPECT_EQ("haha"s, str);
}

}  // namespace android::test
