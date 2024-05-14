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

#include <ftl/expected.h>
#include <ftl/optional.h>
#include <ftl/static_vector.h>
#include <ftl/string.h>
#include <ftl/unit.h>
#include <gtest/gtest.h>

#include <cstdlib>
#include <functional>
#include <numeric>
#include <system_error>
#include <utility>

using namespace std::placeholders;
using namespace std::string_literals;

namespace android::test {

using ftl::Optional;
using ftl::StaticVector;

TEST(Optional, Construct) {
  // Empty.
  EXPECT_EQ(std::nullopt, Optional<int>());
  EXPECT_EQ(std::nullopt, Optional<std::string>(std::nullopt));

  // Value.
  EXPECT_EQ('?', Optional('?'));
  EXPECT_EQ(""s, Optional(std::string()));

  // In place.
  EXPECT_EQ("???"s, Optional<std::string>(std::in_place, 3u, '?'));
  EXPECT_EQ("abc"s, Optional<std::string>(std::in_place, {'a', 'b', 'c'}));

  // Implicit downcast.
  {
    Optional opt = std::optional("test"s);
    static_assert(std::is_same_v<decltype(opt), Optional<std::string>>);

    ASSERT_TRUE(opt);
    EXPECT_EQ(opt.value(), "test"s);
  }
}

TEST(Optional, Transform) {
  // Empty.
  EXPECT_EQ(std::nullopt, Optional<int>().transform([](int) { return 0; }));

  // By value.
  EXPECT_EQ(0, Optional(0).transform([](int x) { return x; }));
  EXPECT_EQ(100, Optional(99).transform([](int x) { return x + 1; }));
  EXPECT_EQ("0b100"s, Optional(4).transform(std::bind(ftl::to_string<int>, _1, ftl::Radix::kBin)));

  // By reference.
  {
    Optional opt = 'x';
    EXPECT_EQ('z', opt.transform([](char& c) {
      c = 'y';
      return 'z';
    }));

    EXPECT_EQ('y', opt);
  }

  // By rvalue reference.
  {
    std::string out;
    EXPECT_EQ("xyz"s, Optional("abc"s).transform([&out](std::string&& str) {
      out = std::move(str);
      return "xyz"s;
    }));

    EXPECT_EQ(out, "abc"s);
  }

  // No return value.
  {
    Optional opt = "food"s;
    EXPECT_EQ(ftl::unit, opt.transform(ftl::unit_fn([](std::string& str) { str.pop_back(); })));
    EXPECT_EQ(opt, "foo"s);
  }

  // Chaining.
  EXPECT_EQ(14u, Optional(StaticVector{"upside"s, "down"s})
                     .transform([](StaticVector<std::string, 3>&& v) {
                       v.push_back("cake"s);
                       return v;
                     })
                     .transform([](const StaticVector<std::string, 3>& v) {
                       return std::accumulate(v.begin(), v.end(), std::string());
                     })
                     .transform([](const std::string& s) { return s.length(); }));
}

namespace {

Optional<int> parse_int(const std::string& str) {
  if (const int i = std::atoi(str.c_str())) return i;
  return std::nullopt;
}

}  // namespace

TEST(Optional, AndThen) {
  // Empty.
  EXPECT_EQ(std::nullopt, Optional<int>().and_then([](int) -> Optional<int> { return 0; }));
  EXPECT_EQ(std::nullopt, Optional<int>().and_then([](int) { return Optional<int>(); }));

  // By value.
  EXPECT_EQ(0, Optional(0).and_then([](int x) { return Optional(x); }));
  EXPECT_EQ(123, Optional("123").and_then(parse_int));
  EXPECT_EQ(std::nullopt, Optional("abc").and_then(parse_int));

  // By reference.
  {
    Optional opt = 'x';
    EXPECT_EQ('z', opt.and_then([](char& c) {
      c = 'y';
      return Optional('z');
    }));

    EXPECT_EQ('y', opt);
  }

  // By rvalue reference.
  {
    std::string out;
    EXPECT_EQ("xyz"s, Optional("abc"s).and_then([&out](std::string&& str) {
      out = std::move(str);
      return Optional("xyz"s);
    }));

    EXPECT_EQ(out, "abc"s);
  }

  // Chaining.
  using StringVector = StaticVector<std::string, 3>;
  EXPECT_EQ(14u, Optional(StaticVector{"-"s, "1"s})
                     .and_then([](StringVector&& v) -> Optional<StringVector> {
                       if (v.push_back("4"s)) return v;
                       return {};
                     })
                     .and_then([](const StringVector& v) -> Optional<std::string> {
                       if (v.full()) return std::accumulate(v.begin(), v.end(), std::string());
                       return {};
                     })
                     .and_then(parse_int)
                     .and_then([](int i) {
                       return i > 0 ? std::nullopt : std::make_optional(static_cast<unsigned>(-i));
                     }));
}

TEST(Optional, OrElse) {
  // Non-empty.
  {
    const Optional opt = false;
    EXPECT_EQ(false, opt.or_else([] { return Optional(true); }));
    EXPECT_EQ('x', Optional('x').or_else([] { return std::make_optional('y'); }));
  }

  // Empty.
  {
    const Optional<int> opt;
    EXPECT_EQ(123, opt.or_else([]() -> Optional<int> { return 123; }));
    EXPECT_EQ("abc"s, Optional<std::string>().or_else([] { return Optional("abc"s); }));
  }
  {
    bool empty = false;
    EXPECT_EQ(Optional<float>(), Optional<float>().or_else([&empty]() -> Optional<float> {
      empty = true;
      return std::nullopt;
    }));
    EXPECT_TRUE(empty);
  }

  // Chaining.
  using StringVector = StaticVector<std::string, 3>;
  EXPECT_EQ(999, Optional(StaticVector{"1"s, "0"s, "0"s})
                     .and_then([](StringVector&& v) -> Optional<StringVector> {
                       if (v.push_back("0"s)) return v;
                       return {};
                     })
                     .or_else([] {
                       return Optional(StaticVector{"9"s, "9"s, "9"s});
                     })
                     .transform([](const StringVector& v) {
                       return std::accumulate(v.begin(), v.end(), std::string());
                     })
                     .and_then(parse_int)
                     .or_else([] { return Optional(-1); }));
}

TEST(Optional, OkOr) {
  using CharExp = ftl::Expected<char, std::errc>;
  using StringExp = ftl::Expected<std::string, std::errc>;

  EXPECT_EQ(CharExp('z'), Optional('z').ok_or(std::errc::broken_pipe));
  EXPECT_EQ(CharExp(ftl::Unexpected(std::errc::broken_pipe)),
            Optional<char>().ok_or(std::errc::broken_pipe));

  EXPECT_EQ(StringExp("abc"s), Optional("abc"s).ok_or(std::errc::protocol_error));
  EXPECT_EQ(StringExp(ftl::Unexpected(std::errc::protocol_error)),
            Optional<std::string>().ok_or(std::errc::protocol_error));
}

// Comparison.
namespace {

constexpr Optional<int> kOptional1 = 1;
constexpr Optional<int> kAnotherOptional1 = 1;
constexpr Optional<int> kOptional2 = 2;
constexpr Optional<int> kOptionalEmpty, kAnotherOptionalEmpty;

constexpr std::optional<int> kStdOptional1 = 1;

static_assert(kOptional1 == kAnotherOptional1);

static_assert(kOptional1 != kOptional2);
static_assert(kOptional2 != kOptional1);

static_assert(kOptional1 != kOptionalEmpty);
static_assert(kOptionalEmpty != kOptional1);

static_assert(kOptionalEmpty == kAnotherOptionalEmpty);

static_assert(kOptional1 == kStdOptional1);
static_assert(kStdOptional1 == kOptional1);

static_assert(kOptional2 != kStdOptional1);
static_assert(kStdOptional1 != kOptional2);

static_assert(kOptional2 != kOptionalEmpty);
static_assert(kOptionalEmpty != kOptional2);

} // namespace

}  // namespace android::test
