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

#include <ftl/mixins.h>
#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <type_traits>
#include <utility>

namespace android::test {
namespace {

// Keep in sync with example usage in header file.

struct Id : ftl::Constructible<Id, std::int32_t>, ftl::Equatable<Id> {
  using Constructible::Constructible;
};

static_assert(!std::is_default_constructible_v<Id>);

struct Color : ftl::DefaultConstructible<Color, std::uint8_t>,
               ftl::Equatable<Color>,
               ftl::Orderable<Color> {
  using DefaultConstructible::DefaultConstructible;
};

static_assert(Color() == Color(0u));
static_assert(ftl::to_underlying(Color(-1)) == 255u);
static_assert(Color(1u) < Color(2u));

struct Sequence : ftl::DefaultConstructible<Sequence, std::int8_t, -1>,
                  ftl::Equatable<Sequence>,
                  ftl::Orderable<Sequence>,
                  ftl::Incrementable<Sequence> {
  using DefaultConstructible::DefaultConstructible;
};

static_assert(Sequence() == Sequence(-1));

struct Timeout : ftl::DefaultConstructible<Timeout, std::chrono::seconds, 10>,
                 ftl::Equatable<Timeout>,
                 ftl::Addable<Timeout> {
  using DefaultConstructible::DefaultConstructible;
};

using namespace std::chrono_literals;
static_assert(Timeout() + Timeout(5s) == Timeout(15s));

// Construction.
constexpr Id kId{1234};
constexpr Sequence kSequence;

// Underlying value.
static_assert(ftl::to_underlying(Id(-42)) == -42);
static_assert(ftl::to_underlying(kSequence) == -1);

// Casting.
static_assert(static_cast<std::int32_t>(Id(-1)) == -1);
static_assert(static_cast<std::int8_t>(kSequence) == -1);

static_assert(!std::is_convertible_v<std::int32_t, Id>);
static_assert(!std::is_convertible_v<Id, std::int32_t>);

// Equality.
static_assert(kId == Id(1234));
static_assert(kId != Id(123));
static_assert(kSequence == Sequence(-1));

// Ordering.
static_assert(Sequence(1) < Sequence(2));
static_assert(Sequence(2) > Sequence(1));
static_assert(Sequence(3) <= Sequence(4));
static_assert(Sequence(4) >= Sequence(3));
static_assert(Sequence(5) <= Sequence(5));
static_assert(Sequence(6) >= Sequence(6));

// Incrementing.
template <typename Op, typename T, typename... Ts>
constexpr auto mutable_op(Op op, T lhs, Ts... rhs) {
  const T result = op(lhs, rhs...);
  return std::make_pair(lhs, result);
}

static_assert(mutable_op([](auto& lhs) { return ++lhs; }, Sequence()) ==
              std::make_pair(Sequence(0), Sequence(0)));

static_assert(mutable_op([](auto& lhs) { return lhs++; }, Sequence()) ==
              std::make_pair(Sequence(0), Sequence(-1)));

// Addition.

// `Addable` implies `Incrementable`.
static_assert(mutable_op([](auto& lhs) { return ++lhs; }, Timeout()) ==
              std::make_pair(Timeout(11s), Timeout(11s)));

static_assert(mutable_op([](auto& lhs) { return lhs++; }, Timeout()) ==
              std::make_pair(Timeout(11s), Timeout(10s)));

static_assert(Timeout(5s) + Timeout(6s) == Timeout(11s));

static_assert(mutable_op([](auto& lhs, const auto& rhs) { return lhs += rhs; }, Timeout(7s),
                         Timeout(8s)) == std::make_pair(Timeout(15s), Timeout(15s)));

// Type safety.

namespace traits {

template <typename, typename = void>
struct is_incrementable : std::false_type {};

template <typename T>
struct is_incrementable<T, std::void_t<decltype(++std::declval<T&>())>> : std::true_type {};

template <typename T>
constexpr bool is_incrementable_v = is_incrementable<T>{};

template <typename, typename, typename, typename = void>
struct has_binary_op : std::false_type {};

template <typename Op, typename T, typename U>
struct has_binary_op<Op, T, U, std::void_t<decltype(Op{}(std::declval<T&>(), std::declval<U&>()))>>
    : std::true_type {};

template <typename T, typename U>
constexpr bool is_equatable_v =
    has_binary_op<std::equal_to<void>, T, U>{} && has_binary_op<std::not_equal_to<void>, T, U>{};

template <typename T, typename U>
constexpr bool is_orderable_v =
    has_binary_op<std::less<void>, T, U>{} && has_binary_op<std::less_equal<void>, T, U>{} &&
    has_binary_op<std::greater<void>, T, U>{} && has_binary_op<std::greater_equal<void>, T, U>{};

template <typename T, typename U>
constexpr bool is_addable_v = has_binary_op<std::plus<void>, T, U>{};

}  // namespace traits

struct Real : ftl::Constructible<Real, float> {
  using Constructible::Constructible;
};

static_assert(traits::is_equatable_v<Id, Id>);
static_assert(!traits::is_equatable_v<Real, Real>);
static_assert(!traits::is_equatable_v<Id, Color>);
static_assert(!traits::is_equatable_v<Sequence, Id>);
static_assert(!traits::is_equatable_v<Id, std::int32_t>);
static_assert(!traits::is_equatable_v<std::chrono::seconds, Timeout>);

static_assert(traits::is_orderable_v<Color, Color>);
static_assert(!traits::is_orderable_v<Id, Id>);
static_assert(!traits::is_orderable_v<Real, Real>);
static_assert(!traits::is_orderable_v<Color, Sequence>);
static_assert(!traits::is_orderable_v<Color, std::uint8_t>);
static_assert(!traits::is_orderable_v<std::chrono::seconds, Timeout>);

static_assert(traits::is_incrementable_v<Sequence>);
static_assert(traits::is_incrementable_v<Timeout>);
static_assert(!traits::is_incrementable_v<Id>);
static_assert(!traits::is_incrementable_v<Color>);
static_assert(!traits::is_incrementable_v<Real>);

static_assert(traits::is_addable_v<Timeout, Timeout>);
static_assert(!traits::is_addable_v<Id, Id>);
static_assert(!traits::is_addable_v<Real, Real>);
static_assert(!traits::is_addable_v<Sequence, Sequence>);
static_assert(!traits::is_addable_v<Timeout, Sequence>);
static_assert(!traits::is_addable_v<Color, Timeout>);

}  // namespace
}  // namespace android::test
