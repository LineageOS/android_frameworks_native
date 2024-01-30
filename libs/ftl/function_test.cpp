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

#include <ftl/function.h>
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace android::test {
namespace {

// Create an alias to composite requirements defined by the trait class `T` for easier testing.
template <typename T, typename S>
inline constexpr bool is_opaquely_storable = (T::template require_trivially_copyable<S> &&
                                              T::template require_trivially_destructible<S> &&
                                              T::template require_will_fit_in_opaque_storage<S> &&
                                              T::template require_alignment_compatible<S>);

// `I` gives a count of sizeof(std::intptr_t) bytes , and `J` gives a raw count of bytes
template <size_t I, size_t J = 0>
struct KnownSizeFunctionObject {
  using Data = std::array<std::byte, sizeof(std::intptr_t) * I + J>;
  void operator()() const {};
  Data data{};
};

}  // namespace

// static_assert the expected type traits
static_assert(std::is_invocable_r_v<void, ftl::Function<void()>>);
static_assert(std::is_trivially_copyable_v<ftl::Function<void()>>);
static_assert(std::is_trivially_destructible_v<ftl::Function<void()>>);
static_assert(std::is_trivially_copy_constructible_v<ftl::Function<void()>>);
static_assert(std::is_trivially_move_constructible_v<ftl::Function<void()>>);
static_assert(std::is_trivially_copy_assignable_v<ftl::Function<void()>>);
static_assert(std::is_trivially_move_assignable_v<ftl::Function<void()>>);

template <typename T>
using function_traits = ftl::details::function_traits<T>;

// static_assert that the expected value of N is used for known function object sizes.
static_assert(function_traits<KnownSizeFunctionObject<0, 0>>::size == 0);
static_assert(function_traits<KnownSizeFunctionObject<0, 1>>::size == 0);
static_assert(function_traits<KnownSizeFunctionObject<1, 0>>::size == 0);
static_assert(function_traits<KnownSizeFunctionObject<1, 1>>::size == 1);
static_assert(function_traits<KnownSizeFunctionObject<2, 0>>::size == 1);
static_assert(function_traits<KnownSizeFunctionObject<2, 1>>::size == 2);

// Check that is_function_v works
static_assert(!ftl::is_function_v<KnownSizeFunctionObject<0>>);
static_assert(!ftl::is_function_v<std::function<void()>>);
static_assert(ftl::is_function_v<ftl::Function<void()>>);

// static_assert what can and cannot be stored inside the opaque storage

template <size_t N>
using function_opaque_storage = ftl::details::function_opaque_storage<N>;

// Function objects can be stored if they fit.
static_assert(is_opaquely_storable<function_opaque_storage<0>, KnownSizeFunctionObject<0>>);
static_assert(is_opaquely_storable<function_opaque_storage<0>, KnownSizeFunctionObject<1>>);
static_assert(!is_opaquely_storable<function_opaque_storage<0>, KnownSizeFunctionObject<2>>);

static_assert(is_opaquely_storable<function_opaque_storage<1>, KnownSizeFunctionObject<2>>);
static_assert(!is_opaquely_storable<function_opaque_storage<1>, KnownSizeFunctionObject<3>>);

static_assert(is_opaquely_storable<function_opaque_storage<2>, KnownSizeFunctionObject<3>>);
static_assert(!is_opaquely_storable<function_opaque_storage<2>, KnownSizeFunctionObject<4>>);

// Another opaque storage can be stored if it fits. This property is used to copy smaller
// ftl::Functions into larger ones.
static_assert(is_opaquely_storable<function_opaque_storage<2>, function_opaque_storage<0>::type>);
static_assert(is_opaquely_storable<function_opaque_storage<2>, function_opaque_storage<1>::type>);
static_assert(is_opaquely_storable<function_opaque_storage<2>, function_opaque_storage<2>::type>);
static_assert(!is_opaquely_storable<function_opaque_storage<2>, function_opaque_storage<3>::type>);

// Function objects that aren't trivially copyable or destroyable cannot be stored.
auto lambda_capturing_unique_ptr = [ptr = std::unique_ptr<void*>()] { static_cast<void>(ptr); };
static_assert(
    !is_opaquely_storable<function_opaque_storage<2>, decltype(lambda_capturing_unique_ptr)>);

// Keep in sync with "Example usage" in header file.
TEST(Function, Example) {
  using namespace std::string_view_literals;

  class MyClass {
   public:
    void on_event() const {}
    int on_string(int*, std::string_view) { return 1; }

    auto get_function() {
      return ftl::make_function([this] { on_event(); });
    }
  } cls;

  // A function container with no arguments, and returning no value.
  ftl::Function<void()> f;

  // Construct a ftl::Function containing a small lambda.
  f = cls.get_function();

  // Construct a ftl::Function that calls `cls.on_event()`.
  f = ftl::make_function<&MyClass::on_event>(&cls);

  // Create a do-nothing function.
  f = ftl::no_op;

  // Invoke the contained function.
  f();

  // Also invokes it.
  std::invoke(f);

  // Create a typedef to give a more meaningful name and bound the size.
  using MyFunction = ftl::Function<int(std::string_view), 2>;
  int* ptr = nullptr;
  auto f1 =
      MyFunction::make([cls = &cls, ptr](std::string_view sv) { return cls->on_string(ptr, sv); });
  int r = f1("abc"sv);

  // Returns a default-constructed int (0).
  f1 = ftl::no_op;
  r = f1("abc"sv);
  EXPECT_EQ(r, 0);
}

TEST(Function, BasicOperations) {
  // Default constructible.
  ftl::Function<int()> f;

  // Compares as empty
  EXPECT_FALSE(f);
  EXPECT_TRUE(f == nullptr);
  EXPECT_FALSE(f != nullptr);
  EXPECT_TRUE(ftl::Function<int()>() == f);
  EXPECT_FALSE(ftl::Function<int()>() != f);

  // Assigning no_op sets it to not empty.
  f = ftl::no_op;

  // Verify it can be called, and that it returns a default constructed value.
  EXPECT_EQ(f(), 0);

  // Comparable when non-empty.
  EXPECT_TRUE(f);
  EXPECT_FALSE(f == nullptr);
  EXPECT_TRUE(f != nullptr);
  EXPECT_FALSE(ftl::Function<int()>() == f);
  EXPECT_TRUE(ftl::Function<int()>() != f);

  // Constructing from nullptr means empty.
  f = ftl::Function<int()>{nullptr};
  EXPECT_FALSE(f);

  // Assigning nullptr means it is empty.
  f = nullptr;
  EXPECT_FALSE(f);

  // Move construction
  f = ftl::no_op;
  ftl::Function<int()> g{std::move(f)};
  EXPECT_TRUE(g != nullptr);

  // Move assignment
  f = nullptr;
  f = std::move(g);
  EXPECT_TRUE(f != nullptr);

  // Copy construction
  ftl::Function<int()> h{f};
  EXPECT_TRUE(h != nullptr);

  // Copy assignment
  g = h;
  EXPECT_TRUE(g != nullptr);
}

TEST(Function, CanMoveConstructFromLambda) {
  auto lambda = [] {};
  ftl::Function<void()> f{std::move(lambda)};
}

TEST(Function, TerseDeducedConstructAndAssignFromLambda) {
  auto f = ftl::Function([] { return 1; });
  EXPECT_EQ(f(), 1);

  f = [] { return 2; };
  EXPECT_EQ(f(), 2);
}

namespace {

struct ImplicitConversionsHelper {
  auto exact(int) -> int { return 0; }
  auto inexact(long) -> short { return 0; }
  // TODO: Switch to `auto templated(auto x)` with C++20
  template <typename T>
  T templated(T x) {
    return x;
  }

  static auto static_exact(int) -> int { return 0; }
  static auto static_inexact(long) -> short { return 0; }
  // TODO: Switch to `static auto static_templated(auto x)` with C++20
  template <typename T>
  static T static_templated(T x) {
    return x;
  }
};

}  // namespace

TEST(Function, ImplicitConversions) {
  using Function = ftl::Function<int(int)>;
  auto check = [](Function f) { return f(0); };
  auto exact = [](int) -> int { return 0; };
  auto inexact = [](long) -> short { return 0; };
  auto templated = [](auto x) { return x; };

  ImplicitConversionsHelper helper;

  // Note, `check(nullptr)` would crash, so we can only check if it would be invocable.
  static_assert(std::is_invocable_v<decltype(check), decltype(nullptr)>);

  // Note: We invoke each of these to fully expand all the templates involved.
  EXPECT_EQ(check(ftl::no_op), 0);

  EXPECT_EQ(check(exact), 0);
  EXPECT_EQ(check(inexact), 0);
  EXPECT_EQ(check(templated), 0);

  EXPECT_EQ(check(Function::make<&ImplicitConversionsHelper::exact>(&helper)), 0);
  EXPECT_EQ(check(Function::make<&ImplicitConversionsHelper::inexact>(&helper)), 0);
  EXPECT_EQ(check(Function::make<&ImplicitConversionsHelper::templated<int>>(&helper)), 0);

  EXPECT_EQ(check(Function::make<&ImplicitConversionsHelper::static_exact>()), 0);
  EXPECT_EQ(check(Function::make<&ImplicitConversionsHelper::static_inexact>()), 0);
  EXPECT_EQ(check(Function::make<&ImplicitConversionsHelper::static_templated<int>>()), 0);
}

TEST(Function, MakeWithNonConstMemberFunction) {
  struct Observer {
    bool called = false;
    void setCalled() { called = true; }
  } observer;

  auto f = ftl::make_function<&Observer::setCalled>(&observer);

  f();

  EXPECT_TRUE(observer.called);

  EXPECT_TRUE(f == ftl::Function<void()>::make<&Observer::setCalled>(&observer));
}

TEST(Function, MakeWithConstMemberFunction) {
  struct Observer {
    mutable bool called = false;
    void setCalled() const { called = true; }
  } observer;

  const auto f = ftl::make_function<&Observer::setCalled>(&observer);

  f();

  EXPECT_TRUE(observer.called);

  EXPECT_TRUE(f == ftl::Function<void()>::make<&Observer::setCalled>(&observer));
}

TEST(Function, MakeWithConstClassPointer) {
  const struct Observer {
    mutable bool called = false;
    void setCalled() const { called = true; }
  } observer;

  const auto f = ftl::make_function<&Observer::setCalled>(&observer);

  f();

  EXPECT_TRUE(observer.called);

  EXPECT_TRUE(f == ftl::Function<void()>::make<&Observer::setCalled>(&observer));
}

TEST(Function, MakeWithNonCapturingLambda) {
  auto f = ftl::make_function([](int a, int b) { return a + b; });
  EXPECT_EQ(f(1, 2), 3);
}

TEST(Function, MakeWithCapturingLambda) {
  bool called = false;
  auto f = ftl::make_function([&called](int a, int b) {
    called = true;
    return a + b;
  });
  EXPECT_EQ(f(1, 2), 3);
  EXPECT_TRUE(called);
}

TEST(Function, MakeWithCapturingMutableLambda) {
  bool called = false;
  auto f = ftl::make_function([&called](int a, int b) mutable {
    called = true;
    return a + b;
  });
  EXPECT_EQ(f(1, 2), 3);
  EXPECT_TRUE(called);
}

TEST(Function, MakeWithThreePointerCapturingLambda) {
  bool my_bool = false;
  int my_int = 0;
  float my_float = 0.f;

  auto f = ftl::make_function(
      [ptr_bool = &my_bool, ptr_int = &my_int, ptr_float = &my_float](int a, int b) mutable {
        *ptr_bool = true;
        *ptr_int = 1;
        *ptr_float = 1.f;

        return a + b;
      });

  EXPECT_EQ(f(1, 2), 3);

  EXPECT_TRUE(my_bool);
  EXPECT_EQ(my_int, 1);
  EXPECT_EQ(my_float, 1.f);
}

TEST(Function, MakeWithFreeFunction) {
  auto f = ftl::make_function<&std::make_unique<int, int>>();
  std::unique_ptr<int> unique_int = f(1);
  ASSERT_TRUE(unique_int);
  EXPECT_EQ(*unique_int, 1);
}

TEST(Function, CopyToLarger) {
  int counter = 0;
  ftl::Function<void()> a{[ptr_counter = &counter] { (*ptr_counter)++; }};
  ftl::Function<void(), 1> b = a;
  ftl::Function<void(), 2> c = a;

  EXPECT_EQ(counter, 0);
  a();
  EXPECT_EQ(counter, 1);
  b();
  EXPECT_EQ(counter, 2);
  c();
  EXPECT_EQ(counter, 3);

  b = [ptr_counter = &counter] { (*ptr_counter) += 2; };
  c = [ptr_counter = &counter] { (*ptr_counter) += 3; };

  b();
  EXPECT_EQ(counter, 5);
  c();
  EXPECT_EQ(counter, 8);
}

}  // namespace android::test
