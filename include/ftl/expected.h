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

#pragma once

#include <android-base/expected.h>
#include <ftl/optional.h>

#include <utility>

namespace android::ftl {

// Superset of base::expected<T, E> with monadic operations.
//
// TODO: Extend std::expected<T, E> in C++23.
//
template <typename T, typename E>
struct Expected final : base::expected<T, E> {
  using Base = base::expected<T, E>;
  using Base::expected;

  using Base::error;
  using Base::has_value;
  using Base::value;

  template <typename P>
  constexpr bool has_error(P predicate) const {
    return !has_value() && predicate(error());
  }

  constexpr Optional<T> value_opt() const& {
    return has_value() ? Optional(value()) : std::nullopt;
  }

  constexpr Optional<T> value_opt() && {
    return has_value() ? Optional(std::move(value())) : std::nullopt;
  }

  // Delete new for this class. Its base doesn't have a virtual destructor, and
  // if it got deleted via base class pointer, it would cause undefined
  // behavior. There's not a good reason to allocate this object on the heap
  // anyway.
  static void* operator new(size_t) = delete;
  static void* operator new[](size_t) = delete;
};

template <typename E>
constexpr auto Unexpected(E&& error) {
  return base::unexpected(std::forward<E>(error));
}

}  // namespace android::ftl
