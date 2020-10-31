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

#pragma once

#include <tuple>
#include <utility>

namespace android::ftl {

// Compile-time counterpart of std::initializer_list<T> that stores per-element constructor
// arguments with heterogeneous types. For a container with elements of type T, given Sizes
// (S0, S1, ..., SN), N elements are initialized: the first element is initialized with the
// first S0 arguments, the second element is initialized with the next S1 arguments, and so
// on. The list of Types (T0, ..., TM) is flattened, so M is equal to the sum of the Sizes.
//
// The InitializerList is created using ftl::init::list, and is consumed by constructors of
// containers. The function call operator is overloaded such that arguments are accumulated
// in a tuple with each successive call. For instance, the following calls initialize three
// strings using different constructors, i.e. string literal, default, and count/character:
//
//     ... = ftl::init::list<std::string>("abc")()(3u, '?');
//
// WARNING: The InitializerList returned by an ftl::init::list expression must be consumed
// immediately, since temporary arguments are destroyed after the full expression. Storing
// an InitializerList results in dangling references.
//
template <typename T, typename Sizes = std::index_sequence<>, typename... Types>
struct InitializerList;

template <typename T, size_t... Sizes, typename... Types>
struct InitializerList<T, std::index_sequence<Sizes...>, Types...> {
    // Creates a superset InitializerList by appending the number of arguments to Sizes, and
    // expanding Types with forwarding references for each argument.
    template <typename... Args>
    [[nodiscard]] constexpr auto operator()(Args&&... args) && -> InitializerList<
            T, std::index_sequence<Sizes..., sizeof...(Args)>, Types..., Args&&...> {
        return {std::tuple_cat(std::move(tuple),
                               std::forward_as_tuple(std::forward<Args>(args)...))};
    }

    // The temporary InitializerList returned by operator() is bound to an rvalue reference in
    // container constructors, which extends the lifetime of any temporary arguments that this
    // tuple refers to until the completion of the full expression containing the construction.
    std::tuple<Types...> tuple;
};

namespace init {

template <typename T, typename... Args>
[[nodiscard]] constexpr auto list(Args&&... args) {
    return InitializerList<T>{}(std::forward<Args>(args)...);
}

} // namespace init
} // namespace android::ftl
