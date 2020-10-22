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

#include <ftl/ArrayTraits.h>
#include <ftl/StaticVector.h>

#include <algorithm>
#include <iterator>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace android::ftl {

template <typename>
struct IsSmallVector;

// ftl::StaticVector that promotes to std::vector when full. SmallVector is a drop-in replacement
// for std::vector with statically allocated storage for N elements, whose goal is to improve run
// time by avoiding heap allocation and increasing probability of cache hits. The standard API is
// augmented by an unstable_erase operation that does not preserve order, and a replace operation
// that destructively emplaces.
//
// SmallVector<T, 0> is a specialization that thinly wraps std::vector.
//
// Example usage:
//
//     ftl::SmallVector<char, 3> vector;
//     assert(vector.empty());
//     assert(!vector.dynamic());
//
//     vector = {'a', 'b', 'c'};
//     assert(vector.size() == 3u);
//     assert(!vector.dynamic());
//
//     vector.push_back('d');
//     assert(vector.dynamic());
//
//     vector.unstable_erase(vector.begin());
//     assert(vector == (ftl::SmallVector{'d', 'b', 'c'}));
//
//     vector.pop_back();
//     assert(vector.back() == 'b');
//     assert(vector.dynamic());
//
//     const char array[] = "hi";
//     vector = ftl::SmallVector(array);
//     assert(vector == (ftl::SmallVector{'h', 'i', '\0'}));
//     assert(!vector.dynamic());
//
template <typename T, size_t N>
class SmallVector final : ArrayTraits<T>, ArrayComparators<SmallVector> {
    using Static = StaticVector<T, N>;
    using Dynamic = SmallVector<T, 0>;

    // TODO: Replace with std::remove_cvref_t in C++20.
    template <typename U>
    using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<U>>;

public:
    FTL_ARRAY_TRAIT(T, value_type);
    FTL_ARRAY_TRAIT(T, size_type);
    FTL_ARRAY_TRAIT(T, difference_type);

    FTL_ARRAY_TRAIT(T, pointer);
    FTL_ARRAY_TRAIT(T, reference);
    FTL_ARRAY_TRAIT(T, iterator);
    FTL_ARRAY_TRAIT(T, reverse_iterator);

    FTL_ARRAY_TRAIT(T, const_pointer);
    FTL_ARRAY_TRAIT(T, const_reference);
    FTL_ARRAY_TRAIT(T, const_iterator);
    FTL_ARRAY_TRAIT(T, const_reverse_iterator);

    // Creates an empty vector.
    SmallVector() = default;

    // Constructs at most N elements. See StaticVector for underlying constructors.
    template <typename Arg, typename... Args,
              typename = std::enable_if_t<!IsSmallVector<remove_cvref_t<Arg>>{}>>
    SmallVector(Arg&& arg, Args&&... args)
          : mVector(std::in_place_type<Static>, std::forward<Arg>(arg),
                    std::forward<Args>(args)...) {}

    // Copies at most N elements from a smaller convertible vector.
    template <typename U, size_t M, typename = std::enable_if_t<M <= N>>
    SmallVector(const SmallVector<U, M>& other)
          : SmallVector(IteratorRange, other.begin(), other.end()) {}

    void swap(SmallVector& other) { mVector.swap(other.mVector); }

    // Returns whether the vector is backed by static or dynamic storage.
    bool dynamic() const { return std::holds_alternative<Dynamic>(mVector); }

#define VISITOR(T, F, ...)                                               \
    T F() __VA_ARGS__ {                                                  \
        return std::visit([](auto&& v) -> T { return v.F(); }, mVector); \
    }

    VISITOR(size_type, max_size, const)
    VISITOR(size_type, size, const)
    VISITOR(bool, empty, const)

    // noexcept to suppress warning about zero variadic macro arguments.
    VISITOR(iterator, begin, noexcept)
    VISITOR(const_iterator, begin, const)
    VISITOR(const_iterator, cbegin, const)

    VISITOR(iterator, end, noexcept)
    VISITOR(const_iterator, end, const)
    VISITOR(const_iterator, cend, const)

    VISITOR(reverse_iterator, rbegin, noexcept)
    VISITOR(const_reverse_iterator, rbegin, const)
    VISITOR(const_reverse_iterator, crbegin, const)

    VISITOR(reverse_iterator, rend, noexcept)
    VISITOR(const_reverse_iterator, rend, const)
    VISITOR(const_reverse_iterator, crend, const)

    VISITOR(iterator, last, noexcept)
    VISITOR(const_iterator, last, const)

    VISITOR(reference, front, noexcept)
    VISITOR(const_reference, front, const)

    VISITOR(reference, back, noexcept)
    VISITOR(const_reference, back, const)

#undef VISITOR

    reference operator[](size_type i) {
        return std::visit([i](auto& v) -> reference { return v[i]; }, mVector);
    }

    const_reference operator[](size_type i) const {
        return std::visit([i](const auto& v) -> const_reference { return v[i]; }, mVector);
    }

    // Replaces an element, and returns a reference to it. The iterator must be dereferenceable, so
    // replacing at end() is erroneous.
    //
    // The element is emplaced via move constructor, so type T does not need to define copy/move
    // assignment, e.g. its data members may be const.
    //
    // The arguments may directly or indirectly refer to the element being replaced.
    //
    // Iterators to the replaced element point to its replacement, and others remain valid.
    //
    template <typename... Args>
    reference replace(const_iterator it, Args&&... args) {
        return std::
                visit([it, &args...](auto& v)
                              -> reference { return v.replace(it, std::forward<Args>(args)...); },
                      mVector);
    }

    // Appends an element, and returns a reference to it.
    //
    // If the vector reaches its static or dynamic capacity, then all iterators are invalidated.
    // Otherwise, only the end() iterator is invalidated.
    //
    template <typename... Args>
    reference emplace_back(Args&&... args) {
        constexpr auto insertStatic = &Static::template emplace_back<Args...>;
        constexpr auto insertDynamic = &Dynamic::template emplace_back<Args...>;
        return *insert<insertStatic, insertDynamic>(std::forward<Args>(args)...);
    }

    // Appends an element.
    //
    // If the vector reaches its static or dynamic capacity, then all iterators are invalidated.
    // Otherwise, only the end() iterator is invalidated.
    //
    void push_back(const value_type& v) {
        constexpr auto insertStatic =
                static_cast<bool (Static::*)(const value_type&)>(&Static::push_back);
        constexpr auto insertDynamic =
                static_cast<bool (Dynamic::*)(const value_type&)>(&Dynamic::push_back);
        insert<insertStatic, insertDynamic>(v);
    }

    void push_back(value_type&& v) {
        constexpr auto insertStatic =
                static_cast<bool (Static::*)(value_type&&)>(&Static::push_back);
        constexpr auto insertDynamic =
                static_cast<bool (Dynamic::*)(value_type&&)>(&Dynamic::push_back);
        insert<insertStatic, insertDynamic>(std::move(v));
    }

    // Removes the last element. The vector must not be empty, or the call is erroneous.
    //
    // The last() and end() iterators are invalidated.
    //
    void pop_back() {
        std::visit([](auto& v) { v.pop_back(); }, mVector);
    }

    // Erases an element, but does not preserve order. Rather than shifting subsequent elements,
    // this moves the last element to the slot of the erased element.
    //
    // The last() and end() iterators, as well as those to the erased element, are invalidated.
    //
    void unstable_erase(iterator it) {
        std::visit([it](auto& v) { v.unstable_erase(it); }, mVector);
    }

private:
    template <typename... Vs>
    struct Visitor : Vs... {};

    // TODO: Remove this deduction guide in C++20.
    template <typename... Vs>
    Visitor(Vs...) -> Visitor<Vs...>;

    template <auto insertStatic, auto insertDynamic, typename... Args>
    auto insert(Args&&... args) {
        return std::visit(Visitor{[this, &args...](Static& vector) {
                                      if (vector.full()) {
                                          return (promote(vector).*
                                                  insertDynamic)(std::forward<Args>(args)...);
                                      }

                                      return (vector.*insertStatic)(std::forward<Args>(args)...);
                                  },
                                  [&args...](Dynamic& vector) {
                                      return (vector.*insertDynamic)(std::forward<Args>(args)...);
                                  }},
                          mVector);
    }

    Dynamic& promote(Static& staticVector) {
        assert(staticVector.full());

        // Allocate double capacity to reduce probability of reallocation.
        Dynamic vector;
        vector.reserve(Static::max_size() * 2);
        std::move(staticVector.begin(), staticVector.end(), std::back_inserter(vector));

        return mVector.template emplace<Dynamic>(std::move(vector));
    }

    std::variant<Static, Dynamic> mVector;
};

// Partial specialization without static storage.
template <typename T>
class SmallVector<T, 0> final : ArrayTraits<T>,
                                ArrayIterators<SmallVector<T, 0>, T>,
                                std::vector<T> {
    using ArrayTraits<T>::construct_at;

    using Iter = ArrayIterators<SmallVector, T>;
    using Impl = std::vector<T>;

    friend Iter;

public:
    FTL_ARRAY_TRAIT(T, value_type);
    FTL_ARRAY_TRAIT(T, size_type);
    FTL_ARRAY_TRAIT(T, difference_type);

    FTL_ARRAY_TRAIT(T, pointer);
    FTL_ARRAY_TRAIT(T, reference);
    FTL_ARRAY_TRAIT(T, iterator);
    FTL_ARRAY_TRAIT(T, reverse_iterator);

    FTL_ARRAY_TRAIT(T, const_pointer);
    FTL_ARRAY_TRAIT(T, const_reference);
    FTL_ARRAY_TRAIT(T, const_iterator);
    FTL_ARRAY_TRAIT(T, const_reverse_iterator);

    using Impl::Impl;

    using Impl::empty;
    using Impl::max_size;
    using Impl::size;

    using Impl::reserve;

    // std::vector iterators are not necessarily raw pointers.
    iterator begin() { return Impl::data(); }
    iterator end() { return Impl::data() + size(); }

    using Iter::begin;
    using Iter::end;

    using Iter::cbegin;
    using Iter::cend;

    using Iter::rbegin;
    using Iter::rend;

    using Iter::crbegin;
    using Iter::crend;

    using Iter::last;

    using Iter::back;
    using Iter::front;

    using Iter::operator[];

    template <typename... Args>
    reference replace(const_iterator it, Args&&... args) {
        value_type element{std::forward<Args>(args)...};
        std::destroy_at(it);
        // This is only safe because exceptions are disabled.
        return *construct_at(it, std::move(element));
    }

    template <typename... Args>
    iterator emplace_back(Args&&... args) {
        return &Impl::emplace_back(std::forward<Args>(args)...);
    }

    bool push_back(const value_type& v) {
        Impl::push_back(v);
        return true;
    }

    bool push_back(value_type&& v) {
        Impl::push_back(std::move(v));
        return true;
    }

    using Impl::pop_back;

    void unstable_erase(iterator it) {
        if (it != last()) std::iter_swap(it, last());
        pop_back();
    }

    void swap(SmallVector& other) { Impl::swap(other); }
};

template <typename>
struct IsSmallVector : std::false_type {};

template <typename T, size_t N>
struct IsSmallVector<SmallVector<T, N>> : std::true_type {};

// Deduction guide for array constructor.
template <typename T, size_t N>
SmallVector(T (&)[N]) -> SmallVector<std::remove_cv_t<T>, N>;

// Deduction guide for variadic constructor.
template <typename T, typename... Us, typename V = std::decay_t<T>,
          typename = std::enable_if_t<(std::is_constructible_v<V, Us> && ...)>>
SmallVector(T&&, Us&&...) -> SmallVector<V, 1 + sizeof...(Us)>;

// Deduction guide for in-place constructor.
template <typename T, typename... Us>
SmallVector(std::in_place_type_t<T>, Us&&...) -> SmallVector<T, sizeof...(Us)>;

// Deduction guide for StaticVector conversion.
template <typename T, size_t N>
SmallVector(StaticVector<T, N>&&) -> SmallVector<T, N>;

template <typename T, size_t N>
inline void swap(SmallVector<T, N>& lhs, SmallVector<T, N>& rhs) {
    lhs.swap(rhs);
}

} // namespace android::ftl
