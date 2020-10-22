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

#include <algorithm>
#include <cassert>
#include <iterator>
#include <memory>
#include <type_traits>
#include <utility>

namespace android::ftl {

constexpr struct IteratorRangeTag {} IteratorRange;

// Fixed-capacity, statically allocated counterpart of std::vector. Akin to std::array, StaticVector
// allocates contiguous storage for N elements of type T at compile time, but stores at most (rather
// than exactly) N elements. Unlike std::array, its default constructor does not require T to have a
// default constructor, since elements are constructed in-place as the vector grows. Operations that
// insert an element (emplace_back, push_back, etc.) fail when the vector is full. The API otherwise
// adheres to standard containers, except the unstable_erase operation that does not preserve order,
// and the replace operation that destructively emplaces.
//
// StaticVector<T, 1> is analogous to an iterable std::optional, but StaticVector<T, 0> is an error.
//
// Example usage:
//
//     ftl::StaticVector<char, 3> vector;
//     assert(vector.empty());
//
//     vector = {'a', 'b'};
//     assert(vector.size() == 2u);
//
//     vector.push_back('c');
//     assert(vector.full());
//
//     assert(!vector.push_back('d'));
//     assert(vector.size() == 3u);
//
//     vector.unstable_erase(vector.begin());
//     assert(vector == (ftl::StaticVector{'c', 'b'}));
//
//     vector.pop_back();
//     assert(vector.back() == 'c');
//
//     const char array[] = "hi";
//     vector = ftl::StaticVector(array);
//     assert(vector == (ftl::StaticVector{'h', 'i', '\0'}));
//
template <typename T, size_t N>
class StaticVector final : ArrayTraits<T>,
                           ArrayIterators<StaticVector<T, N>, T>,
                           ArrayComparators<StaticVector> {
    static_assert(N > 0);

    using ArrayTraits<T>::construct_at;

    using Iter = ArrayIterators<StaticVector, T>;
    friend Iter;

    // There is ambiguity when constructing from two iterator-like elements like pointers:
    // they could be an iterator range, or arguments for in-place construction. Assume the
    // latter unless they are input iterators and cannot be used to construct elements. If
    // the former is intended, the caller can pass an IteratorRangeTag to disambiguate.
    template <typename I, typename Traits = std::iterator_traits<I>>
    using IsInputIterator = std::conjunction<
            std::is_base_of<std::input_iterator_tag, typename Traits::iterator_category>,
            std::negation<std::is_constructible<T, I>>>;

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
    StaticVector() = default;

    // Copies and moves a vector, respectively.
    StaticVector(const StaticVector& other)
          : StaticVector(IteratorRange, other.begin(), other.end()) {}
    StaticVector(StaticVector&& other) { swap<Empty>(other); }

    // Copies at most N elements from a smaller convertible vector.
    template <typename U, size_t M, typename = std::enable_if_t<M <= N>>
    StaticVector(const StaticVector<U, M>& other)
          : StaticVector(IteratorRange, other.begin(), other.end()) {}

    // Copies at most N elements from an array.
    template <typename U, size_t M>
    explicit StaticVector(U (&array)[M])
          : StaticVector(IteratorRange, std::begin(array), std::end(array)) {}

    // Copies at most N elements from the range [first, last).
    //
    // IteratorRangeTag disambiguates with initialization from two iterator-like elements.
    //
    template <typename Iterator, typename = std::enable_if_t<IsInputIterator<Iterator>{}>>
    StaticVector(Iterator first, Iterator last) : StaticVector(IteratorRange, first, last) {
        using V = typename std::iterator_traits<Iterator>::value_type;
        static_assert(std::is_constructible_v<value_type, V>, "Incompatible iterator range");
    }

    template <typename Iterator>
    StaticVector(IteratorRangeTag, Iterator first, Iterator last)
          : mSize(std::min(max_size(), static_cast<size_type>(std::distance(first, last)))) {
        std::uninitialized_copy(first, first + mSize, begin());
    }

    // Constructs at most N elements. The template arguments T and N are inferred using the
    // deduction guide defined below. Note that T is determined from the first element, and
    // subsequent elements must have convertible types:
    //
    //     ftl::StaticVector vector = {1, 2, 3};
    //     static_assert(std::is_same_v<decltype(vector), ftl::StaticVector<int, 3>>);
    //
    //     const auto copy = "quince"s;
    //     auto move = "tart"s;
    //     ftl::StaticVector vector = {copy, std::move(move)};
    //
    //     static_assert(std::is_same_v<decltype(vector), ftl::StaticVector<std::string, 2>>);
    //
    template <typename E, typename... Es,
              typename = std::enable_if_t<std::is_constructible_v<value_type, E>>>
    StaticVector(E&& element, Es&&... elements)
          : StaticVector(std::index_sequence<0>{}, std::forward<E>(element),
                         std::forward<Es>(elements)...) {
        static_assert(sizeof...(elements) < N, "Too many elements");
    }

    // Constructs at most N elements. The template arguments T and N are inferred using the
    // deduction guide defined below. Element types must be convertible to the specified T:
    //
    //     ftl::StaticVector vector(std::in_place_type<std::string>, "red", "velvet", "cake");
    //     static_assert(std::is_same_v<decltype(vector), ftl::StaticVector<std::string, 3>>);
    //
    template <typename... Es>
    explicit StaticVector(std::in_place_type_t<T>, Es... elements)
          : StaticVector(std::forward<Es>(elements)...) {}

    ~StaticVector() { std::destroy(begin(), end()); }

    StaticVector& operator=(const StaticVector& other) {
        StaticVector copy(other);
        swap(copy);
        return *this;
    }

    StaticVector& operator=(StaticVector&& other) {
        std::destroy(begin(), end());
        mSize = 0;
        swap<Empty>(other);
        return *this;
    }

    template <typename = void>
    void swap(StaticVector&);

    static constexpr size_type max_size() { return N; }
    size_type size() const { return mSize; }

    bool empty() const { return size() == 0; }
    bool full() const { return size() == max_size(); }

    iterator begin() { return std::launder(reinterpret_cast<pointer>(mData)); }
    iterator end() { return begin() + size(); }

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
        value_type element{std::forward<Args>(args)...};
        std::destroy_at(it);
        // This is only safe because exceptions are disabled.
        return *construct_at(it, std::move(element));
    }

    // Appends an element, and returns an iterator to it. If the vector is full, the element is not
    // inserted, and the end() iterator is returned.
    //
    // On success, the end() iterator is invalidated.
    //
    template <typename... Args>
    iterator emplace_back(Args&&... args) {
        if (full()) return end();
        const iterator it = construct_at(end(), std::forward<Args>(args)...);
        ++mSize;
        return it;
    }

    // Appends an element unless the vector is full, and returns whether the element was inserted.
    //
    // On success, the end() iterator is invalidated.
    //
    bool push_back(const value_type& v) {
        // Two statements for sequence point.
        const iterator it = emplace_back(v);
        return it != end();
    }

    bool push_back(value_type&& v) {
        // Two statements for sequence point.
        const iterator it = emplace_back(std::move(v));
        return it != end();
    }

    // Removes the last element. The vector must not be empty, or the call is erroneous.
    //
    // The last() and end() iterators are invalidated.
    //
    void pop_back() { unstable_erase(last()); }

    // Erases an element, but does not preserve order. Rather than shifting subsequent elements,
    // this moves the last element to the slot of the erased element.
    //
    // The last() and end() iterators, as well as those to the erased element, are invalidated.
    //
    void unstable_erase(const_iterator it) {
        std::destroy_at(it);
        if (it != last()) {
            // Move last element and destroy its source for destructor side effects. This is only
            // safe because exceptions are disabled.
            construct_at(it, std::move(back()));
            std::destroy_at(last());
        }
        --mSize;
    }

private:
    struct Empty {};

    // Recursion for variadic constructor.
    template <size_t I, typename E, typename... Es>
    StaticVector(std::index_sequence<I>, E&& element, Es&&... elements)
          : StaticVector(std::index_sequence<I + 1>{}, std::forward<Es>(elements)...) {
        construct_at(begin() + I, std::forward<E>(element));
    }

    // Base case for variadic constructor.
    template <size_t I>
    explicit StaticVector(std::index_sequence<I>) : mSize(I) {}

    size_type mSize = 0;
    std::aligned_storage_t<sizeof(value_type), alignof(value_type)> mData[N];
};

// Deduction guide for array constructor.
template <typename T, size_t N>
StaticVector(T (&)[N]) -> StaticVector<std::remove_cv_t<T>, N>;

// Deduction guide for variadic constructor.
template <typename T, typename... Us, typename V = std::decay_t<T>,
          typename = std::enable_if_t<(std::is_constructible_v<V, Us> && ...)>>
StaticVector(T&&, Us&&...) -> StaticVector<V, 1 + sizeof...(Us)>;

// Deduction guide for in-place constructor.
template <typename T, typename... Us>
StaticVector(std::in_place_type_t<T>, Us&&...) -> StaticVector<T, sizeof...(Us)>;

template <typename T, size_t N>
template <typename E>
void StaticVector<T, N>::swap(StaticVector& other) {
    auto [to, from] = std::make_pair(this, &other);
    if (from == this) return;

    // Assume this vector has fewer elements, so the excess of the other vector will be moved to it.
    auto [min, max] = std::make_pair(size(), other.size());

    // No elements to swap if moving into an empty vector.
    if constexpr (std::is_same_v<E, Empty>) {
        assert(min == 0);
    } else {
        if (min > max) {
            std::swap(from, to);
            std::swap(min, max);
        }

        // Swap elements [0, min).
        std::swap_ranges(begin(), begin() + min, other.begin());

        // No elements to move if sizes are equal.
        if (min == max) return;
    }

    // Move elements [min, max) and destroy their source for destructor side effects.
    const auto [first, last] = std::make_pair(from->begin() + min, from->begin() + max);
    std::uninitialized_move(first, last, to->begin() + min);
    std::destroy(first, last);

    std::swap(mSize, other.mSize);
}

template <typename T, size_t N>
inline void swap(StaticVector<T, N>& lhs, StaticVector<T, N>& rhs) {
    lhs.swap(rhs);
}

} // namespace android::ftl
