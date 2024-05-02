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
#include <ftl/small_map.h>
#include <ftl/static_vector.h>
#include <gtest/gtest.h>

#include <string_view>

namespace android::test {

// Keep in sync with example usage in header file.
TEST(Algorithm, Contains) {
  const ftl::StaticVector vector = {1, 2, 3};
  EXPECT_TRUE(ftl::contains(vector, 1));

  EXPECT_FALSE(ftl::contains(vector, 0));
  EXPECT_TRUE(ftl::contains(vector, 2));
  EXPECT_TRUE(ftl::contains(vector, 3));
  EXPECT_FALSE(ftl::contains(vector, 4));
}

// Keep in sync with example usage in header file.
TEST(Algorithm, FindIf) {
  using namespace std::string_view_literals;

  const ftl::StaticVector vector = {"upside"sv, "down"sv, "cake"sv};
  EXPECT_EQ(ftl::find_if(vector, [](const auto& str) { return str.front() == 'c'; }), "cake"sv);

  const ftl::SmallMap map = ftl::init::map<int, ftl::StaticVector<std::string_view, 3>>(
      12, "snow"sv, "cone"sv)(13, "tiramisu"sv)(14, "upside"sv, "down"sv, "cake"sv);

  using Map = decltype(map);

  EXPECT_EQ(14, ftl::find_if(map, [](const auto& pair) {
                  return pair.second.size() == 3;
                }).transform(ftl::to_key<Map>));

  const auto opt = ftl::find_if(map, [](const auto& pair) {
                     return pair.second.size() == 1;
                   }).transform(ftl::to_mapped_ref<Map>);

  ASSERT_TRUE(opt);
  EXPECT_EQ(opt->get(), ftl::StaticVector("tiramisu"sv));
}

TEST(Algorithm, StaticRef) {
  using namespace std::string_view_literals;

  const ftl::SmallMap map = ftl::init::map(13, "tiramisu"sv)(14, "upside-down cake"sv);
  ASSERT_EQ("???"sv,
            map.get(20).or_else(ftl::static_ref<std::string_view>([] { return "???"sv; }))->get());

  using Map = decltype(map);

  ASSERT_EQ("snow cone"sv,
            ftl::find_if(map, [](const auto& pair) { return pair.second.front() == 's'; })
                .transform(ftl::to_mapped_ref<Map>)
                .or_else(ftl::static_ref<std::string_view>([] { return "snow cone"sv; }))
                ->get());
}

}  // namespace android::test
