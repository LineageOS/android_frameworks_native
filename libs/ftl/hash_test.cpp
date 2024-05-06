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

#include <ftl/hash.h>
#include <gtest/gtest.h>

#include <numeric>
#include <string>

namespace android::test {

TEST(Hash, StableHash) {
  EXPECT_EQ(11160318154034397263ull, (ftl::stable_hash({})));

  std::string string(64, '?');
  std::iota(string.begin(), string.end(), 'A');

  // Maximum length is 64 characters.
  EXPECT_FALSE(ftl::stable_hash(string + '\n'));

  EXPECT_EQ(6278090252846864564ull, ftl::stable_hash(std::string_view(string).substr(0, 8)));
  EXPECT_EQ(1883356980931444616ull, ftl::stable_hash(std::string_view(string).substr(0, 16)));
  EXPECT_EQ(8073093283835059304ull, ftl::stable_hash(std::string_view(string).substr(0, 32)));
  EXPECT_EQ(18197365392429149980ull, ftl::stable_hash(string));
}

}  // namespace android::test
