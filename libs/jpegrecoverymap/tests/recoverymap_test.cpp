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

#include <gtest/gtest.h>
#include <jpegrecoverymap/recoverymap.h>

namespace android::recoverymap {

class RecoveryMapTest : public testing::Test {
public:
  RecoveryMapTest();
  ~RecoveryMapTest();
protected:
  virtual void SetUp();
  virtual void TearDown();
};

RecoveryMapTest::RecoveryMapTest() {}
RecoveryMapTest::~RecoveryMapTest() {}

void RecoveryMapTest::SetUp() {}
void RecoveryMapTest::TearDown() {}

TEST_F(RecoveryMapTest, build) {
  // Force all of the recovery map lib to be linked by calling all public functions.
  RecoveryMap recovery_map;
  recovery_map.encodeJPEGR(nullptr, nullptr, static_cast<jpegr_transfer_function>(0),
                           nullptr, 0, nullptr);
  recovery_map.encodeJPEGR(nullptr, nullptr, nullptr, static_cast<jpegr_transfer_function>(0),
                           nullptr);
  recovery_map.encodeJPEGR(nullptr, nullptr, static_cast<jpegr_transfer_function>(0), nullptr);
  recovery_map.decodeJPEGR(nullptr, nullptr, nullptr, false);
}

} // namespace android::recoverymap
