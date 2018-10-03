/*
 * Copyright (C) 2018 The Android Open Source Project
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
#include <private/dvr/buffer_hub_metadata.h>

using android::dvr::BufferHubDefs::IsBufferGained;

namespace android {
namespace dvr {

constexpr size_t kEmptyUserMetadataSize = 0;

class BufferHubMetadataTest : public ::testing::Test {};

TEST_F(BufferHubMetadataTest, Create_UserMetdataSizeTooBig) {
  BufferHubMetadata m1 =
      BufferHubMetadata::Create(std::numeric_limits<uint32_t>::max());
  EXPECT_FALSE(m1.IsValid());
}

TEST_F(BufferHubMetadataTest, Create_Success) {
  BufferHubMetadata m1 = BufferHubMetadata::Create(kEmptyUserMetadataSize);
  EXPECT_TRUE(m1.IsValid());
  EXPECT_NE(m1.metadata_header(), nullptr);
}

TEST_F(BufferHubMetadataTest, Import_Success) {
  BufferHubMetadata m1 = BufferHubMetadata::Create(kEmptyUserMetadataSize);
  EXPECT_TRUE(m1.IsValid());
  EXPECT_NE(m1.metadata_header(), nullptr);

  pdx::LocalHandle h2 = m1.ashmem_handle().Duplicate();
  EXPECT_TRUE(h2.IsValid());

  BufferHubMetadata m2 = BufferHubMetadata::Import(std::move(h2));
  EXPECT_FALSE(h2.IsValid());
  EXPECT_TRUE(m1.IsValid());
  BufferHubDefs::MetadataHeader* mh1 = m1.metadata_header();
  EXPECT_NE(mh1, nullptr);

  // TODO(b/111976433): Update this test once BufferHub state machine gets
  // updated. In the old model, buffer starts in the gained state (i.e.
  // valued 0). In the new model, buffer states in the released state.
  EXPECT_TRUE(IsBufferGained(mh1->fence_state.load()));

  EXPECT_TRUE(m2.IsValid());
  BufferHubDefs::MetadataHeader* mh2 = m2.metadata_header();
  EXPECT_NE(mh2, nullptr);

  // TODO(b/111976433): Update this test once BufferHub state machine gets
  // updated. In the old model, buffer starts in the gained state (i.e.
  // valued 0). In the new model, buffer states in the released state.
  EXPECT_TRUE(IsBufferGained(mh2->fence_state.load()));
}

TEST_F(BufferHubMetadataTest, MoveMetadataInvalidatesOldOne) {
  BufferHubMetadata m1 = BufferHubMetadata::Create(sizeof(int));
  EXPECT_TRUE(m1.IsValid());
  EXPECT_NE(m1.metadata_header(), nullptr);
  EXPECT_TRUE(m1.ashmem_handle().IsValid());
  EXPECT_EQ(m1.user_metadata_size(), sizeof(int));

  BufferHubMetadata m2 = std::move(m1);

  // After the move, the metadata header (a raw pointer) should be reset in the
  // older buffer.
  EXPECT_EQ(m1.metadata_header(), nullptr);
  EXPECT_NE(m2.metadata_header(), nullptr);

  EXPECT_FALSE(m1.ashmem_handle().IsValid());
  EXPECT_TRUE(m2.ashmem_handle().IsValid());

  EXPECT_EQ(m1.user_metadata_size(), 0U);
  EXPECT_EQ(m2.user_metadata_size(), sizeof(int));

  BufferHubMetadata m3{std::move(m2)};

  // After the move, the metadata header (a raw pointer) should be reset in the
  // older buffer.
  EXPECT_EQ(m2.metadata_header(), nullptr);
  EXPECT_NE(m3.metadata_header(), nullptr);

  EXPECT_FALSE(m2.ashmem_handle().IsValid());
  EXPECT_TRUE(m3.ashmem_handle().IsValid());

  EXPECT_EQ(m2.user_metadata_size(), 0U);
  EXPECT_EQ(m3.user_metadata_size(), sizeof(int));
}

}  // namespace dvr
}  // namespace android
