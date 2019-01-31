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
#include <ui/BufferHubMetadata.h>

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

  unique_fd h2 = unique_fd(dup(m1.ashmem_fd().get()));
  EXPECT_NE(h2.get(), -1);

  BufferHubMetadata m2 = BufferHubMetadata::Import(std::move(h2));
  EXPECT_EQ(h2.get(), -1);
  EXPECT_TRUE(m1.IsValid());
  BufferHubDefs::MetadataHeader* mh1 = m1.metadata_header();
  EXPECT_NE(mh1, nullptr);

  // Check if the newly allocated buffer is initialized in released state (i.e.
  // state equals to 0U).
  EXPECT_TRUE(mh1->buffer_state.load() == 0U);

  EXPECT_TRUE(m2.IsValid());
  BufferHubDefs::MetadataHeader* mh2 = m2.metadata_header();
  EXPECT_NE(mh2, nullptr);

  // Check if the newly allocated buffer is initialized in released state (i.e.
  // state equals to 0U).
  EXPECT_TRUE(mh2->buffer_state.load() == 0U);
}

TEST_F(BufferHubMetadataTest, MoveMetadataInvalidatesOldOne) {
  BufferHubMetadata m1 = BufferHubMetadata::Create(sizeof(int));
  EXPECT_TRUE(m1.IsValid());
  EXPECT_NE(m1.metadata_header(), nullptr);
  EXPECT_NE(m1.ashmem_fd().get(), -1);
  EXPECT_EQ(m1.user_metadata_size(), sizeof(int));

  BufferHubMetadata m2 = std::move(m1);

  // After the move, the metadata header (a raw pointer) should be reset in the older buffer.
  EXPECT_EQ(m1.metadata_header(), nullptr);
  EXPECT_NE(m2.metadata_header(), nullptr);

  EXPECT_EQ(m1.ashmem_fd().get(), -1);
  EXPECT_NE(m2.ashmem_fd().get(), -1);

  EXPECT_EQ(m1.user_metadata_size(), 0U);
  EXPECT_EQ(m2.user_metadata_size(), sizeof(int));

  BufferHubMetadata m3{std::move(m2)};

  // After the move, the metadata header (a raw pointer) should be reset in the older buffer.
  EXPECT_EQ(m2.metadata_header(), nullptr);
  EXPECT_NE(m3.metadata_header(), nullptr);

  EXPECT_EQ(m2.ashmem_fd().get(), -1);
  EXPECT_NE(m3.ashmem_fd().get(), -1);

  EXPECT_EQ(m2.user_metadata_size(), 0U);
  EXPECT_EQ(m3.user_metadata_size(), sizeof(int));
}

}  // namespace dvr
}  // namespace android
