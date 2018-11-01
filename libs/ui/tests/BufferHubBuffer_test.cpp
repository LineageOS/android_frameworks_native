/*
 * Copyright 2018 The Android Open Source Project
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

#define LOG_TAG "BufferHubBufferTest"

#include <android/frameworks/bufferhub/1.0/IBufferHub.h>
#include <gtest/gtest.h>
#include <hidl/ServiceManagement.h>
#include <hwbinder/IPCThreadState.h>
#include <ui/BufferHubBuffer.h>

namespace android {

namespace {

const int kWidth = 640;
const int kHeight = 480;
const int kLayerCount = 1;
const int kFormat = HAL_PIXEL_FORMAT_RGBA_8888;
const int kUsage = 0;
const size_t kUserMetadataSize = 0;

} // namespace

using dvr::BufferHubDefs::IsBufferGained;
using dvr::BufferHubDefs::kMetadataHeaderSize;
using dvr::BufferHubDefs::kProducerStateBit;
using frameworks::bufferhub::V1_0::IBufferHub;
using hardware::hidl_handle;
using hidl::base::V1_0::IBase;
using pdx::LocalChannelHandle;

class BufferHubBufferTest : public ::testing::Test {
    void SetUp() override { android::hardware::ProcessState::self()->startThreadPool(); }
};

TEST_F(BufferHubBufferTest, CreateBufferHubBufferFails) {
    // Buffer Creation will fail: BLOB format requires height to be 1.
    auto b1 = BufferHubBuffer::Create(kWidth, /*height=*/2, kLayerCount,
                                      /*format=*/HAL_PIXEL_FORMAT_BLOB, kUsage, kUserMetadataSize);

    EXPECT_FALSE(b1->IsConnected());
    EXPECT_FALSE(b1->IsValid());

    // Buffer Creation will fail: user metadata size too large.
    auto b2 = BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage,
                                      /*userMetadataSize=*/std::numeric_limits<size_t>::max());

    EXPECT_FALSE(b2->IsConnected());
    EXPECT_FALSE(b2->IsValid());

    // Buffer Creation will fail: user metadata size too large.
    const size_t userMetadataSize = std::numeric_limits<size_t>::max() - kMetadataHeaderSize;
    auto b3 = BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage,
                                      userMetadataSize);

    EXPECT_FALSE(b3->IsConnected());
    EXPECT_FALSE(b3->IsValid());
}

TEST_F(BufferHubBufferTest, CreateBufferHubBuffer) {
    auto b1 = BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage,
                                      kUserMetadataSize);
    EXPECT_TRUE(b1->IsConnected());
    EXPECT_TRUE(b1->IsValid());
    EXPECT_NE(b1->id(), 0);
}

TEST_F(BufferHubBufferTest, DuplicateBufferHubBuffer) {
    auto b1 = BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage,
                                      kUserMetadataSize);
    int id1 = b1->id();
    uint64_t bufferStateMask1 = b1->client_state_mask();
    EXPECT_NE(bufferStateMask1, 0ULL);
    EXPECT_TRUE(b1->IsValid());
    EXPECT_EQ(b1->user_metadata_size(), kUserMetadataSize);

    auto statusOrHandle = b1->Duplicate();
    EXPECT_TRUE(statusOrHandle);

    // The detached buffer should still be valid.
    EXPECT_TRUE(b1->IsConnected());
    EXPECT_TRUE(b1->IsValid());

    // Gets the channel handle for the duplicated buffer.
    LocalChannelHandle h2 = statusOrHandle.take();
    EXPECT_TRUE(h2.valid());

    std::unique_ptr<BufferHubBuffer> b2 = BufferHubBuffer::Import(std::move(h2));
    EXPECT_FALSE(h2.valid());
    ASSERT_TRUE(b2 != nullptr);
    EXPECT_TRUE(b2->IsValid());
    EXPECT_EQ(b2->user_metadata_size(), kUserMetadataSize);

    int id2 = b2->id();
    uint64_t bufferStateMask2 = b2->client_state_mask();
    EXPECT_NE(bufferStateMask2, 0ULL);

    // These two buffer instances are based on the same physical buffer under the
    // hood, so they should share the same id.
    EXPECT_EQ(id1, id2);
    // We use client_state_mask() to tell those two instances apart.
    EXPECT_NE(bufferStateMask1, bufferStateMask2);

    // Both buffer instances should be in gained state.
    EXPECT_TRUE(IsBufferGained(b1->buffer_state()));
    EXPECT_TRUE(IsBufferGained(b2->buffer_state()));

    // TODO(b/112338294): rewrite test after migration
    return;
}

TEST_F(BufferHubBufferTest, ConnectHidlServer) {
    sp<IBufferHub> bufferhub = IBufferHub::getService();
    ASSERT_NE(nullptr, bufferhub.get());

    // TODO(b/116681016): Fill in real test once the interface gets implemented..
    hidl_handle handle;
    sp<IBase> interface = bufferhub->importBuffer(handle);
    EXPECT_EQ(nullptr, interface.get());
}

} // namespace android
