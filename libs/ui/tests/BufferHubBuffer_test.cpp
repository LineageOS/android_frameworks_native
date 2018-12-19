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

#include <android/frameworks/bufferhub/1.0/IBufferClient.h>
#include <android/frameworks/bufferhub/1.0/IBufferHub.h>
#include <android/hardware_buffer.h>
#include <cutils/native_handle.h>
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

using BufferHubDefs::AnyClientAcquired;
using BufferHubDefs::AnyClientGained;
using BufferHubDefs::AnyClientPosted;
using BufferHubDefs::IsBufferReleased;
using BufferHubDefs::IsClientAcquired;
using BufferHubDefs::IsClientGained;
using BufferHubDefs::IsClientPosted;
using BufferHubDefs::IsClientReleased;
using BufferHubDefs::kFirstClientBitMask;
using BufferHubDefs::kMetadataHeaderSize;
using frameworks::bufferhub::V1_0::BufferHubStatus;
using frameworks::bufferhub::V1_0::IBufferClient;
using frameworks::bufferhub::V1_0::IBufferHub;
using hardware::hidl_handle;
using hardware::graphics::common::V1_2::HardwareBufferDescription;
using hidl::base::V1_0::IBase;
using pdx::LocalChannelHandle;

class BufferHubBufferTest : public ::testing::Test {
protected:
    void SetUp() override { android::hardware::ProcessState::self()->startThreadPool(); }
};

class BufferHubBufferStateTransitionTest : public BufferHubBufferTest {
protected:
    void SetUp() override {
        BufferHubBufferTest::SetUp();
        CreateTwoClientsOfABuffer();
    }

    std::unique_ptr<BufferHubBuffer> b1;
    uint64_t b1ClientMask = 0U;
    std::unique_ptr<BufferHubBuffer> b2;
    uint64_t b2ClientMask = 0U;

private:
    // Creates b1 and b2 as the clients of the same buffer for testing.
    void CreateTwoClientsOfABuffer();
};

void BufferHubBufferStateTransitionTest::CreateTwoClientsOfABuffer() {
    b1 = BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage, kUserMetadataSize);
    b1ClientMask = b1->client_state_mask();
    ASSERT_NE(b1ClientMask, 0U);
    auto statusOrHandle = b1->Duplicate();
    ASSERT_TRUE(statusOrHandle);
    LocalChannelHandle h2 = statusOrHandle.take();
    b2 = BufferHubBuffer::Import(std::move(h2));
    b2ClientMask = b2->client_state_mask();
    ASSERT_NE(b2ClientMask, 0U);
    ASSERT_NE(b2ClientMask, b1ClientMask);
}

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
    EXPECT_NE(bufferStateMask1, 0U);
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
    EXPECT_NE(bufferStateMask2, 0U);

    // These two buffer instances are based on the same physical buffer under the
    // hood, so they should share the same id.
    EXPECT_EQ(id1, id2);
    // We use client_state_mask() to tell those two instances apart.
    EXPECT_NE(bufferStateMask1, bufferStateMask2);

    // Both buffer instances should be in released state currently.
    EXPECT_TRUE(IsBufferReleased(b1->buffer_state()));
    EXPECT_TRUE(IsBufferReleased(b2->buffer_state()));

    // TODO(b/112338294): rewrite test after migration
    return;
}

TEST_F(BufferHubBufferStateTransitionTest, GainBuffer_fromReleasedState) {
    ASSERT_TRUE(IsBufferReleased(b1->buffer_state()));

    // Successful gaining the buffer should change the buffer state bit of b1 to
    // gained state, other client state bits to released state.
    EXPECT_EQ(b1->Gain(), 0);
    EXPECT_TRUE(IsClientGained(b1->buffer_state(), b1ClientMask));
}

TEST_F(BufferHubBufferStateTransitionTest, GainBuffer_fromGainedState) {
    ASSERT_EQ(b1->Gain(), 0);
    auto current_buffer_state = b1->buffer_state();
    ASSERT_TRUE(IsClientGained(current_buffer_state, b1ClientMask));

    // Gaining from gained state by the same client should not return error.
    EXPECT_EQ(b1->Gain(), 0);

    // Gaining from gained state by another client should return error.
    EXPECT_EQ(b2->Gain(), -EBUSY);
}

TEST_F(BufferHubBufferStateTransitionTest, GainBuffer_fromAcquiredState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_EQ(b1->Post(), 0);
    ASSERT_EQ(b2->Acquire(), 0);
    ASSERT_TRUE(AnyClientAcquired(b1->buffer_state()));

    // Gaining from acquired state should fail.
    EXPECT_EQ(b1->Gain(), -EBUSY);
    EXPECT_EQ(b2->Gain(), -EBUSY);
}

TEST_F(BufferHubBufferStateTransitionTest, GainBuffer_fromOtherClientInPostedState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_EQ(b1->Post(), 0);
    ASSERT_TRUE(AnyClientPosted(b1->buffer_state()));

    // Gaining a buffer who has other posted client should succeed.
    EXPECT_EQ(b1->Gain(), 0);
}

TEST_F(BufferHubBufferStateTransitionTest, GainBuffer_fromSelfInPostedState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_EQ(b1->Post(), 0);
    ASSERT_TRUE(AnyClientPosted(b1->buffer_state()));

    // A posted client should be able to gain the buffer when there is no other clients in
    // acquired state.
    EXPECT_EQ(b2->Gain(), 0);
}

TEST_F(BufferHubBufferStateTransitionTest, PostBuffer_fromOtherInGainedState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_TRUE(IsClientGained(b1->buffer_state(), b1ClientMask));

    EXPECT_EQ(b2->Post(), -EBUSY);
}

TEST_F(BufferHubBufferStateTransitionTest, PostBuffer_fromSelfInGainedState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_TRUE(IsClientGained(b1->buffer_state(), b1ClientMask));

    EXPECT_EQ(b1->Post(), 0);
    auto current_buffer_state = b1->buffer_state();
    EXPECT_TRUE(IsClientReleased(current_buffer_state, b1ClientMask));
    EXPECT_TRUE(IsClientPosted(current_buffer_state, b2ClientMask));
}

TEST_F(BufferHubBufferStateTransitionTest, PostBuffer_fromPostedState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_EQ(b1->Post(), 0);
    ASSERT_TRUE(AnyClientPosted(b1->buffer_state()));

    // Post from posted state should fail.
    EXPECT_EQ(b1->Post(), -EBUSY);
    EXPECT_EQ(b2->Post(), -EBUSY);
}

TEST_F(BufferHubBufferStateTransitionTest, PostBuffer_fromAcquiredState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_EQ(b1->Post(), 0);
    ASSERT_EQ(b2->Acquire(), 0);
    ASSERT_TRUE(AnyClientAcquired(b1->buffer_state()));

    // Posting from acquired state should fail.
    EXPECT_EQ(b1->Post(), -EBUSY);
    EXPECT_EQ(b2->Post(), -EBUSY);
}

TEST_F(BufferHubBufferStateTransitionTest, PostBuffer_fromReleasedState) {
    ASSERT_TRUE(IsBufferReleased(b1->buffer_state()));

    // Posting from released state should fail.
    EXPECT_EQ(b1->Post(), -EBUSY);
    EXPECT_EQ(b2->Post(), -EBUSY);
}

TEST_F(BufferHubBufferStateTransitionTest, AcquireBuffer_fromSelfInPostedState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_EQ(b1->Post(), 0);
    ASSERT_TRUE(IsClientPosted(b1->buffer_state(), b2ClientMask));

    // Acquire from posted state should pass.
    EXPECT_EQ(b2->Acquire(), 0);
}

TEST_F(BufferHubBufferStateTransitionTest, AcquireBuffer_fromOtherInPostedState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_EQ(b1->Post(), 0);
    ASSERT_TRUE(IsClientPosted(b1->buffer_state(), b2ClientMask));

    // Acquire from released state should fail, although there are other clients
    // in posted state.
    EXPECT_EQ(b1->Acquire(), -EBUSY);
}

TEST_F(BufferHubBufferStateTransitionTest, AcquireBuffer_fromSelfInAcquiredState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_EQ(b1->Post(), 0);
    ASSERT_EQ(b2->Acquire(), 0);
    auto current_buffer_state = b1->buffer_state();
    ASSERT_TRUE(IsClientAcquired(current_buffer_state, b2ClientMask));

    // Acquiring from acquired state by the same client should not error out.
    EXPECT_EQ(b2->Acquire(), 0);
}

TEST_F(BufferHubBufferStateTransitionTest, AcquireBuffer_fromReleasedState) {
    ASSERT_TRUE(IsBufferReleased(b1->buffer_state()));

    // Acquiring form released state should fail.
    EXPECT_EQ(b1->Acquire(), -EBUSY);
    EXPECT_EQ(b2->Acquire(), -EBUSY);
}

TEST_F(BufferHubBufferStateTransitionTest, AcquireBuffer_fromGainedState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_TRUE(AnyClientGained(b1->buffer_state()));

    // Acquiring from gained state should fail.
    EXPECT_EQ(b1->Acquire(), -EBUSY);
    EXPECT_EQ(b2->Acquire(), -EBUSY);
}

TEST_F(BufferHubBufferStateTransitionTest, ReleaseBuffer_fromSelfInReleasedState) {
    ASSERT_TRUE(IsBufferReleased(b1->buffer_state()));

    EXPECT_EQ(b1->Release(), 0);
}

TEST_F(BufferHubBufferStateTransitionTest, ReleaseBuffer_fromSelfInGainedState) {
    ASSERT_TRUE(IsBufferReleased(b1->buffer_state()));
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_TRUE(AnyClientGained(b1->buffer_state()));

    EXPECT_EQ(b1->Release(), 0);
}

TEST_F(BufferHubBufferStateTransitionTest, ReleaseBuffer_fromSelfInPostedState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_EQ(b1->Post(), 0);
    ASSERT_TRUE(AnyClientPosted(b1->buffer_state()));

    EXPECT_EQ(b2->Release(), 0);
}

TEST_F(BufferHubBufferStateTransitionTest, ReleaseBuffer_fromSelfInAcquiredState) {
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_EQ(b1->Post(), 0);
    ASSERT_EQ(b2->Acquire(), 0);
    ASSERT_TRUE(AnyClientAcquired(b1->buffer_state()));

    EXPECT_EQ(b2->Release(), 0);
}

} // namespace
} // namespace android
