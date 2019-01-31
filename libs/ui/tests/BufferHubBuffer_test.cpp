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

#include <errno.h>
#include <sys/epoll.h>

#include <android/hardware_buffer.h>
#include <cutils/native_handle.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hidl/ServiceManagement.h>
#include <hwbinder/IPCThreadState.h>
#include <ui/BufferHubBuffer.h>
#include <ui/BufferHubEventFd.h>

namespace android {

namespace {

using ::android::BufferHubDefs::AnyClientAcquired;
using ::android::BufferHubDefs::AnyClientGained;
using ::android::BufferHubDefs::AnyClientPosted;
using ::android::BufferHubDefs::IsClientAcquired;
using ::android::BufferHubDefs::IsClientGained;
using ::android::BufferHubDefs::IsClientPosted;
using ::android::BufferHubDefs::IsClientReleased;
using ::android::BufferHubDefs::kMetadataHeaderSize;
using ::testing::IsNull;
using ::testing::NotNull;

const int kWidth = 640;
const int kHeight = 480;
const int kLayerCount = 1;
const int kFormat = HAL_PIXEL_FORMAT_RGBA_8888;
const int kUsage = 0;
const AHardwareBuffer_Desc kDesc = {kWidth, kHeight,        kLayerCount,  kFormat,
                                    kUsage, /*stride=*/0UL, /*rfu0=*/0UL, /*rfu1=*/0ULL};
const size_t kUserMetadataSize = 1;

class BufferHubBufferTest : public ::testing::Test {
protected:
    void SetUp() override { android::hardware::ProcessState::self()->startThreadPool(); }
};

bool cmpAHardwareBufferDesc(const AHardwareBuffer_Desc& desc, const AHardwareBuffer_Desc& other) {
    // Not comparing stride because it's unknown before allocation
    return desc.format == other.format && desc.height == other.height &&
            desc.layers == other.layers && desc.usage == other.usage && desc.width == other.width;
}

class BufferHubBufferStateTransitionTest : public BufferHubBufferTest {
protected:
    void SetUp() override {
        BufferHubBufferTest::SetUp();
        CreateTwoClientsOfABuffer();
    }

    std::unique_ptr<BufferHubBuffer> b1;
    uint32_t b1ClientMask = 0U;
    std::unique_ptr<BufferHubBuffer> b2;
    uint32_t b2ClientMask = 0U;

private:
    // Creates b1 and b2 as the clients of the same buffer for testing.
    void CreateTwoClientsOfABuffer();
};

void BufferHubBufferStateTransitionTest::CreateTwoClientsOfABuffer() {
    b1 = BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage, kUserMetadataSize);
    ASSERT_THAT(b1, NotNull());
    b1ClientMask = b1->client_state_mask();
    ASSERT_NE(b1ClientMask, 0U);

    native_handle_t* token = b1->Duplicate();
    ASSERT_THAT(token, NotNull());

    // TODO(b/122543147): use a movalbe wrapper for token
    b2 = BufferHubBuffer::Import(token);
    native_handle_close(token);
    native_handle_delete(token);
    ASSERT_THAT(b2, NotNull());

    b2ClientMask = b2->client_state_mask();
    ASSERT_NE(b2ClientMask, 0U);
    ASSERT_NE(b2ClientMask, b1ClientMask);
}

TEST_F(BufferHubBufferTest, CreateBufferFails) {
    // Buffer Creation will fail: BLOB format requires height to be 1.
    auto b1 = BufferHubBuffer::Create(kWidth, /*height=*/2, kLayerCount,
                                      /*format=*/HAL_PIXEL_FORMAT_BLOB, kUsage, kUserMetadataSize);

    EXPECT_THAT(b1, IsNull());

    // Buffer Creation will fail: user metadata size too large.
    auto b2 = BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage,
                                      /*userMetadataSize=*/std::numeric_limits<size_t>::max());

    EXPECT_THAT(b2, IsNull());

    // Buffer Creation will fail: user metadata size too large.
    const size_t userMetadataSize = std::numeric_limits<size_t>::max() - kMetadataHeaderSize;
    auto b3 = BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage,
                                      userMetadataSize);

    EXPECT_THAT(b3, IsNull());
}

TEST_F(BufferHubBufferTest, CreateBuffer) {
    auto b1 = BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage,
                                      kUserMetadataSize);
    ASSERT_THAT(b1, NotNull());
    EXPECT_TRUE(b1->IsConnected());
    EXPECT_TRUE(b1->IsValid());
    EXPECT_TRUE(cmpAHardwareBufferDesc(b1->desc(), kDesc));
    EXPECT_EQ(b1->user_metadata_size(), kUserMetadataSize);
}

TEST_F(BufferHubBufferTest, DuplicateAndImportBuffer) {
    auto b1 = BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage,
                                      kUserMetadataSize);
    ASSERT_THAT(b1, NotNull());
    EXPECT_TRUE(b1->IsValid());

    native_handle_t* token = b1->Duplicate();
    EXPECT_TRUE(token);

    // The detached buffer should still be valid.
    EXPECT_TRUE(b1->IsConnected());
    EXPECT_TRUE(b1->IsValid());

    std::unique_ptr<BufferHubBuffer> b2 = BufferHubBuffer::Import(token);
    native_handle_close(token);
    native_handle_delete(token);

    ASSERT_THAT(b2, NotNull());
    EXPECT_TRUE(b2->IsValid());

    EXPECT_TRUE(cmpAHardwareBufferDesc(b1->desc(), b2->desc()));
    EXPECT_EQ(b1->user_metadata_size(), b2->user_metadata_size());

    // These two buffer instances are based on the same physical buffer under the
    // hood, so they should share the same id.
    EXPECT_EQ(b1->id(), b2->id());
    // We use client_state_mask() to tell those two instances apart.
    EXPECT_NE(b1->client_state_mask(), b2->client_state_mask());

    // Both buffer instances should be in released state currently.
    EXPECT_TRUE(b1->IsReleased());
    EXPECT_TRUE(b2->IsReleased());

    // The event fd should behave like duped event fds.
    const BufferHubEventFd& eventFd1 = b1->eventFd();
    ASSERT_GE(eventFd1.get(), 0);
    const BufferHubEventFd& eventFd2 = b2->eventFd();
    ASSERT_GE(eventFd2.get(), 0);

    base::unique_fd epollFd(epoll_create(64));
    ASSERT_GE(epollFd.get(), 0);

    // Add eventFd1 to epoll set, and signal eventFd2.
    epoll_event e = {.events = EPOLLIN | EPOLLET, .data = {.u32 = 0}};
    ASSERT_EQ(epoll_ctl(epollFd.get(), EPOLL_CTL_ADD, eventFd1.get(), &e), 0) << strerror(errno);

    std::array<epoll_event, 1> events;
    EXPECT_EQ(epoll_wait(epollFd.get(), events.data(), events.size(), 0), 0);

    eventFd2.signal();
    EXPECT_EQ(epoll_wait(epollFd.get(), events.data(), events.size(), 0), 1);

    // The epoll fd is edge triggered, so it only responds to the eventFd once.
    EXPECT_EQ(epoll_wait(epollFd.get(), events.data(), events.size(), 0), 0);

    eventFd2.signal();
    eventFd2.clear();
    EXPECT_EQ(epoll_wait(epollFd.get(), events.data(), events.size(), 0), 0);
}

TEST_F(BufferHubBufferTest, ImportFreedBuffer) {
    auto b1 = BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage,
                                      kUserMetadataSize);
    ASSERT_THAT(b1, NotNull());
    EXPECT_TRUE(b1->IsValid());

    native_handle_t* token = b1->Duplicate();
    EXPECT_TRUE(token);

    // Explicitly destroy b1. Backend buffer should be freed and token becomes invalid
    b1.reset();

    // TODO(b/122543147): use a movalbe wrapper for token
    std::unique_ptr<BufferHubBuffer> b2 = BufferHubBuffer::Import(token);
    native_handle_close(token);
    native_handle_delete(token);

    // Import should fail with INVALID_TOKEN
    EXPECT_THAT(b2, IsNull());
}

// nullptr must not crash the service
TEST_F(BufferHubBufferTest, ImportNullToken) {
    auto b1 = BufferHubBuffer::Import(nullptr);
    EXPECT_THAT(b1, IsNull());
}

TEST_F(BufferHubBufferTest, ImportInvalidToken) {
    native_handle_t* token = native_handle_create(/*numFds=*/0, /*numInts=*/1);
    token->data[0] = 0;

    auto b1 = BufferHubBuffer::Import(token);
    native_handle_delete(token);

    EXPECT_THAT(b1, IsNull());
}

TEST_F(BufferHubBufferStateTransitionTest, GainBuffer_fromReleasedState) {
    ASSERT_TRUE(b1->IsReleased());

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
    ASSERT_TRUE(b1->IsReleased());

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
    ASSERT_TRUE(b1->IsReleased());

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
    ASSERT_TRUE(b1->IsReleased());

    EXPECT_EQ(b1->Release(), 0);
}

TEST_F(BufferHubBufferStateTransitionTest, ReleaseBuffer_fromSelfInGainedState) {
    ASSERT_TRUE(b1->IsReleased());
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

TEST_F(BufferHubBufferStateTransitionTest, BasicUsage) {
    // 1 producer buffer and 1 consumer buffer initialised in testcase setup.
    // Test if this set of basic operation succeed:
    // Producer post three times to the consumer, and released by consumer.
    for (int i = 0; i < 3; ++i) {
        ASSERT_EQ(b1->Gain(), 0);
        ASSERT_EQ(b1->Post(), 0);
        ASSERT_EQ(b2->Acquire(), 0);
        ASSERT_EQ(b2->Release(), 0);
    }
}

TEST_F(BufferHubBufferTest, createNewConsumerAfterGain) {
    // Create a poducer buffer and gain.
    std::unique_ptr<BufferHubBuffer> b1 =
            BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage,
                                    kUserMetadataSize);
    ASSERT_THAT(b1, NotNull());
    ASSERT_EQ(b1->Gain(), 0);

    // Create a consumer of the buffer and test if the consumer can acquire the
    // buffer if producer posts.
    // TODO(b/122543147): use a movalbe wrapper for token
    native_handle_t* token = b1->Duplicate();
    ASSERT_TRUE(token);

    std::unique_ptr<BufferHubBuffer> b2 = BufferHubBuffer::Import(token);
    native_handle_close(token);
    native_handle_delete(token);

    ASSERT_THAT(b2, NotNull());
    ASSERT_NE(b1->client_state_mask(), b2->client_state_mask());

    ASSERT_EQ(b1->Post(), 0);
    EXPECT_EQ(b2->Acquire(), 0);
}

TEST_F(BufferHubBufferTest, createNewConsumerAfterPost) {
    // Create a poducer buffer and post.
    std::unique_ptr<BufferHubBuffer> b1 =
            BufferHubBuffer::Create(kWidth, kHeight, kLayerCount, kFormat, kUsage,
                                    kUserMetadataSize);
    ASSERT_EQ(b1->Gain(), 0);
    ASSERT_EQ(b1->Post(), 0);

    // Create a consumer of the buffer and test if the consumer can acquire the
    // buffer if producer posts.
    // TODO(b/122543147): use a movalbe wrapper for token
    native_handle_t* token = b1->Duplicate();
    ASSERT_TRUE(token);

    std::unique_ptr<BufferHubBuffer> b2 = BufferHubBuffer::Import(token);
    native_handle_close(token);
    native_handle_delete(token);

    ASSERT_THAT(b2, NotNull());
    ASSERT_NE(b1->client_state_mask(), b2->client_state_mask());

    EXPECT_EQ(b2->Acquire(), 0);
}

} // namespace

} // namespace android
