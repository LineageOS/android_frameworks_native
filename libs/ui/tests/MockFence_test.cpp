/*
 * Copyright 2021 The Android Open Source Project
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

#include <ui/MockFence.h>

#include <gtest/gtest.h>

namespace android::ui {

using testing::Return;

class MockFenceTest : public testing::Test {
public:
    sp<Fence> getFenceForTesting() const { return mMockFence; }

    const mock::MockFence& getMockFence() const { return *mMockFence; }

private:
    sp<mock::MockFence> mMockFence = sp<mock::MockFence>::make();
};

TEST_F(MockFenceTest, getSignalTime) {
    sp<Fence> fence = getFenceForTesting();

    EXPECT_CALL(getMockFence(), getSignalTime).WillOnce(Return(Fence::SIGNAL_TIME_PENDING));
    EXPECT_EQ(Fence::SIGNAL_TIME_PENDING, fence->getSignalTime());

    EXPECT_CALL(getMockFence(), getSignalTime).WillOnce(Return(1234));
    EXPECT_EQ(1234, fence->getSignalTime());
}

TEST_F(MockFenceTest, getStatus) {
    sp<Fence> fence = getFenceForTesting();

    EXPECT_CALL(getMockFence(), getStatus).WillOnce(Return(Fence::Status::Unsignaled));
    EXPECT_EQ(Fence::Status::Unsignaled, fence->getStatus());

    EXPECT_CALL(getMockFence(), getStatus).WillOnce(Return(Fence::Status::Signaled));
    EXPECT_EQ(Fence::Status::Signaled, fence->getStatus());

    EXPECT_CALL(getMockFence(), getStatus).WillOnce(Return(Fence::Status::Invalid));
    EXPECT_EQ(Fence::Status::Invalid, fence->getStatus());
}
} // namespace android::ui
