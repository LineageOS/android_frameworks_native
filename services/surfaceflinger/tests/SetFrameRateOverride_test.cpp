/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <gui/DisplayEventReceiver.h>
#include <gui/ISurfaceComposer.h>
#include <gui/SurfaceComposerClient.h>
#include <sys/epoll.h>
#include <algorithm>

namespace android {
namespace {
using FrameRateOverride = DisplayEventReceiver::Event::FrameRateOverride;

class SetFrameRateOverrideTest : public ::testing::Test {
protected:
    void SetUp() override {
        const ISurfaceComposer::VsyncSource vsyncSource = ISurfaceComposer::eVsyncSourceApp;
        const ISurfaceComposer::EventRegistrationFlags eventRegistration = {
                ISurfaceComposer::EventRegistration::frameRateOverride};

        mDisplayEventReceiver =
                std::make_unique<DisplayEventReceiver>(vsyncSource, eventRegistration);
        EXPECT_EQ(NO_ERROR, mDisplayEventReceiver->initCheck());

        mEpollFd = epoll_create1(EPOLL_CLOEXEC);
        EXPECT_GT(mEpollFd, 1);

        epoll_event event;
        event.events = EPOLLIN;
        EXPECT_EQ(0, epoll_ctl(mEpollFd, EPOLL_CTL_ADD, mDisplayEventReceiver->getFd(), &event));
    }

    void TearDown() override { close(mEpollFd); }

    void setFrameRateAndListenEvents(uid_t uid, float frameRate) {
        status_t ret = SurfaceComposerClient::setOverrideFrameRate(uid, frameRate);
        ASSERT_EQ(NO_ERROR, ret);

        DisplayEventReceiver::Event event;
        bool isOverrideFlushReceived = false;
        mFrameRateOverrides.clear();

        epoll_event epollEvent;
        while (epoll_wait(mEpollFd, &epollEvent, 1, 1000) > 0) {
            while (mDisplayEventReceiver->getEvents(&event, 1) > 0) {
                if (event.header.type == DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE) {
                    mFrameRateOverrides.emplace_back(event.frameRateOverride);
                }
                if (event.header.type ==
                    DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE_FLUSH) {
                    isOverrideFlushReceived = true;
                }
            }

            if (isOverrideFlushReceived) break;
        }
    }

    std::unique_ptr<DisplayEventReceiver> mDisplayEventReceiver;
    std::vector<FrameRateOverride> mFrameRateOverrides;

    int mEpollFd;
};

TEST_F(SetFrameRateOverrideTest, SetFrameRateOverrideCall) {
    uid_t uid = getuid();
    float frameRate = 30.0f;
    setFrameRateAndListenEvents(uid, frameRate);
    // check if the frame rate override we set exists
    ASSERT_TRUE(std::find_if(mFrameRateOverrides.begin(), mFrameRateOverrides.end(),
                             [uid = uid, frameRate = frameRate](auto i) {
                                 return uid == i.uid && frameRate == i.frameRateHz;
                             }) != mFrameRateOverrides.end());

    // test removing frame rate override
    frameRate = 0.0f;
    setFrameRateAndListenEvents(uid, frameRate);
    ASSERT_TRUE(std::find_if(mFrameRateOverrides.begin(), mFrameRateOverrides.end(),
                             [uid = uid, frameRate = frameRate](auto i) {
                                 return uid == i.uid && frameRate == i.frameRateHz;
                             }) == mFrameRateOverrides.end());
}
} // namespace
} // namespace android
