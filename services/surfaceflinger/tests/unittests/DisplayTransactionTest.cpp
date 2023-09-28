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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include "DisplayTransactionTestHelpers.h"

namespace android {

using testing::AnyNumber;
using testing::DoAll;
using testing::Mock;
using testing::Return;
using testing::SetArgPointee;

using android::hardware::graphics::composer::hal::HWDisplayId;

DisplayTransactionTest::DisplayTransactionTest(bool withMockScheduler) {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

    mFlinger.mutableSupportsWideColor() = false;
    mFlinger.mutableDisplayColorSetting() = DisplayColorSetting::kUnmanaged;

    mFlinger.setCreateBufferQueueFunction([](auto, auto, auto) {
        ADD_FAILURE() << "Unexpected request to create a buffer queue.";
    });

    mFlinger.setCreateNativeWindowSurface([](auto) {
        ADD_FAILURE() << "Unexpected request to create a native window surface.";
        return nullptr;
    });

    if (withMockScheduler) {
        injectMockScheduler(PhysicalDisplayId::fromPort(0));
    }

    mFlinger.setupRenderEngine(std::unique_ptr<renderengine::RenderEngine>(mRenderEngine));

    injectMockComposer(0);
}

DisplayTransactionTest::~DisplayTransactionTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    mFlinger.resetScheduler(nullptr);
}

void DisplayTransactionTest::injectMockScheduler(PhysicalDisplayId displayId) {
    LOG_ALWAYS_FATAL_IF(mFlinger.scheduler());

    EXPECT_CALL(*mEventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*mEventThread, createEventConnection(_, _))
            .WillOnce(Return(
                    sp<EventThreadConnection>::make(mEventThread, mock::EventThread::kCallingUid)));

    EXPECT_CALL(*mSFEventThread, registerDisplayEventConnection(_));
    EXPECT_CALL(*mSFEventThread, createEventConnection(_, _))
            .WillOnce(Return(sp<EventThreadConnection>::make(mSFEventThread,
                                                             mock::EventThread::kCallingUid)));

    mFlinger.setupScheduler(std::make_unique<mock::VsyncController>(),
                            std::make_shared<mock::VSyncTracker>(),
                            std::unique_ptr<EventThread>(mEventThread),
                            std::unique_ptr<EventThread>(mSFEventThread),
                            TestableSurfaceFlinger::DefaultDisplayMode{displayId},
                            TestableSurfaceFlinger::SchedulerCallbackImpl::kMock);
}

void DisplayTransactionTest::injectMockComposer(int virtualDisplayCount) {
    if (mComposer) {
        // If reinjecting, disable first to prevent the enable below from being a no-op.
        mFlinger.enableHalVirtualDisplays(false);
    }

    mComposer = new Hwc2::mock::Composer();
    mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));

    EXPECT_CALL(*mComposer, getMaxVirtualDisplayCount()).WillOnce(Return(virtualDisplayCount));
    mFlinger.enableHalVirtualDisplays(true);

    Mock::VerifyAndClear(mComposer);
}

void DisplayTransactionTest::injectFakeBufferQueueFactory() {
    // This setup is only expected once per test.
    ASSERT_TRUE(mConsumer == nullptr && mProducer == nullptr);

    mConsumer = sp<mock::GraphicBufferConsumer>::make();
    mProducer = sp<mock::GraphicBufferProducer>::make();

    mFlinger.setCreateBufferQueueFunction([this](auto outProducer, auto outConsumer, bool) {
        *outProducer = mProducer;
        *outConsumer = mConsumer;
    });
}

void DisplayTransactionTest::injectFakeNativeWindowSurfaceFactory() {
    // This setup is only expected once per test.
    ASSERT_TRUE(mNativeWindowSurface == nullptr);

    mNativeWindowSurface = new surfaceflinger::mock::NativeWindowSurface();

    mFlinger.setCreateNativeWindowSurface([this](auto) {
        return std::unique_ptr<surfaceflinger::NativeWindowSurface>(mNativeWindowSurface);
    });
}

bool DisplayTransactionTest::hasPhysicalHwcDisplay(HWDisplayId hwcDisplayId) const {
    const auto& map = mFlinger.hwcPhysicalDisplayIdMap();

    const auto it = map.find(hwcDisplayId);
    if (it == map.end()) return false;

    return mFlinger.hwcDisplayData().count(it->second) == 1;
}

bool DisplayTransactionTest::hasTransactionFlagSet(int32_t flag) const {
    return mFlinger.transactionFlags() & flag;
}

bool DisplayTransactionTest::hasDisplayDevice(const sp<IBinder>& displayToken) const {
    return mFlinger.displays().contains(displayToken);
}

const DisplayDevice& DisplayTransactionTest::getDisplayDevice(
        const sp<IBinder>& displayToken) const {
    return *mFlinger.displays().get(displayToken)->get();
}

bool DisplayTransactionTest::hasCurrentDisplayState(const sp<IBinder>& displayToken) const {
    return mFlinger.currentState().displays.indexOfKey(displayToken) >= 0;
}

const DisplayDeviceState& DisplayTransactionTest::getCurrentDisplayState(
        const sp<IBinder>& displayToken) const {
    return mFlinger.currentState().displays.valueFor(displayToken);
}

bool DisplayTransactionTest::hasDrawingDisplayState(const sp<IBinder>& displayToken) const {
    return mFlinger.drawingState().displays.indexOfKey(displayToken) >= 0;
}

const DisplayDeviceState& DisplayTransactionTest::getDrawingDisplayState(
        const sp<IBinder>& displayToken) const {
    return mFlinger.drawingState().displays.valueFor(displayToken);
}

} // namespace android
