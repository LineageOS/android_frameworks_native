/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "../InputProcessor.h"
#include <gtest/gtest.h>
#include <gui/constants.h>

#include "TestInputListener.h"

#include <aidl/android/hardware/input/processor/BnInputProcessor.h>
#include <aidl/android/hardware/input/processor/IInputProcessor.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

using namespace aidl::android::hardware::input;
using aidl::android::hardware::input::common::Classification;
using aidl::android::hardware::input::processor::IInputProcessor;

namespace android {

// --- InputProcessorTest ---

static NotifyMotionArgs generateBasicMotionArgs() {
    // Create a basic motion event for testing
    PointerProperties properties;
    properties.id = 0;
    properties.toolType = ToolType::FINGER;

    PointerCoords coords;
    coords.clear();
    coords.setAxisValue(AMOTION_EVENT_AXIS_X, 1);
    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, 1);
    static constexpr nsecs_t downTime = 2;
    NotifyMotionArgs motionArgs(/*sequenceNum=*/1, /*eventTime=*/downTime, /*readTime=*/2,
                                /*deviceId=*/3, AINPUT_SOURCE_ANY, ADISPLAY_ID_DEFAULT,
                                /*policyFlags=*/4, AMOTION_EVENT_ACTION_DOWN, /*actionButton=*/0,
                                /*flags=*/0, AMETA_NONE, /*buttonState=*/0,
                                MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE,
                                /*pointerCount=*/1, &properties, &coords, /*xPrecision=*/0,
                                /*yPrecision=*/0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                AMOTION_EVENT_INVALID_CURSOR_POSITION, downTime,
                                /*videoFrames=*/{});
    return motionArgs;
}

class InputProcessorTest : public testing::Test {
protected:
    TestInputListener mTestListener;
    std::unique_ptr<InputProcessorInterface> mProcessor;

    void SetUp() override { mProcessor = std::make_unique<InputProcessor>(mTestListener); }
};

/**
 * Create a basic configuration change and send it to input processor.
 * Expect that the event is received by the next input stage, unmodified.
 */
TEST_F(InputProcessorTest, SendToNextStage_NotifyConfigurationChangedArgs) {
    // Create a basic configuration change and send to processor
    NotifyConfigurationChangedArgs args(/*sequenceNum=*/1, /*eventTime=*/2);

    mProcessor->notifyConfigurationChanged(args);
    NotifyConfigurationChangedArgs outArgs;
    ASSERT_NO_FATAL_FAILURE(mTestListener.assertNotifyConfigurationChangedWasCalled(&outArgs));
    ASSERT_EQ(args, outArgs);
}

TEST_F(InputProcessorTest, SendToNextStage_NotifyKeyArgs) {
    // Create a basic key event and send to processor
    NotifyKeyArgs args(/*sequenceNum=*/1, /*eventTime=*/2, /*readTime=*/21, /*deviceId=*/3,
                       AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_DEFAULT, /*policyFlags=*/0,
                       AKEY_EVENT_ACTION_DOWN, /*flags=*/4, AKEYCODE_HOME, /*scanCode=*/5,
                       AMETA_NONE, /*downTime=*/6);

    mProcessor->notifyKey(args);
    ASSERT_NO_FATAL_FAILURE(mTestListener.assertNotifyKeyWasCalled(testing::Eq(args)));
}

/**
 * Create a basic motion event and send it to input processor.
 * Expect that the event is received by the next input stage, unmodified.
 */
TEST_F(InputProcessorTest, SendToNextStage_NotifyMotionArgs) {
    NotifyMotionArgs motionArgs = generateBasicMotionArgs();
    mProcessor->notifyMotion(motionArgs);
    ASSERT_NO_FATAL_FAILURE(mTestListener.assertNotifyMotionWasCalled(testing::Eq(motionArgs)));
}

/**
 * Create a basic switch event and send it to input processor.
 * Expect that the event is received by the next input stage, unmodified.
 */
TEST_F(InputProcessorTest, SendToNextStage_NotifySwitchArgs) {
    NotifySwitchArgs args(/*sequenceNum=*/1, /*eventTime=*/2, /*policyFlags=*/3,
                          /*switchValues=*/4, /*switchMask=*/5);

    mProcessor->notifySwitch(args);
    NotifySwitchArgs outArgs;
    ASSERT_NO_FATAL_FAILURE(mTestListener.assertNotifySwitchWasCalled(&outArgs));
    ASSERT_EQ(args, outArgs);
}

/**
 * Create a basic device reset event and send it to input processor.
 * Expect that the event is received by the next input stage, unmodified.
 */
TEST_F(InputProcessorTest, SendToNextStage_NotifyDeviceResetArgs) {
    NotifyDeviceResetArgs args(/*sequenceNum=*/1, /*eventTime=*/2, /*deviceId=*/3);

    mProcessor->notifyDeviceReset(args);
    NotifyDeviceResetArgs outArgs;
    ASSERT_NO_FATAL_FAILURE(mTestListener.assertNotifyDeviceResetWasCalled(&outArgs));
    ASSERT_EQ(args, outArgs);
}

TEST_F(InputProcessorTest, SetMotionClassifier_Enabled) {
    mProcessor->setMotionClassifierEnabled(true);
}

TEST_F(InputProcessorTest, SetMotionClassifier_Disabled) {
    mProcessor->setMotionClassifierEnabled(false);
}

/**
 * Try to break it by calling setMotionClassifierEnabled multiple times.
 */
TEST_F(InputProcessorTest, SetMotionClassifier_Multiple) {
    mProcessor->setMotionClassifierEnabled(true);
    mProcessor->setMotionClassifierEnabled(true);
    mProcessor->setMotionClassifierEnabled(true);
    mProcessor->setMotionClassifierEnabled(false);
    mProcessor->setMotionClassifierEnabled(false);
    mProcessor->setMotionClassifierEnabled(true);
    mProcessor->setMotionClassifierEnabled(true);
    mProcessor->setMotionClassifierEnabled(true);
}

/**
 * A minimal implementation of IInputProcessor.
 */
class TestHal : public aidl::android::hardware::input::processor::BnInputProcessor {
    ::ndk::ScopedAStatus classify(
            const ::aidl::android::hardware::input::common::MotionEvent& in_event,
            ::aidl::android::hardware::input::common::Classification* _aidl_return) override {
        *_aidl_return = Classification::NONE;
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus reset() override { return ndk::ScopedAStatus::ok(); }
    ::ndk::ScopedAStatus resetDevice(int32_t in_deviceId) override {
        return ndk::ScopedAStatus::ok();
    }
};

// --- MotionClassifierTest ---

class MotionClassifierTest : public testing::Test {
protected:
    std::unique_ptr<MotionClassifierInterface> mMotionClassifier;

    void SetUp() override {
        std::shared_ptr<IInputProcessor> service = ndk::SharedRefBase::make<TestHal>();
        mMotionClassifier = MotionClassifier::create(std::move(service));
    }
};

/**
 * Since MotionClassifier creates a new thread to communicate with HAL,
 * it's not really expected to ever exit. However, for testing purposes,
 * we need to ensure that it is able to exit cleanly.
 * If the thread is not properly cleaned up, it will generate SIGABRT.
 * The logic for exiting the thread and cleaning up the resources is inside
 * the destructor. Here, we just make sure the destructor does not crash.
 */
TEST_F(MotionClassifierTest, Destructor_DoesNotCrash) {
    mMotionClassifier = nullptr;
}

/**
 * Make sure MotionClassifier can handle events that don't have any
 * video frames.
 */
TEST_F(MotionClassifierTest, Classify_NoVideoFrames) {
    NotifyMotionArgs motionArgs = generateBasicMotionArgs();

    // We are not checking the return value, because we can't be making assumptions
    // about the HAL operation, since it will be highly hardware-dependent
    ASSERT_NO_FATAL_FAILURE(mMotionClassifier->classify(motionArgs));
}

/**
 * Make sure nothing crashes when a videoFrame is sent.
 */
TEST_F(MotionClassifierTest, Classify_OneVideoFrame) {
    NotifyMotionArgs motionArgs = generateBasicMotionArgs();

    std::vector<int16_t> videoData = {1, 2, 3, 4};
    timeval timestamp = {1, 1};
    TouchVideoFrame frame(2, 2, std::move(videoData), timestamp);
    motionArgs.videoFrames = {frame};

    // We are not checking the return value, because we can't be making assumptions
    // about the HAL operation, since it will be highly hardware-dependent
    ASSERT_NO_FATAL_FAILURE(mMotionClassifier->classify(motionArgs));
}

/**
 * Make sure nothing crashes when 2 videoFrames are sent.
 */
TEST_F(MotionClassifierTest, Classify_TwoVideoFrames) {
    NotifyMotionArgs motionArgs = generateBasicMotionArgs();

    std::vector<int16_t> videoData1 = {1, 2, 3, 4};
    timeval timestamp1 = {1, 1};
    TouchVideoFrame frame1(2, 2, std::move(videoData1), timestamp1);

    std::vector<int16_t> videoData2 = {6, 6, 6, 6};
    timeval timestamp2 = {1, 2};
    TouchVideoFrame frame2(2, 2, std::move(videoData2), timestamp2);

    motionArgs.videoFrames = {frame1, frame2};

    // We are not checking the return value, because we can't be making assumptions
    // about the HAL operation, since it will be highly hardware-dependent
    ASSERT_NO_FATAL_FAILURE(mMotionClassifier->classify(motionArgs));
}

/**
 * Make sure MotionClassifier does not crash when it is reset.
 */
TEST_F(MotionClassifierTest, Reset_DoesNotCrash) {
    ASSERT_NO_FATAL_FAILURE(mMotionClassifier->reset());
}

/**
 * Make sure MotionClassifier does not crash when a device is reset.
 */
TEST_F(MotionClassifierTest, DeviceReset_DoesNotCrash) {
    NotifyDeviceResetArgs args(/*sequenceNum=*/1, /*eventTime=*/2, /*deviceId=*/3);
    ASSERT_NO_FATAL_FAILURE(mMotionClassifier->reset(args));
}

} // namespace android
