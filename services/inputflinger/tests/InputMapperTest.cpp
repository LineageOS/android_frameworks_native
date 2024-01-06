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

#include "InputMapperTest.h"

#include <InputReaderBase.h>
#include <gtest/gtest.h>
#include <ui/Rotation.h>
#include <utils/Timers.h>

#include "NotifyArgs.h"

namespace android {

using testing::_;
using testing::Return;

void InputMapperUnitTest::SetUpWithBus(int bus) {
    mFakePointerController = std::make_shared<FakePointerController>();
    mFakePointerController->setBounds(0, 0, 800 - 1, 480 - 1);
    mFakePointerController->setPosition(INITIAL_CURSOR_X, INITIAL_CURSOR_Y);
    mFakePolicy = sp<FakeInputReaderPolicy>::make();

    EXPECT_CALL(mMockInputReaderContext, getPointerController(DEVICE_ID))
            .WillRepeatedly(Return(mFakePointerController));

    EXPECT_CALL(mMockInputReaderContext, getPolicy()).WillRepeatedly(Return(mFakePolicy.get()));

    EXPECT_CALL(mMockInputReaderContext, getEventHub()).WillRepeatedly(Return(&mMockEventHub));

    mIdentifier.name = "device";
    mIdentifier.location = "USB1";
    mIdentifier.bus = bus;
    EXPECT_CALL(mMockEventHub, getDeviceIdentifier(EVENTHUB_ID))
            .WillRepeatedly(Return(mIdentifier));
    EXPECT_CALL(mMockEventHub, getConfiguration(EVENTHUB_ID)).WillRepeatedly([&](int32_t) {
        return mPropertyMap;
    });
}

void InputMapperUnitTest::createDevice() {
    mDevice = std::make_unique<InputDevice>(&mMockInputReaderContext, DEVICE_ID,
                                            /*generation=*/2, mIdentifier);
    mDevice->addEmptyEventHubDevice(EVENTHUB_ID);
    mDeviceContext = std::make_unique<InputDeviceContext>(*mDevice, EVENTHUB_ID);
    std::list<NotifyArgs> args =
            mDevice->configure(systemTime(), mReaderConfiguration, /*changes=*/{});
    ASSERT_THAT(args, testing::ElementsAre(testing::VariantWith<NotifyDeviceResetArgs>(_)));
}

void InputMapperUnitTest::setupAxis(int axis, bool valid, int32_t min, int32_t max,
                                    int32_t resolution) {
    EXPECT_CALL(mMockEventHub, getAbsoluteAxisInfo(EVENTHUB_ID, axis, _))
            .WillRepeatedly([=](int32_t, int32_t, RawAbsoluteAxisInfo* outAxisInfo) {
                outAxisInfo->valid = valid;
                outAxisInfo->minValue = min;
                outAxisInfo->maxValue = max;
                outAxisInfo->flat = 0;
                outAxisInfo->fuzz = 0;
                outAxisInfo->resolution = resolution;
                return valid ? OK : -1;
            });
}

void InputMapperUnitTest::expectScanCodes(bool present, std::set<int> scanCodes) {
    for (const auto& scanCode : scanCodes) {
        EXPECT_CALL(mMockEventHub, hasScanCode(EVENTHUB_ID, scanCode))
                .WillRepeatedly(testing::Return(present));
    }
}

void InputMapperUnitTest::setScanCodeState(KeyState state, std::set<int> scanCodes) {
    for (const auto& scanCode : scanCodes) {
        EXPECT_CALL(mMockEventHub, getScanCodeState(EVENTHUB_ID, scanCode))
                .WillRepeatedly(testing::Return(static_cast<int>(state)));
    }
}

void InputMapperUnitTest::setKeyCodeState(KeyState state, std::set<int> keyCodes) {
    for (const auto& keyCode : keyCodes) {
        EXPECT_CALL(mMockEventHub, getKeyCodeState(EVENTHUB_ID, keyCode))
                .WillRepeatedly(testing::Return(static_cast<int>(state)));
    }
}

std::list<NotifyArgs> InputMapperUnitTest::process(int32_t type, int32_t code, int32_t value) {
    nsecs_t when = systemTime(SYSTEM_TIME_MONOTONIC);
    return process(when, type, code, value);
}

std::list<NotifyArgs> InputMapperUnitTest::process(nsecs_t when, int32_t type, int32_t code,
                                                   int32_t value) {
    RawEvent event;
    event.when = when;
    event.readTime = when;
    event.deviceId = mMapper->getDeviceContext().getEventHubId();
    event.type = type;
    event.code = code;
    event.value = value;
    return mMapper->process(&event);
}

const char* InputMapperTest::DEVICE_NAME = "device";
const char* InputMapperTest::DEVICE_LOCATION = "USB1";
const ftl::Flags<InputDeviceClass> InputMapperTest::DEVICE_CLASSES =
        ftl::Flags<InputDeviceClass>(0); // not needed for current tests

void InputMapperTest::SetUp(ftl::Flags<InputDeviceClass> classes, int bus) {
    mFakeEventHub = std::make_unique<FakeEventHub>();
    mFakePolicy = sp<FakeInputReaderPolicy>::make();
    mFakeListener = std::make_unique<TestInputListener>();
    mReader = std::make_unique<InstrumentedInputReader>(mFakeEventHub, mFakePolicy, *mFakeListener);
    mDevice = newDevice(DEVICE_ID, DEVICE_NAME, DEVICE_LOCATION, EVENTHUB_ID, classes, bus);
    // Consume the device reset notification generated when adding a new device.
    mFakeListener->assertNotifyDeviceResetWasCalled();
}

void InputMapperTest::SetUp() {
    SetUp(DEVICE_CLASSES);
}

void InputMapperTest::TearDown() {
    mFakeListener.reset();
    mFakePolicy.clear();
}

void InputMapperTest::addConfigurationProperty(const char* key, const char* value) {
    mFakeEventHub->addConfigurationProperty(EVENTHUB_ID, key, value);
}

std::list<NotifyArgs> InputMapperTest::configureDevice(ConfigurationChanges changes) {
    using namespace ftl::flag_operators;
    if (!changes.any() ||
        (changes.any(InputReaderConfiguration::Change::DISPLAY_INFO |
                     InputReaderConfiguration::Change::POINTER_CAPTURE |
                     InputReaderConfiguration::Change::DEVICE_TYPE))) {
        mReader->requestRefreshConfiguration(changes);
        mReader->loopOnce();
    }
    std::list<NotifyArgs> out =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(), changes);
    // Loop the reader to flush the input listener queue.
    for (const NotifyArgs& args : out) {
        mFakeListener->notify(args);
    }
    mReader->loopOnce();
    return out;
}

std::shared_ptr<InputDevice> InputMapperTest::newDevice(int32_t deviceId, const std::string& name,
                                                        const std::string& location,
                                                        int32_t eventHubId,
                                                        ftl::Flags<InputDeviceClass> classes,
                                                        int bus) {
    InputDeviceIdentifier identifier;
    identifier.name = name;
    identifier.location = location;
    identifier.bus = bus;
    std::shared_ptr<InputDevice> device =
            std::make_shared<InputDevice>(mReader->getContext(), deviceId, DEVICE_GENERATION,
                                          identifier);
    mReader->pushNextDevice(device);
    mFakeEventHub->addDevice(eventHubId, name, classes, bus);
    mReader->loopOnce();
    return device;
}

void InputMapperTest::setDisplayInfoAndReconfigure(int32_t displayId, int32_t width, int32_t height,
                                                   ui::Rotation orientation,
                                                   const std::string& uniqueId,
                                                   std::optional<uint8_t> physicalPort,
                                                   ViewportType viewportType) {
    mFakePolicy->addDisplayViewport(displayId, width, height, orientation, /* isActive= */ true,
                                    uniqueId, physicalPort, viewportType);
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);
}

void InputMapperTest::clearViewports() {
    mFakePolicy->clearViewports();
}

std::list<NotifyArgs> InputMapperTest::process(InputMapper& mapper, nsecs_t when, nsecs_t readTime,
                                               int32_t type, int32_t code, int32_t value) {
    RawEvent event;
    event.when = when;
    event.readTime = readTime;
    event.deviceId = mapper.getDeviceContext().getEventHubId();
    event.type = type;
    event.code = code;
    event.value = value;
    std::list<NotifyArgs> processArgList = mapper.process(&event);
    for (const NotifyArgs& args : processArgList) {
        mFakeListener->notify(args);
    }
    // Loop the reader to flush the input listener queue.
    mReader->loopOnce();
    return processArgList;
}

void InputMapperTest::resetMapper(InputMapper& mapper, nsecs_t when) {
    const auto resetArgs = mapper.reset(when);
    for (const auto args : resetArgs) {
        mFakeListener->notify(args);
    }
    // Loop the reader to flush the input listener queue.
    mReader->loopOnce();
}

std::list<NotifyArgs> InputMapperTest::handleTimeout(InputMapper& mapper, nsecs_t when) {
    std::list<NotifyArgs> generatedArgs = mapper.timeoutExpired(when);
    for (const NotifyArgs& args : generatedArgs) {
        mFakeListener->notify(args);
    }
    // Loop the reader to flush the input listener queue.
    mReader->loopOnce();
    return generatedArgs;
}

void assertMotionRange(const InputDeviceInfo& info, int32_t axis, uint32_t source, float min,
                       float max, float flat, float fuzz) {
    const InputDeviceInfo::MotionRange* range = info.getMotionRange(axis, source);
    ASSERT_TRUE(range != nullptr) << "Axis: " << axis << " Source: " << source;
    ASSERT_EQ(axis, range->axis) << "Axis: " << axis << " Source: " << source;
    ASSERT_EQ(source, range->source) << "Axis: " << axis << " Source: " << source;
    ASSERT_NEAR(min, range->min, EPSILON) << "Axis: " << axis << " Source: " << source;
    ASSERT_NEAR(max, range->max, EPSILON) << "Axis: " << axis << " Source: " << source;
    ASSERT_NEAR(flat, range->flat, EPSILON) << "Axis: " << axis << " Source: " << source;
    ASSERT_NEAR(fuzz, range->fuzz, EPSILON) << "Axis: " << axis << " Source: " << source;
}

void assertPointerCoords(const PointerCoords& coords, float x, float y, float pressure, float size,
                         float touchMajor, float touchMinor, float toolMajor, float toolMinor,
                         float orientation, float distance, float scaledAxisEpsilon) {
    ASSERT_NEAR(x, coords.getAxisValue(AMOTION_EVENT_AXIS_X), scaledAxisEpsilon);
    ASSERT_NEAR(y, coords.getAxisValue(AMOTION_EVENT_AXIS_Y), scaledAxisEpsilon);
    ASSERT_NEAR(pressure, coords.getAxisValue(AMOTION_EVENT_AXIS_PRESSURE), EPSILON);
    ASSERT_NEAR(size, coords.getAxisValue(AMOTION_EVENT_AXIS_SIZE), EPSILON);
    ASSERT_NEAR(touchMajor, coords.getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR), scaledAxisEpsilon);
    ASSERT_NEAR(touchMinor, coords.getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR), scaledAxisEpsilon);
    ASSERT_NEAR(toolMajor, coords.getAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR), scaledAxisEpsilon);
    ASSERT_NEAR(toolMinor, coords.getAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR), scaledAxisEpsilon);
    ASSERT_NEAR(orientation, coords.getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION), EPSILON);
    ASSERT_NEAR(distance, coords.getAxisValue(AMOTION_EVENT_AXIS_DISTANCE), EPSILON);
}

} // namespace android
