/*
 * Copyright 2023 The Android Open Source Project
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

#include "../PointerChoreographer.h"

#include <gtest/gtest.h>
#include <vector>

#include "FakePointerController.h"
#include "NotifyArgsBuilders.h"
#include "TestEventMatchers.h"
#include "TestInputListener.h"

namespace android {

using ControllerType = PointerControllerInterface::ControllerType;

// Helpers to std::visit with lambdas.
template <typename... V>
struct Visitor : V... {};
template <typename... V>
Visitor(V...) -> Visitor<V...>;

constexpr int32_t DEVICE_ID = 3;
constexpr int32_t DISPLAY_ID = 5;
constexpr int32_t ANOTHER_DISPLAY_ID = 10;

const auto MOUSE_POINTER = PointerBuilder(/*id=*/0, ToolType::MOUSE)
                                   .axis(AMOTION_EVENT_AXIS_RELATIVE_X, 10)
                                   .axis(AMOTION_EVENT_AXIS_RELATIVE_Y, 20);

static InputDeviceInfo generateTestDeviceInfo(int32_t deviceId, uint32_t source,
                                              int32_t associatedDisplayId) {
    InputDeviceIdentifier identifier;

    auto info = InputDeviceInfo();
    info.initialize(deviceId, /*generation=*/1, /*controllerNumber=*/1, identifier, "alias",
                    /*isExternal=*/false, /*hasMic=*/false, associatedDisplayId);
    info.addSource(source);
    return info;
}

static std::vector<DisplayViewport> createViewports(std::vector<int32_t> displayIds) {
    std::vector<DisplayViewport> viewports;
    for (auto displayId : displayIds) {
        DisplayViewport viewport;
        viewport.displayId = displayId;
        viewports.push_back(viewport);
    }
    return viewports;
}

// --- PointerChoreographerTest ---

class PointerChoreographerTest : public testing::Test, public PointerChoreographerPolicyInterface {
protected:
    TestInputListener mTestListener;
    PointerChoreographer mChoreographer{mTestListener, *this};
    std::list<std::weak_ptr<FakePointerController>> mPointerControllers{};

    std::shared_ptr<PointerControllerInterface> createPointerController(ControllerType type) {
        mLastCreatedControllerType = type;
        std::shared_ptr<FakePointerController> pc = std::make_shared<FakePointerController>();
        mPointerControllers.emplace_back(pc);
        return pc;
    }

    void notifyPointerDisplayIdChanged(int32_t displayId, const FloatPoint& position) {
        mPointerDisplayIdNotified = displayId;
    }

    void assertPointerControllerCreated(ControllerType type) {
        ASSERT_EQ(type, mLastCreatedControllerType);
        mLastCreatedControllerType.reset();
    }

    void assertPointerControllerNotCreated() {
        ASSERT_EQ(std::nullopt, mLastCreatedControllerType);
    }

    void assertPointerControllerCount(size_t count) {
        // At first, erase ones which aren't used anymore.
        auto it = mPointerControllers.begin();
        while (it != mPointerControllers.end()) {
            auto pc = it->lock();
            if (!pc) {
                it = mPointerControllers.erase(it);
                continue;
            }
            it++;
        }

        ASSERT_EQ(count, mPointerControllers.size());
    }

    void assertPointerDisplayIdNotified(int32_t displayId) {
        ASSERT_EQ(displayId, mPointerDisplayIdNotified);
        mPointerDisplayIdNotified.reset();
    }

    void assertPointerDisplayIdNotNotified() { ASSERT_EQ(std::nullopt, mPointerDisplayIdNotified); }

private:
    std::optional<ControllerType> mLastCreatedControllerType;
    std::optional<int32_t> mPointerDisplayIdNotified;
};

TEST_F(PointerChoreographerTest, ForwardsArgsToInnerListener) {
    const std::vector<NotifyArgs> allArgs{NotifyInputDevicesChangedArgs{},
                                          NotifyConfigurationChangedArgs{},
                                          NotifyKeyArgs{},
                                          NotifyMotionArgs{},
                                          NotifySensorArgs{},
                                          NotifySwitchArgs{},
                                          NotifyDeviceResetArgs{},
                                          NotifyPointerCaptureChangedArgs{},
                                          NotifyVibratorStateArgs{}};

    for (auto notifyArgs : allArgs) {
        mChoreographer.notify(notifyArgs);
        EXPECT_NO_FATAL_FAILURE(
                std::visit(Visitor{
                                   [&](const NotifyInputDevicesChangedArgs& args) {
                                       mTestListener.assertNotifyInputDevicesChangedWasCalled();
                                   },
                                   [&](const NotifyConfigurationChangedArgs& args) {
                                       mTestListener.assertNotifyConfigurationChangedWasCalled();
                                   },
                                   [&](const NotifyKeyArgs& args) {
                                       mTestListener.assertNotifyKeyWasCalled();
                                   },
                                   [&](const NotifyMotionArgs& args) {
                                       mTestListener.assertNotifyMotionWasCalled();
                                   },
                                   [&](const NotifySensorArgs& args) {
                                       mTestListener.assertNotifySensorWasCalled();
                                   },
                                   [&](const NotifySwitchArgs& args) {
                                       mTestListener.assertNotifySwitchWasCalled();
                                   },
                                   [&](const NotifyDeviceResetArgs& args) {
                                       mTestListener.assertNotifyDeviceResetWasCalled();
                                   },
                                   [&](const NotifyPointerCaptureChangedArgs& args) {
                                       mTestListener.assertNotifyCaptureWasCalled();
                                   },
                                   [&](const NotifyVibratorStateArgs& args) {
                                       mTestListener.assertNotifyVibratorStateWasCalled();
                                   },
                           },
                           notifyArgs));
    }
}

TEST_F(PointerChoreographerTest, WhenMouseIsJustAddedDoesNotCreatePointerController) {
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    assertPointerControllerNotCreated();
    assertPointerControllerCount(size_t(0));
}

TEST_F(PointerChoreographerTest, WhenMouseEventOccursCreatesPointerController) {
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerControllerCount(size_t(1));
}

TEST_F(PointerChoreographerTest, WhenMouseIsRemovedRemovesPointerController) {
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerControllerCount(size_t(1));

    // Remove the mouse.
    mChoreographer.notifyInputDevicesChanged({/*id=*/1, {}});
    assertPointerControllerCount(size_t(0));
}

TEST_F(PointerChoreographerTest, WhenKeyboardIsAddedDoesNotCreatePointerController) {
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_NONE)}});
    assertPointerControllerNotCreated();
}

TEST_F(PointerChoreographerTest, SetsViewportForAssociatedMouse) {
    // Just adding a viewport should not create a PointerController.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    assertPointerControllerCount(size_t(0));
    assertPointerControllerNotCreated();

    // After the mouse emits event, PointerController will be created and viewport will be set.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, DISPLAY_ID)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    assertPointerControllerCount(size_t(1));
    assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, mPointerControllers.back().lock()->getDisplayId());
}

TEST_F(PointerChoreographerTest, WhenViewportSetLaterSetsViewportForAssociatedMouse) {
    // Without viewport information, PointerController will be created by a mouse event
    // but viewport won't be set.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, DISPLAY_ID)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    assertPointerControllerCount(size_t(1));
    assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(ADISPLAY_ID_NONE, mPointerControllers.back().lock()->getDisplayId());

    // After Choreographer gets viewport, PointerController should also have viewport.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    ASSERT_EQ(DISPLAY_ID, mPointerControllers.back().lock()->getDisplayId());
}

TEST_F(PointerChoreographerTest, SetsDefaultMouseViewportForPointerController) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);

    // For a mouse event without a target display, default viewport should be set for
    // the PointerController.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    assertPointerControllerCount(size_t(1));
    assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, mPointerControllers.back().lock()->getDisplayId());
}

TEST_F(PointerChoreographerTest,
       WhenDefaultMouseDisplayChangesSetsDefaultMouseViewportForPointerController) {
    // Set one display as a default mouse display and emit mouse event to create PointerController.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID, ANOTHER_DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    assertPointerControllerCount(size_t(1));
    assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, mPointerControllers.back().lock()->getDisplayId());

    // Change default mouse display. Existing PointerController should be removed.
    mChoreographer.setDefaultMouseDisplayId(ANOTHER_DISPLAY_ID);
    assertPointerControllerNotCreated();
    assertPointerControllerCount(size_t(0));

    // New PointerController for the new default display will be created by the motion event.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerControllerCount(size_t(1));
    ASSERT_EQ(ANOTHER_DISPLAY_ID, mPointerControllers.back().lock()->getDisplayId());
}

TEST_F(PointerChoreographerTest, CallsNotifyPointerDisplayIdChanged) {
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());

    assertPointerDisplayIdNotified(DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, WhenViewportIsSetLaterCallsNotifyPointerDisplayIdChanged) {
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    assertPointerDisplayIdNotNotified();

    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    assertPointerDisplayIdNotified(DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, WhenMouseIsRemovedCallsNotifyPointerDisplayIdChanged) {
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    assertPointerDisplayIdNotified(DISPLAY_ID);
    assertPointerControllerCount(size_t(1));

    mChoreographer.notifyInputDevicesChanged({/*id=*/1, {}});
    assertPointerDisplayIdNotified(ADISPLAY_ID_NONE);
    assertPointerControllerCount(size_t(0));
}

TEST_F(PointerChoreographerTest, WhenDefaultMouseDisplayChangesCallsNotifyPointerDisplayIdChanged) {
    // Add two viewports.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID, ANOTHER_DISPLAY_ID}));

    // Set one viewport as a default mouse display ID.
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    assertPointerDisplayIdNotified(DISPLAY_ID);

    // Set another viewport as a default mouse display ID. ADISPLAY_ID_NONE will be notified
    // before a mouse event.
    mChoreographer.setDefaultMouseDisplayId(ANOTHER_DISPLAY_ID);
    assertPointerDisplayIdNotified(ADISPLAY_ID_NONE);

    // After a mouse event, pointer display ID will be notified with new default mouse display.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    assertPointerDisplayIdNotified(ANOTHER_DISPLAY_ID);
}

} // namespace android
