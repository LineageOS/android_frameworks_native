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
using testing::AllOf;

namespace {

// Helpers to std::visit with lambdas.
template <typename... V>
struct Visitor : V... {};
template <typename... V>
Visitor(V...) -> Visitor<V...>;

constexpr int32_t DEVICE_ID = 3;
constexpr int32_t SECOND_DEVICE_ID = DEVICE_ID + 1;
constexpr int32_t DISPLAY_ID = 5;
constexpr int32_t ANOTHER_DISPLAY_ID = 10;
constexpr int32_t DISPLAY_WIDTH = 480;
constexpr int32_t DISPLAY_HEIGHT = 800;

const auto MOUSE_POINTER = PointerBuilder(/*id=*/0, ToolType::MOUSE)
                                   .axis(AMOTION_EVENT_AXIS_RELATIVE_X, 10)
                                   .axis(AMOTION_EVENT_AXIS_RELATIVE_Y, 20);
const auto FIRST_TOUCH_POINTER = PointerBuilder(/*id=*/0, ToolType::FINGER).x(100).y(200);
const auto SECOND_TOUCH_POINTER = PointerBuilder(/*id=*/1, ToolType::FINGER).x(200).y(300);
const auto STYLUS_POINTER = PointerBuilder(/*id=*/0, ToolType::STYLUS).x(100).y(200);

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
        viewport.logicalRight = DISPLAY_WIDTH;
        viewport.logicalBottom = DISPLAY_HEIGHT;
        viewports.push_back(viewport);
    }
    return viewports;
}

} // namespace

// --- PointerChoreographerTest ---

class PointerChoreographerTest : public testing::Test, public PointerChoreographerPolicyInterface {
protected:
    TestInputListener mTestListener;
    PointerChoreographer mChoreographer{mTestListener, *this};

    std::shared_ptr<FakePointerController> assertPointerControllerCreated(
            ControllerType expectedType) {
        EXPECT_TRUE(mLastCreatedController) << "No PointerController was created";
        auto [type, controller] = std::move(*mLastCreatedController);
        EXPECT_EQ(expectedType, type);
        mLastCreatedController.reset();
        return controller;
    }

    void assertPointerControllerNotCreated() { ASSERT_EQ(std::nullopt, mLastCreatedController); }

    void assertPointerControllerRemoved(const std::shared_ptr<FakePointerController>& pc) {
        // Ensure that the code under test is not holding onto this PointerController.
        // While the policy initially creates the PointerControllers, the PointerChoreographer is
        // expected to manage their lifecycles. Although we may not want to strictly enforce how
        // the object is managed, in this case, we need to have a way of ensuring that the
        // corresponding graphical resources have been released by the PointerController, and the
        // simplest way of checking for that is to just make sure that the PointerControllers
        // themselves are released by Choreographer when no longer in use. This check is ensuring
        // that the reference retained by the test is the last one.
        ASSERT_EQ(1, pc.use_count()) << "Expected PointerChoreographer to release all references "
                                        "to this PointerController";
    }

    void assertPointerDisplayIdNotified(int32_t displayId) {
        ASSERT_EQ(displayId, mPointerDisplayIdNotified);
        mPointerDisplayIdNotified.reset();
    }

    void assertPointerDisplayIdNotNotified() { ASSERT_EQ(std::nullopt, mPointerDisplayIdNotified); }

private:
    std::optional<std::pair<ControllerType, std::shared_ptr<FakePointerController>>>
            mLastCreatedController;
    std::optional<int32_t> mPointerDisplayIdNotified;

    std::shared_ptr<PointerControllerInterface> createPointerController(
            ControllerType type) override {
        EXPECT_FALSE(mLastCreatedController.has_value())
                << "More than one PointerController created at a time";
        std::shared_ptr<FakePointerController> pc = std::make_shared<FakePointerController>();
        EXPECT_FALSE(pc->isPointerShown());
        mLastCreatedController = {type, pc};
        return pc;
    }

    void notifyPointerDisplayIdChanged(int32_t displayId, const FloatPoint& position) override {
        mPointerDisplayIdNotified = displayId;
    }
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
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);

    // Remove the mouse.
    mChoreographer.notifyInputDevicesChanged({/*id=*/1, {}});
    assertPointerControllerRemoved(pc);
}

TEST_F(PointerChoreographerTest, WhenKeyboardIsAddedDoesNotCreatePointerController) {
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_NONE)}});
    assertPointerControllerNotCreated();
}

TEST_F(PointerChoreographerTest, SetsViewportForAssociatedMouse) {
    // Just adding a viewport or device should not create a PointerController.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, DISPLAY_ID)}});
    assertPointerControllerNotCreated();

    // After the mouse emits event, PointerController will be created and viewport will be set.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());
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
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(ADISPLAY_ID_NONE, pc->getDisplayId());

    // After Choreographer gets viewport, PointerController should also have viewport.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());
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
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());
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
    auto firstDisplayPc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, firstDisplayPc->getDisplayId());

    // Change default mouse display. Existing PointerController should be removed.
    mChoreographer.setDefaultMouseDisplayId(ANOTHER_DISPLAY_ID);
    assertPointerControllerRemoved(firstDisplayPc);
    assertPointerControllerNotCreated();

    // New PointerController for the new default display will be created by the motion event.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    auto secondDisplayPc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(ANOTHER_DISPLAY_ID, secondDisplayPc->getDisplayId());
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
    assertPointerControllerCreated(ControllerType::MOUSE);

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
    assertPointerControllerCreated(ControllerType::MOUSE);
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
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerDisplayIdNotified(DISPLAY_ID);

    mChoreographer.notifyInputDevicesChanged({/*id=*/1, {}});
    assertPointerDisplayIdNotified(ADISPLAY_ID_NONE);
    assertPointerControllerRemoved(pc);
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
    auto firstDisplayPc = assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerDisplayIdNotified(DISPLAY_ID);

    // Set another viewport as a default mouse display ID. ADISPLAY_ID_NONE will be notified
    // before a mouse event.
    mChoreographer.setDefaultMouseDisplayId(ANOTHER_DISPLAY_ID);
    assertPointerDisplayIdNotified(ADISPLAY_ID_NONE);
    assertPointerControllerRemoved(firstDisplayPc);

    // After a mouse event, pointer display ID will be notified with new default mouse display.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerDisplayIdNotified(ANOTHER_DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, MouseMovesPointerAndReturnsNewArgs) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    mTestListener.assertNotifyMotionWasCalled(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE));
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());

    // Set bounds and initial position of the PointerController.
    pc->setPosition(100, 200);

    // Make NotifyMotionArgs and notify Choreographer.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());

    // Check that the PointerController updated the position and the pointer is shown.
    pc->assertPosition(110, 220);
    ASSERT_TRUE(pc->isPointerShown());

    // Check that x-y cooridnates, displayId and cursor position are correctly updated.
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithCoords(110, 220), WithDisplayId(DISPLAY_ID), WithCursorPosition(110, 220)));
}

TEST_F(PointerChoreographerTest,
       AssociatedMouseMovesPointerOnAssociatedDisplayAndDoesNotMovePointerOnDefaultDisplay) {
    // Add two displays and set one to default.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID, ANOTHER_DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);

    // Add two devices, one unassociated and the other associated with non-default mouse display.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE),
              generateTestDeviceInfo(SECOND_DEVICE_ID, AINPUT_SOURCE_MOUSE, ANOTHER_DISPLAY_ID)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    mTestListener.assertNotifyMotionWasCalled(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE));
    auto unassociatedMousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, unassociatedMousePc->getDisplayId());

    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(SECOND_DEVICE_ID)
                    .displayId(ANOTHER_DISPLAY_ID)
                    .build());
    mTestListener.assertNotifyMotionWasCalled(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE));
    auto associatedMousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(ANOTHER_DISPLAY_ID, associatedMousePc->getDisplayId());

    // Set bounds and initial position for PointerControllers.
    unassociatedMousePc->setPosition(100, 200);
    associatedMousePc->setPosition(300, 400);

    // Make NotifyMotionArgs from the associated mouse and notify Choreographer.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(SECOND_DEVICE_ID)
                    .displayId(ANOTHER_DISPLAY_ID)
                    .build());

    // Check the status of the PointerControllers.
    unassociatedMousePc->assertPosition(100, 200);
    ASSERT_EQ(DISPLAY_ID, unassociatedMousePc->getDisplayId());
    associatedMousePc->assertPosition(310, 420);
    ASSERT_EQ(ANOTHER_DISPLAY_ID, associatedMousePc->getDisplayId());
    ASSERT_TRUE(associatedMousePc->isPointerShown());

    // Check that x-y cooridnates, displayId and cursor position are correctly updated.
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithCoords(310, 420), WithDeviceId(SECOND_DEVICE_ID),
                  WithDisplayId(ANOTHER_DISPLAY_ID), WithCursorPosition(310, 420)));
}

TEST_F(PointerChoreographerTest, DoesNotMovePointerForMouseRelativeSource) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    mTestListener.assertNotifyMotionWasCalled(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE));
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());

    // Set bounds and initial position of the PointerController.
    pc->setPosition(100, 200);

    // Assume that pointer capture is enabled.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/1,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE_RELATIVE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyPointerCaptureChanged(
            NotifyPointerCaptureChangedArgs(/*id=*/2, systemTime(SYSTEM_TIME_MONOTONIC),
                                            PointerCaptureRequest(/*enable=*/true, /*seq=*/0)));

    // Notify motion as if pointer capture is enabled.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_MOUSE_RELATIVE)
                    .pointer(PointerBuilder(/*id=*/0, ToolType::MOUSE)
                                     .x(10)
                                     .y(20)
                                     .axis(AMOTION_EVENT_AXIS_RELATIVE_X, 10)
                                     .axis(AMOTION_EVENT_AXIS_RELATIVE_Y, 20))
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());

    // Check that there's no update on the PointerController.
    pc->assertPosition(100, 200);
    ASSERT_FALSE(pc->isPointerShown());

    // Check x-y cooridnates, displayId and cursor position are not changed.
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithCoords(10, 20), WithRelativeMotion(10, 20), WithDisplayId(ADISPLAY_ID_NONE),
                  WithCursorPosition(AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                     AMOTION_EVENT_INVALID_CURSOR_POSITION)));
}

TEST_F(PointerChoreographerTest, WhenPointerCaptureEnabledHidesPointer) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    mTestListener.assertNotifyMotionWasCalled(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE));
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());

    // Set bounds and initial position of the PointerController.
    pc->setPosition(100, 200);

    // Make NotifyMotionArgs and notify Choreographer.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());

    // Check that the PointerController updated the position and the pointer is shown.
    pc->assertPosition(110, 220);
    ASSERT_TRUE(pc->isPointerShown());

    // Enable pointer capture and check if the PointerController hid the pointer.
    mChoreographer.notifyPointerCaptureChanged(
            NotifyPointerCaptureChangedArgs(/*id=*/1, systemTime(SYSTEM_TIME_MONOTONIC),
                                            PointerCaptureRequest(/*enable=*/true, /*seq=*/0)));
    ASSERT_FALSE(pc->isPointerShown());
}

TEST_F(PointerChoreographerTest, WhenShowTouchesEnabledAndDisabledDoesNotCreatePointerController) {
    // Disable show touches and add a touch device.
    mChoreographer.setShowTouchesEnabled(false);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID)}});
    assertPointerControllerNotCreated();

    // Enable show touches. PointerController still should not be created.
    mChoreographer.setShowTouchesEnabled(true);
    assertPointerControllerNotCreated();
}

TEST_F(PointerChoreographerTest, WhenTouchEventOccursCreatesPointerController) {
    // Add a touch device and enable show touches.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID)}});
    mChoreographer.setShowTouchesEnabled(true);
    assertPointerControllerNotCreated();

    // Emit touch event. Now PointerController should be created.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    assertPointerControllerCreated(ControllerType::TOUCH);
}

TEST_F(PointerChoreographerTest,
       WhenShowTouchesDisabledAndTouchEventOccursDoesNotCreatePointerController) {
    // Add a touch device and disable show touches.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID)}});
    mChoreographer.setShowTouchesEnabled(false);
    assertPointerControllerNotCreated();

    // Emit touch event. Still, PointerController should not be created.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    assertPointerControllerNotCreated();
}

TEST_F(PointerChoreographerTest, WhenTouchDeviceIsRemovedRemovesPointerController) {
    // Make sure the PointerController is created.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID)}});
    mChoreographer.setShowTouchesEnabled(true);
    assertPointerControllerNotCreated();
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    auto pc = assertPointerControllerCreated(ControllerType::TOUCH);

    // Remove the device.
    mChoreographer.notifyInputDevicesChanged({/*id=*/1, {}});
    assertPointerControllerRemoved(pc);
}

TEST_F(PointerChoreographerTest, WhenShowTouchesDisabledRemovesPointerController) {
    // Make sure the PointerController is created.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID)}});
    mChoreographer.setShowTouchesEnabled(true);
    assertPointerControllerNotCreated();
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    auto pc = assertPointerControllerCreated(ControllerType::TOUCH);

    // Disable show touches.
    mChoreographer.setShowTouchesEnabled(false);
    assertPointerControllerRemoved(pc);
}

TEST_F(PointerChoreographerTest, TouchSetsSpots) {
    mChoreographer.setShowTouchesEnabled(true);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID)}});

    // Emit first pointer down.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    auto pc = assertPointerControllerCreated(ControllerType::TOUCH);
    auto it = pc->getSpots().find(DISPLAY_ID);
    ASSERT_TRUE(it != pc->getSpots().end());
    ASSERT_EQ(size_t(1), it->second.size());

    // Emit second pointer down.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                      (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                              AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .pointer(SECOND_TOUCH_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    it = pc->getSpots().find(DISPLAY_ID);
    ASSERT_TRUE(it != pc->getSpots().end());
    ASSERT_EQ(size_t(2), it->second.size());

    // Emit second pointer up.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_POINTER_UP |
                                      (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                              AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .pointer(SECOND_TOUCH_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    it = pc->getSpots().find(DISPLAY_ID);
    ASSERT_TRUE(it != pc->getSpots().end());
    ASSERT_EQ(size_t(1), it->second.size());

    // Emit first pointer up.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    it = pc->getSpots().find(DISPLAY_ID);
    ASSERT_TRUE(it != pc->getSpots().end());
    ASSERT_EQ(size_t(0), it->second.size());
}

TEST_F(PointerChoreographerTest, TouchSetsSpotsForStylusEvent) {
    mChoreographer.setShowTouchesEnabled(true);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_STYLUS,
                                     DISPLAY_ID)}});

    // Emit down event with stylus properties.
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN,
                                                  AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_STYLUS)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto pc = assertPointerControllerCreated(ControllerType::TOUCH);
    auto it = pc->getSpots().find(DISPLAY_ID);
    ASSERT_TRUE(it != pc->getSpots().end());
    ASSERT_EQ(size_t(1), it->second.size());
}

TEST_F(PointerChoreographerTest, TouchSetsSpotsForTwoDisplays) {
    mChoreographer.setShowTouchesEnabled(true);
    // Add two touch devices associated to different displays.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID),
              generateTestDeviceInfo(SECOND_DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN,
                                     ANOTHER_DISPLAY_ID)}});

    // Emit touch event with first device.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    auto firstDisplayPc = assertPointerControllerCreated(ControllerType::TOUCH);
    auto firstSpotsIt = firstDisplayPc->getSpots().find(DISPLAY_ID);
    ASSERT_TRUE(firstSpotsIt != firstDisplayPc->getSpots().end());
    ASSERT_EQ(size_t(1), firstSpotsIt->second.size());

    // Emit touch events with second device.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .deviceId(SECOND_DEVICE_ID)
                    .displayId(ANOTHER_DISPLAY_ID)
                    .build());
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_POINTER_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .pointer(SECOND_TOUCH_POINTER)
                    .deviceId(SECOND_DEVICE_ID)
                    .displayId(ANOTHER_DISPLAY_ID)
                    .build());

    // There should be another PointerController created.
    auto secondDisplayPc = assertPointerControllerCreated(ControllerType::TOUCH);

    // Check if the spots are set for the second device.
    auto secondSpotsIt = secondDisplayPc->getSpots().find(ANOTHER_DISPLAY_ID);
    ASSERT_TRUE(secondSpotsIt != secondDisplayPc->getSpots().end());
    ASSERT_EQ(size_t(2), secondSpotsIt->second.size());

    // Check if there's no change on the spot of the first device.
    firstSpotsIt = firstDisplayPc->getSpots().find(DISPLAY_ID);
    ASSERT_TRUE(firstSpotsIt != firstDisplayPc->getSpots().end());
    ASSERT_EQ(size_t(1), firstSpotsIt->second.size());
}

TEST_F(PointerChoreographerTest, WhenTouchDeviceIsResetClearsSpots) {
    // Make sure the PointerController is created and there is a spot.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID)}});
    mChoreographer.setShowTouchesEnabled(true);
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    auto pc = assertPointerControllerCreated(ControllerType::TOUCH);
    auto it = pc->getSpots().find(DISPLAY_ID);
    ASSERT_TRUE(it != pc->getSpots().end());
    ASSERT_EQ(size_t(1), it->second.size());

    // Reset the device and see there's no spot.
    mChoreographer.notifyDeviceReset(NotifyDeviceResetArgs(/*id=*/1, /*eventTime=*/0, DEVICE_ID));
    it = pc->getSpots().find(DISPLAY_ID);
    ASSERT_TRUE(it == pc->getSpots().end());
}

} // namespace android
