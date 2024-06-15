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
#include <deque>
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
struct Visitor : V... {
    using V::operator()...;
};
template <typename... V>
Visitor(V...) -> Visitor<V...>;

constexpr int32_t DEVICE_ID = 3;
constexpr int32_t SECOND_DEVICE_ID = DEVICE_ID + 1;
constexpr int32_t DISPLAY_ID = 5;
constexpr int32_t ANOTHER_DISPLAY_ID = 10;
constexpr int32_t DISPLAY_WIDTH = 480;
constexpr int32_t DISPLAY_HEIGHT = 800;
constexpr auto DRAWING_TABLET_SOURCE = AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_STYLUS;

const auto MOUSE_POINTER = PointerBuilder(/*id=*/0, ToolType::MOUSE)
                                   .axis(AMOTION_EVENT_AXIS_RELATIVE_X, 10)
                                   .axis(AMOTION_EVENT_AXIS_RELATIVE_Y, 20);
const auto FIRST_TOUCH_POINTER = PointerBuilder(/*id=*/0, ToolType::FINGER).x(100).y(200);
const auto SECOND_TOUCH_POINTER = PointerBuilder(/*id=*/1, ToolType::FINGER).x(200).y(300);
const auto STYLUS_POINTER = PointerBuilder(/*id=*/0, ToolType::STYLUS).x(100).y(200);
const auto TOUCHPAD_POINTER = PointerBuilder(/*id=*/0, ToolType::FINGER)
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
        EXPECT_FALSE(mCreatedControllers.empty()) << "No PointerController was created";
        auto [type, controller] = std::move(mCreatedControllers.front());
        EXPECT_EQ(expectedType, type);
        mCreatedControllers.pop_front();
        return controller;
    }

    void assertPointerControllerNotCreated() { ASSERT_TRUE(mCreatedControllers.empty()); }

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

    void assertPointerControllerNotRemoved(const std::shared_ptr<FakePointerController>& pc) {
        // See assertPointerControllerRemoved above.
        ASSERT_GT(pc.use_count(), 1) << "Expected PointerChoreographer to hold at least one "
                                        "reference to this PointerController";
    }

    void assertPointerDisplayIdNotified(int32_t displayId) {
        ASSERT_EQ(displayId, mPointerDisplayIdNotified);
        mPointerDisplayIdNotified.reset();
    }

    void assertPointerDisplayIdNotNotified() { ASSERT_EQ(std::nullopt, mPointerDisplayIdNotified); }

private:
    std::deque<std::pair<ControllerType, std::shared_ptr<FakePointerController>>>
            mCreatedControllers;
    std::optional<int32_t> mPointerDisplayIdNotified;

    std::shared_ptr<PointerControllerInterface> createPointerController(
            ControllerType type) override {
        std::shared_ptr<FakePointerController> pc = std::make_shared<FakePointerController>();
        EXPECT_FALSE(pc->isPointerShown());
        mCreatedControllers.emplace_back(type, pc);
        return pc;
    }

    void notifyPointerDisplayIdChanged(int32_t displayId, const FloatPoint& position) override {
        mPointerDisplayIdNotified = displayId;
    }
};

TEST_F(PointerChoreographerTest, ForwardsArgsToInnerListener) {
    const std::vector<NotifyArgs>
            allArgs{NotifyInputDevicesChangedArgs{},
                    NotifyConfigurationChangedArgs{},
                    KeyArgsBuilder(AKEY_EVENT_ACTION_DOWN, AINPUT_SOURCE_KEYBOARD).build(),
                    MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                            .pointer(FIRST_TOUCH_POINTER)
                            .build(),
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

TEST_F(PointerChoreographerTest, WhenMouseIsAddedCreatesPointerController) {
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    assertPointerControllerCreated(ControllerType::MOUSE);
}

TEST_F(PointerChoreographerTest, WhenMouseIsRemovedRemovesPointerController) {
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
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
    // Just adding a viewport or device should create a PointerController.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, DISPLAY_ID)}});

    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    pc->assertViewportSet(DISPLAY_ID);
    ASSERT_TRUE(pc->isPointerShown());
}

TEST_F(PointerChoreographerTest, WhenViewportSetLaterSetsViewportForAssociatedMouse) {
    // Without viewport information, PointerController will be created but viewport won't be set.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, DISPLAY_ID)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    pc->assertViewportNotSet();

    // After Choreographer gets viewport, PointerController should also have viewport.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    pc->assertViewportSet(DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, SetsDefaultMouseViewportForPointerController) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);

    // For a mouse event without a target display, default viewport should be set for
    // the PointerController.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    pc->assertViewportSet(DISPLAY_ID);
    ASSERT_TRUE(pc->isPointerShown());
}

TEST_F(PointerChoreographerTest,
       WhenDefaultMouseDisplayChangesSetsDefaultMouseViewportForPointerController) {
    // Set one display as a default mouse display and emit mouse event to create PointerController.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID, ANOTHER_DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    auto firstDisplayPc = assertPointerControllerCreated(ControllerType::MOUSE);
    firstDisplayPc->assertViewportSet(DISPLAY_ID);
    ASSERT_TRUE(firstDisplayPc->isPointerShown());

    // Change default mouse display. Existing PointerController should be removed and a new one
    // should be created.
    mChoreographer.setDefaultMouseDisplayId(ANOTHER_DISPLAY_ID);
    assertPointerControllerRemoved(firstDisplayPc);

    auto secondDisplayPc = assertPointerControllerCreated(ControllerType::MOUSE);
    secondDisplayPc->assertViewportSet(ANOTHER_DISPLAY_ID);
    ASSERT_TRUE(secondDisplayPc->isPointerShown());
}

TEST_F(PointerChoreographerTest, CallsNotifyPointerDisplayIdChanged) {
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    assertPointerControllerCreated(ControllerType::MOUSE);

    assertPointerDisplayIdNotified(DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, WhenViewportIsSetLaterCallsNotifyPointerDisplayIdChanged) {
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
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
    auto firstDisplayPc = assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerDisplayIdNotified(DISPLAY_ID);

    // Set another viewport as a default mouse display ID. The mouse is moved to the other display.
    mChoreographer.setDefaultMouseDisplayId(ANOTHER_DISPLAY_ID);
    assertPointerControllerRemoved(firstDisplayPc);

    assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerDisplayIdNotified(ANOTHER_DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, MouseMovesPointerAndReturnsNewArgs) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());

    // Set initial position of the PointerController.
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

    // Check that x-y coordinates, displayId and cursor position are correctly updated.
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
    auto unassociatedMousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, unassociatedMousePc->getDisplayId());
    auto associatedMousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(ANOTHER_DISPLAY_ID, associatedMousePc->getDisplayId());

    // Set initial position for PointerControllers.
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

    // Check that x-y coordinates, displayId and cursor position are correctly updated.
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithCoords(310, 420), WithDeviceId(SECOND_DEVICE_ID),
                  WithDisplayId(ANOTHER_DISPLAY_ID), WithCursorPosition(310, 420)));
}

TEST_F(PointerChoreographerTest, DoesNotMovePointerForMouseRelativeSource) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());

    // Set initial position of the PointerController.
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

    // Check x-y coordinates, displayId and cursor position are not changed.
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
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());
    ASSERT_TRUE(pc->isPointerShown());

    // Enable pointer capture and check if the PointerController hid the pointer.
    mChoreographer.notifyPointerCaptureChanged(
            NotifyPointerCaptureChangedArgs(/*id=*/1, systemTime(SYSTEM_TIME_MONOTONIC),
                                            PointerCaptureRequest(/*enable=*/true, /*seq=*/0)));
    ASSERT_FALSE(pc->isPointerShown());
}

TEST_F(PointerChoreographerTest, MultipleMiceConnectionAndRemoval) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);

    // A mouse is connected, and the pointer is shown.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});

    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_TRUE(pc->isPointerShown());

    pc->fade(PointerControllerInterface::Transition::IMMEDIATE);

    // Add a second mouse is added, the pointer is shown again.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE),
              generateTestDeviceInfo(SECOND_DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    ASSERT_TRUE(pc->isPointerShown());

    // One of the mice is removed, and it does not cause the mouse pointer to fade, because
    // we have one more mouse connected.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(SECOND_DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    assertPointerControllerNotRemoved(pc);
    ASSERT_TRUE(pc->isPointerShown());

    // The final mouse is removed. The pointer is removed.
    mChoreographer.notifyInputDevicesChanged({/*id=*/0, {}});
    assertPointerControllerRemoved(pc);
}

TEST_F(PointerChoreographerTest, UnrelatedChangeDoesNotUnfadePointer) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});

    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_TRUE(pc->isPointerShown());

    pc->fade(PointerControllerInterface::Transition::IMMEDIATE);

    // Adding a touchscreen device does not unfade the mouse pointer.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE),
              generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_STYLUS,
                                     DISPLAY_ID)}});

    ASSERT_FALSE(pc->isPointerShown());

    // Show touches setting change does not unfade the mouse pointer.
    mChoreographer.setShowTouchesEnabled(true);

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
    pc->assertSpotCount(DISPLAY_ID, 1);

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
    pc->assertSpotCount(DISPLAY_ID, 2);

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
    pc->assertSpotCount(DISPLAY_ID, 1);

    // Emit first pointer up.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN)
                    .pointer(FIRST_TOUCH_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    pc->assertSpotCount(DISPLAY_ID, 0);
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
    pc->assertSpotCount(DISPLAY_ID, 1);
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
    firstDisplayPc->assertSpotCount(DISPLAY_ID, 1);

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
    secondDisplayPc->assertSpotCount(ANOTHER_DISPLAY_ID, 2);

    // Check if there's no change on the spot of the first device.
    firstDisplayPc->assertSpotCount(DISPLAY_ID, 1);
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
    pc->assertSpotCount(DISPLAY_ID, 1);

    // Reset the device and ensure the touch pointer controller was removed.
    mChoreographer.notifyDeviceReset(NotifyDeviceResetArgs(/*id=*/1, /*eventTime=*/0, DEVICE_ID));
    assertPointerControllerRemoved(pc);
}

using StylusFixtureParam =
        std::tuple</*name*/ std::string_view, /*source*/ uint32_t, ControllerType>;

class StylusTestFixture : public PointerChoreographerTest,
                          public ::testing::WithParamInterface<StylusFixtureParam> {};

INSTANTIATE_TEST_SUITE_P(PointerChoreographerTest, StylusTestFixture,
                         ::testing::Values(std::make_tuple("DirectStylus", AINPUT_SOURCE_STYLUS,
                                                           ControllerType::STYLUS),
                                           std::make_tuple("DrawingTablet", DRAWING_TABLET_SOURCE,
                                                           ControllerType::MOUSE)),
                         [](const testing::TestParamInfo<StylusFixtureParam>& p) {
                             return std::string{std::get<0>(p.param)};
                         });

TEST_P(StylusTestFixture, WhenStylusPointerIconEnabledAndDisabledDoesNotCreatePointerController) {
    const auto& [name, source, controllerType] = GetParam();

    // Disable stylus pointer icon and add a stylus device.
    mChoreographer.setStylusPointerIconEnabled(false);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID)}});
    assertPointerControllerNotCreated();

    // Enable stylus pointer icon. PointerController still should not be created.
    mChoreographer.setStylusPointerIconEnabled(true);
    assertPointerControllerNotCreated();
}

TEST_P(StylusTestFixture, WhenStylusHoverEventOccursCreatesPointerController) {
    const auto& [name, source, controllerType] = GetParam();

    // Add a stylus device and enable stylus pointer icon.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(true);
    assertPointerControllerNotCreated();

    // Emit hover event. Now PointerController should be created.
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    assertPointerControllerCreated(controllerType);
}

TEST_F(PointerChoreographerTest, StylusHoverEventWhenStylusPointerIconDisabled) {
    // Add a stylus device and disable stylus pointer icon.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_STYLUS, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(false);
    assertPointerControllerNotCreated();

    // Emit hover event. Still, PointerController should not be created.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, AINPUT_SOURCE_STYLUS)
                    .pointer(STYLUS_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    assertPointerControllerNotCreated();
}

TEST_F(PointerChoreographerTest, DrawingTabletHoverEventWhenStylusPointerIconDisabled) {
    // Add a drawing tablet and disable stylus pointer icon.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, DRAWING_TABLET_SOURCE, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(false);
    assertPointerControllerNotCreated();

    // Emit hover event. Drawing tablets are not affected by "stylus pointer icon" setting.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, DRAWING_TABLET_SOURCE)
                    .pointer(STYLUS_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    assertPointerControllerCreated(ControllerType::MOUSE);
}

TEST_P(StylusTestFixture, WhenStylusDeviceIsRemovedRemovesPointerController) {
    const auto& [name, source, controllerType] = GetParam();

    // Make sure the PointerController is created.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto pc = assertPointerControllerCreated(controllerType);

    // Remove the device.
    mChoreographer.notifyInputDevicesChanged({/*id=*/1, {}});
    assertPointerControllerRemoved(pc);
}

TEST_F(PointerChoreographerTest, StylusPointerIconDisabledRemovesPointerController) {
    // Make sure the PointerController is created.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_STYLUS, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, AINPUT_SOURCE_STYLUS)
                    .pointer(STYLUS_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    auto pc = assertPointerControllerCreated(ControllerType::STYLUS);

    // Disable stylus pointer icon.
    mChoreographer.setStylusPointerIconEnabled(false);
    assertPointerControllerRemoved(pc);
}

TEST_F(PointerChoreographerTest,
       StylusPointerIconDisabledDoesNotRemoveDrawingTabletPointerController) {
    // Make sure the PointerController is created.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, DRAWING_TABLET_SOURCE, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, DRAWING_TABLET_SOURCE)
                    .pointer(STYLUS_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);

    // Disable stylus pointer icon. This should not affect drawing tablets.
    mChoreographer.setStylusPointerIconEnabled(false);
    assertPointerControllerNotRemoved(pc);
}

TEST_P(StylusTestFixture, SetsViewportForStylusPointerController) {
    const auto& [name, source, controllerType] = GetParam();

    // Set viewport.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));

    // Make sure the PointerController is created.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto pc = assertPointerControllerCreated(controllerType);

    // Check that viewport is set for the PointerController.
    pc->assertViewportSet(DISPLAY_ID);
}

TEST_P(StylusTestFixture, WhenViewportIsSetLaterSetsViewportForStylusPointerController) {
    const auto& [name, source, controllerType] = GetParam();

    // Make sure the PointerController is created.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto pc = assertPointerControllerCreated(controllerType);

    // Check that viewport is unset.
    pc->assertViewportNotSet();

    // Set viewport.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));

    // Check that the viewport is set for the PointerController.
    pc->assertViewportSet(DISPLAY_ID);
}

TEST_P(StylusTestFixture, WhenViewportDoesNotMatchDoesNotSetViewportForStylusPointerController) {
    const auto& [name, source, controllerType] = GetParam();

    // Make sure the PointerController is created.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto pc = assertPointerControllerCreated(controllerType);

    // Check that viewport is unset.
    pc->assertViewportNotSet();

    // Set viewport which does not match the associated display of the stylus.
    mChoreographer.setDisplayViewports(createViewports({ANOTHER_DISPLAY_ID}));

    // Check that viewport is still unset.
    pc->assertViewportNotSet();
}

TEST_P(StylusTestFixture, StylusHoverManipulatesPointer) {
    const auto& [name, source, controllerType] = GetParam();

    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));

    // Emit hover enter event. This is for creating PointerController.
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto pc = assertPointerControllerCreated(controllerType);

    // Emit hover move event. After bounds are set, PointerController will update the position.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, source)
                    .pointer(PointerBuilder(/*id=*/0, ToolType::STYLUS).x(150).y(250))
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    pc->assertPosition(150, 250);
    ASSERT_TRUE(pc->isPointerShown());

    // Emit hover exit event.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_EXIT, source)
                    .pointer(PointerBuilder(/*id=*/0, ToolType::STYLUS).x(150).y(250))
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    // Check that the pointer is gone.
    ASSERT_FALSE(pc->isPointerShown());
}

TEST_P(StylusTestFixture, StylusHoverManipulatesPointerForTwoDisplays) {
    const auto& [name, source, controllerType] = GetParam();

    mChoreographer.setStylusPointerIconEnabled(true);
    // Add two stylus devices associated to different displays.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID),
              generateTestDeviceInfo(SECOND_DEVICE_ID, source, ANOTHER_DISPLAY_ID)}});
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID, ANOTHER_DISPLAY_ID}));

    // Emit hover event with first device. This is for creating PointerController.
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto firstDisplayPc = assertPointerControllerCreated(controllerType);

    // Emit hover event with second device. This is for creating PointerController.
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(SECOND_DEVICE_ID)
                                        .displayId(ANOTHER_DISPLAY_ID)
                                        .build());

    // There should be another PointerController created.
    auto secondDisplayPc = assertPointerControllerCreated(controllerType);

    // Emit hover event with first device.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, source)
                    .pointer(PointerBuilder(/*id=*/0, ToolType::STYLUS).x(150).y(250))
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());

    // Check the pointer of the first device.
    firstDisplayPc->assertPosition(150, 250);
    ASSERT_TRUE(firstDisplayPc->isPointerShown());

    // Emit hover event with second device.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, source)
                    .pointer(PointerBuilder(/*id=*/0, ToolType::STYLUS).x(250).y(350))
                    .deviceId(SECOND_DEVICE_ID)
                    .displayId(ANOTHER_DISPLAY_ID)
                    .build());

    // Check the pointer of the second device.
    secondDisplayPc->assertPosition(250, 350);
    ASSERT_TRUE(secondDisplayPc->isPointerShown());

    // Check that there's no change on the pointer of the first device.
    firstDisplayPc->assertPosition(150, 250);
    ASSERT_TRUE(firstDisplayPc->isPointerShown());
}

TEST_P(StylusTestFixture, WhenStylusDeviceIsResetRemovesPointer) {
    const auto& [name, source, controllerType] = GetParam();

    // Make sure the PointerController is created and there is a pointer.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto pc = assertPointerControllerCreated(controllerType);
    ASSERT_TRUE(pc->isPointerShown());

    // Reset the device and see the pointer controller was removed.
    mChoreographer.notifyDeviceReset(NotifyDeviceResetArgs(/*id=*/1, /*eventTime=*/0, DEVICE_ID));
    assertPointerControllerRemoved(pc);
}

TEST_F(PointerChoreographerTest, WhenTouchpadIsAddedCreatesPointerController) {
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    assertPointerControllerCreated(ControllerType::MOUSE);
}

TEST_F(PointerChoreographerTest, WhenTouchpadIsRemovedRemovesPointerController) {
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);

    // Remove the touchpad.
    mChoreographer.notifyInputDevicesChanged({/*id=*/1, {}});
    assertPointerControllerRemoved(pc);
}

TEST_F(PointerChoreographerTest, SetsViewportForAssociatedTouchpad) {
    // Just adding a viewport or device should not create a PointerController.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     DISPLAY_ID)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    pc->assertViewportSet(DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, WhenViewportSetLaterSetsViewportForAssociatedTouchpad) {
    // Without viewport information, PointerController will be created by a touchpad event
    // but viewport won't be set.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     DISPLAY_ID)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    pc->assertViewportNotSet();

    // After Choreographer gets viewport, PointerController should also have viewport.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    pc->assertViewportSet(DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, SetsDefaultTouchpadViewportForPointerController) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);

    // For a touchpad event without a target display, default viewport should be set for
    // the PointerController.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    pc->assertViewportSet(DISPLAY_ID);
}

TEST_F(PointerChoreographerTest,
       WhenDefaultTouchpadDisplayChangesSetsDefaultTouchpadViewportForPointerController) {
    // Set one display as a default touchpad display and create PointerController.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID, ANOTHER_DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    auto firstDisplayPc = assertPointerControllerCreated(ControllerType::MOUSE);
    firstDisplayPc->assertViewportSet(DISPLAY_ID);

    // Change default mouse display. Existing PointerController should be removed.
    mChoreographer.setDefaultMouseDisplayId(ANOTHER_DISPLAY_ID);
    assertPointerControllerRemoved(firstDisplayPc);

    auto secondDisplayPc = assertPointerControllerCreated(ControllerType::MOUSE);
    secondDisplayPc->assertViewportSet(ANOTHER_DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, TouchpadCallsNotifyPointerDisplayIdChanged) {
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    assertPointerControllerCreated(ControllerType::MOUSE);

    assertPointerDisplayIdNotified(DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, WhenViewportIsSetLaterTouchpadCallsNotifyPointerDisplayIdChanged) {
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerDisplayIdNotNotified();

    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    assertPointerDisplayIdNotified(DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, WhenTouchpadIsRemovedCallsNotifyPointerDisplayIdChanged) {
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerDisplayIdNotified(DISPLAY_ID);

    mChoreographer.notifyInputDevicesChanged({/*id=*/1, {}});
    assertPointerDisplayIdNotified(ADISPLAY_ID_NONE);
    assertPointerControllerRemoved(pc);
}

TEST_F(PointerChoreographerTest,
       WhenDefaultMouseDisplayChangesTouchpadCallsNotifyPointerDisplayIdChanged) {
    // Add two viewports.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID, ANOTHER_DISPLAY_ID}));

    // Set one viewport as a default mouse display ID.
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    auto firstDisplayPc = assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerDisplayIdNotified(DISPLAY_ID);

    // Set another viewport as a default mouse display ID. ADISPLAY_ID_NONE will be notified
    // before a touchpad event.
    mChoreographer.setDefaultMouseDisplayId(ANOTHER_DISPLAY_ID);
    assertPointerControllerRemoved(firstDisplayPc);

    assertPointerControllerCreated(ControllerType::MOUSE);
    assertPointerDisplayIdNotified(ANOTHER_DISPLAY_ID);
}

TEST_F(PointerChoreographerTest, TouchpadMovesPointerAndReturnsNewArgs) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());

    // Set initial position of the PointerController.
    pc->setPosition(100, 200);

    // Make NotifyMotionArgs and notify Choreographer.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(TOUCHPAD_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());

    // Check that the PointerController updated the position and the pointer is shown.
    pc->assertPosition(110, 220);
    ASSERT_TRUE(pc->isPointerShown());

    // Check that x-y coordinates, displayId and cursor position are correctly updated.
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithCoords(110, 220), WithDisplayId(DISPLAY_ID), WithCursorPosition(110, 220)));
}

TEST_F(PointerChoreographerTest, TouchpadAddsPointerPositionToTheCoords) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());

    // Set initial position of the PointerController.
    pc->setPosition(100, 200);

    // Notify motion with fake fingers, as if it is multi-finger swipe.
    // Check if the position of the PointerController is added to the fake finger coords.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(-100).y(0))
                    .classification(MotionClassification::MULTI_FINGER_SWIPE)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithMotionClassification(MotionClassification::MULTI_FINGER_SWIPE),
                  WithCoords(0, 200), WithCursorPosition(100, 200)));
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                      (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                              AINPUT_SOURCE_MOUSE)
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(-100).y(0))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(0).y(0))
                    .classification(MotionClassification::MULTI_FINGER_SWIPE)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                   (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT)),
                  WithMotionClassification(MotionClassification::MULTI_FINGER_SWIPE),
                  WithPointerCoords(0, 0, 200), WithPointerCoords(1, 100, 200),
                  WithCursorPosition(100, 200)));
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                      (2 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                              AINPUT_SOURCE_MOUSE)
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(-100).y(0))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(0).y(0))
                    .pointer(PointerBuilder(/*id=*/2, ToolType::FINGER).x(100).y(0))
                    .classification(MotionClassification::MULTI_FINGER_SWIPE)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                   (2 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT)),
                  WithMotionClassification(MotionClassification::MULTI_FINGER_SWIPE),
                  WithPointerCoords(0, 0, 200), WithPointerCoords(1, 100, 200),
                  WithPointerCoords(2, 200, 200), WithCursorPosition(100, 200)));
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(-90).y(10))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(10).y(10))
                    .pointer(PointerBuilder(/*id=*/2, ToolType::FINGER).x(110).y(10))
                    .classification(MotionClassification::MULTI_FINGER_SWIPE)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithMotionClassification(MotionClassification::MULTI_FINGER_SWIPE),
                  WithPointerCoords(0, 10, 210), WithPointerCoords(1, 110, 210),
                  WithPointerCoords(2, 210, 210), WithCursorPosition(100, 200)));
}

TEST_F(PointerChoreographerTest,
       AssociatedTouchpadMovesPointerOnAssociatedDisplayAndDoesNotMovePointerOnDefaultDisplay) {
    // Add two displays and set one to default.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID, ANOTHER_DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);

    // Add two devices, one unassociated and the other associated with non-default mouse display.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE),
              generateTestDeviceInfo(SECOND_DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ANOTHER_DISPLAY_ID)}});
    auto unassociatedMousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, unassociatedMousePc->getDisplayId());
    auto associatedMousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(ANOTHER_DISPLAY_ID, associatedMousePc->getDisplayId());

    // Set initial positions for PointerControllers.
    unassociatedMousePc->setPosition(100, 200);
    associatedMousePc->setPosition(300, 400);

    // Make NotifyMotionArgs from the associated mouse and notify Choreographer.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(TOUCHPAD_POINTER)
                    .deviceId(SECOND_DEVICE_ID)
                    .displayId(ANOTHER_DISPLAY_ID)
                    .build());

    // Check the status of the PointerControllers.
    unassociatedMousePc->assertPosition(100, 200);
    ASSERT_EQ(DISPLAY_ID, unassociatedMousePc->getDisplayId());
    associatedMousePc->assertPosition(310, 420);
    ASSERT_EQ(ANOTHER_DISPLAY_ID, associatedMousePc->getDisplayId());
    ASSERT_TRUE(associatedMousePc->isPointerShown());

    // Check that x-y coordinates, displayId and cursor position are correctly updated.
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithCoords(310, 420), WithDeviceId(SECOND_DEVICE_ID),
                  WithDisplayId(ANOTHER_DISPLAY_ID), WithCursorPosition(310, 420)));
}

TEST_F(PointerChoreographerTest, DoesNotMovePointerForTouchpadSource) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());

    // Set initial position of the PointerController.
    pc->setPosition(200, 300);

    // Assume that pointer capture is enabled.
    mChoreographer.notifyPointerCaptureChanged(
            NotifyPointerCaptureChangedArgs(/*id=*/1, systemTime(SYSTEM_TIME_MONOTONIC),
                                            PointerCaptureRequest(/*enable=*/true, /*seq=*/0)));

    // Notify motion as if pointer capture is enabled.
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHPAD)
                                        .pointer(FIRST_TOUCH_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(ADISPLAY_ID_NONE)
                                        .build());

    // Check that there's no update on the PointerController.
    pc->assertPosition(200, 300);
    ASSERT_FALSE(pc->isPointerShown());

    // Check x-y coordinates, displayId and cursor position are not changed.
    mTestListener.assertNotifyMotionWasCalled(
            AllOf(WithCoords(100, 200), WithDisplayId(ADISPLAY_ID_NONE),
                  WithCursorPosition(AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                     AMOTION_EVENT_INVALID_CURSOR_POSITION)));
}

TEST_F(PointerChoreographerTest, WhenPointerCaptureEnabledTouchpadHidesPointer) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, pc->getDisplayId());
    ASSERT_TRUE(pc->isPointerShown());

    // Enable pointer capture and check if the PointerController hid the pointer.
    mChoreographer.notifyPointerCaptureChanged(
            NotifyPointerCaptureChangedArgs(/*id=*/1, systemTime(SYSTEM_TIME_MONOTONIC),
                                            PointerCaptureRequest(/*enable=*/true, /*seq=*/0)));
    ASSERT_FALSE(pc->isPointerShown());
}

TEST_F(PointerChoreographerTest, SetsPointerIconForMouse) {
    // Make sure there is a PointerController.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    pc->assertPointerIconNotSet();

    // Set pointer icon for the device.
    ASSERT_TRUE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, DISPLAY_ID, DEVICE_ID));
    pc->assertPointerIconSet(PointerIconStyle::TYPE_TEXT);
}

TEST_F(PointerChoreographerTest, DoesNotSetMousePointerIconForWrongDisplayId) {
    // Make sure there is a PointerController.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    pc->assertPointerIconNotSet();

    // Set pointer icon for wrong display id. This should be ignored.
    ASSERT_FALSE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, ANOTHER_DISPLAY_ID,
                                               SECOND_DEVICE_ID));
    pc->assertPointerIconNotSet();
}

TEST_F(PointerChoreographerTest, DoesNotSetPointerIconForWrongDeviceId) {
    // Make sure there is a PointerController.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    pc->assertPointerIconNotSet();

    // Set pointer icon for wrong device id. This should be ignored.
    ASSERT_FALSE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, DISPLAY_ID,
                                               SECOND_DEVICE_ID));
    pc->assertPointerIconNotSet();
}

TEST_F(PointerChoreographerTest, SetsCustomPointerIconForMouse) {
    // Make sure there is a PointerController.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    auto pc = assertPointerControllerCreated(ControllerType::MOUSE);
    pc->assertCustomPointerIconNotSet();

    // Set custom pointer icon for the device.
    ASSERT_TRUE(mChoreographer.setPointerIcon(std::make_unique<SpriteIcon>(
                                                      PointerIconStyle::TYPE_CUSTOM),
                                              DISPLAY_ID, DEVICE_ID));
    pc->assertCustomPointerIconSet(PointerIconStyle::TYPE_CUSTOM);

    // Set custom pointer icon for wrong device id. This should be ignored.
    ASSERT_FALSE(mChoreographer.setPointerIcon(std::make_unique<SpriteIcon>(
                                                       PointerIconStyle::TYPE_CUSTOM),
                                               DISPLAY_ID, SECOND_DEVICE_ID));
    pc->assertCustomPointerIconNotSet();
}

TEST_F(PointerChoreographerTest, SetsPointerIconForMouseOnTwoDisplays) {
    // Make sure there are two PointerControllers on different displays.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID, ANOTHER_DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE),
              generateTestDeviceInfo(SECOND_DEVICE_ID, AINPUT_SOURCE_MOUSE, ANOTHER_DISPLAY_ID)}});
    auto firstMousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, firstMousePc->getDisplayId());
    auto secondMousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(ANOTHER_DISPLAY_ID, secondMousePc->getDisplayId());

    // Set pointer icon for one mouse.
    ASSERT_TRUE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, DISPLAY_ID, DEVICE_ID));
    firstMousePc->assertPointerIconSet(PointerIconStyle::TYPE_TEXT);
    secondMousePc->assertPointerIconNotSet();

    // Set pointer icon for another mouse.
    ASSERT_TRUE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, ANOTHER_DISPLAY_ID,
                                              SECOND_DEVICE_ID));
    secondMousePc->assertPointerIconSet(PointerIconStyle::TYPE_TEXT);
    firstMousePc->assertPointerIconNotSet();
}

TEST_P(StylusTestFixture, SetsPointerIconForStylus) {
    const auto& [name, source, controllerType] = GetParam();

    // Make sure there is a PointerController.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto pc = assertPointerControllerCreated(controllerType);
    pc->assertPointerIconNotSet();

    // Set pointer icon for the device.
    ASSERT_TRUE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, DISPLAY_ID, DEVICE_ID));
    pc->assertPointerIconSet(PointerIconStyle::TYPE_TEXT);

    // Set pointer icon for wrong device id. This should be ignored.
    ASSERT_FALSE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, DISPLAY_ID,
                                               SECOND_DEVICE_ID));
    pc->assertPointerIconNotSet();

    // The stylus stops hovering. This should cause the icon to be reset.
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_EXIT, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    pc->assertPointerIconSet(PointerIconStyle::TYPE_NOT_SPECIFIED);
}

TEST_P(StylusTestFixture, SetsCustomPointerIconForStylus) {
    const auto& [name, source, controllerType] = GetParam();

    // Make sure there is a PointerController.
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto pc = assertPointerControllerCreated(controllerType);
    pc->assertCustomPointerIconNotSet();

    // Set custom pointer icon for the device.
    ASSERT_TRUE(mChoreographer.setPointerIcon(std::make_unique<SpriteIcon>(
                                                      PointerIconStyle::TYPE_CUSTOM),
                                              DISPLAY_ID, DEVICE_ID));
    pc->assertCustomPointerIconSet(PointerIconStyle::TYPE_CUSTOM);

    // Set custom pointer icon for wrong device id. This should be ignored.
    ASSERT_FALSE(mChoreographer.setPointerIcon(std::make_unique<SpriteIcon>(
                                                       PointerIconStyle::TYPE_CUSTOM),
                                               DISPLAY_ID, SECOND_DEVICE_ID));
    pc->assertCustomPointerIconNotSet();
}

TEST_P(StylusTestFixture, SetsPointerIconForTwoStyluses) {
    const auto& [name, source, controllerType] = GetParam();

    // Make sure there are two StylusPointerControllers. They can be on a same display.
    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID),
              generateTestDeviceInfo(SECOND_DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto firstStylusPc = assertPointerControllerCreated(controllerType);
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(SECOND_DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto secondStylusPc = assertPointerControllerCreated(controllerType);

    // Set pointer icon for one stylus.
    ASSERT_TRUE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, DISPLAY_ID, DEVICE_ID));
    firstStylusPc->assertPointerIconSet(PointerIconStyle::TYPE_TEXT);
    secondStylusPc->assertPointerIconNotSet();

    // Set pointer icon for another stylus.
    ASSERT_TRUE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, DISPLAY_ID,
                                              SECOND_DEVICE_ID));
    secondStylusPc->assertPointerIconSet(PointerIconStyle::TYPE_TEXT);
    firstStylusPc->assertPointerIconNotSet();
}

TEST_P(StylusTestFixture, SetsPointerIconForMouseAndStylus) {
    const auto& [name, source, controllerType] = GetParam();

    // Make sure there are PointerControllers for a mouse and a stylus.
    mChoreographer.setStylusPointerIconEnabled(true);
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE),
              generateTestDeviceInfo(SECOND_DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(ADISPLAY_ID_NONE)
                    .build());
    auto mousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(SECOND_DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    auto stylusPc = assertPointerControllerCreated(controllerType);

    // Set pointer icon for the mouse.
    ASSERT_TRUE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, DISPLAY_ID, DEVICE_ID));
    mousePc->assertPointerIconSet(PointerIconStyle::TYPE_TEXT);
    stylusPc->assertPointerIconNotSet();

    // Set pointer icon for the stylus.
    ASSERT_TRUE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, DISPLAY_ID,
                                              SECOND_DEVICE_ID));
    stylusPc->assertPointerIconSet(PointerIconStyle::TYPE_TEXT);
    mousePc->assertPointerIconNotSet();
}

TEST_F(PointerChoreographerTest, SetPointerIconVisibilityHidesPointerOnDisplay) {
    // Make sure there are two PointerControllers on different displays.
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID, ANOTHER_DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE),
              generateTestDeviceInfo(SECOND_DEVICE_ID, AINPUT_SOURCE_MOUSE, ANOTHER_DISPLAY_ID)}});
    auto firstMousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, firstMousePc->getDisplayId());
    auto secondMousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(ANOTHER_DISPLAY_ID, secondMousePc->getDisplayId());

    // Both pointers should be visible.
    ASSERT_TRUE(firstMousePc->isPointerShown());
    ASSERT_TRUE(secondMousePc->isPointerShown());

    // Hide the icon on the second display.
    mChoreographer.setPointerIconVisibility(ANOTHER_DISPLAY_ID, false);
    ASSERT_TRUE(firstMousePc->isPointerShown());
    ASSERT_FALSE(secondMousePc->isPointerShown());

    // Move and set pointer icons for both mice. The second pointer should still be hidden.
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(DEVICE_ID)
                    .displayId(DISPLAY_ID)
                    .build());
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(SECOND_DEVICE_ID)
                    .displayId(ANOTHER_DISPLAY_ID)
                    .build());
    ASSERT_TRUE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, DISPLAY_ID, DEVICE_ID));
    ASSERT_TRUE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, ANOTHER_DISPLAY_ID,
                                              SECOND_DEVICE_ID));
    firstMousePc->assertPointerIconSet(PointerIconStyle::TYPE_TEXT);
    secondMousePc->assertPointerIconSet(PointerIconStyle::TYPE_TEXT);
    ASSERT_TRUE(firstMousePc->isPointerShown());
    ASSERT_FALSE(secondMousePc->isPointerShown());

    // Allow the icon to be visible on the second display, and move the mouse.
    mChoreographer.setPointerIconVisibility(ANOTHER_DISPLAY_ID, true);
    mChoreographer.notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, AINPUT_SOURCE_MOUSE)
                    .pointer(MOUSE_POINTER)
                    .deviceId(SECOND_DEVICE_ID)
                    .displayId(ANOTHER_DISPLAY_ID)
                    .build());
    ASSERT_TRUE(firstMousePc->isPointerShown());
    ASSERT_TRUE(secondMousePc->isPointerShown());
}

TEST_F(PointerChoreographerTest, SetPointerIconVisibilityHidesPointerWhenDeviceConnected) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);

    // Hide the pointer on the display, and then connect the mouse.
    mChoreographer.setPointerIconVisibility(DISPLAY_ID, false);
    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE, ADISPLAY_ID_NONE)}});
    auto mousePc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, mousePc->getDisplayId());

    // The pointer should not be visible.
    ASSERT_FALSE(mousePc->isPointerShown());
}

TEST_F(PointerChoreographerTest, SetPointerIconVisibilityHidesPointerForTouchpad) {
    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setDefaultMouseDisplayId(DISPLAY_ID);

    // Hide the pointer on the display.
    mChoreographer.setPointerIconVisibility(DISPLAY_ID, false);

    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0,
             {generateTestDeviceInfo(DEVICE_ID, AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD,
                                     ADISPLAY_ID_NONE)}});
    auto touchpadPc = assertPointerControllerCreated(ControllerType::MOUSE);
    ASSERT_EQ(DISPLAY_ID, touchpadPc->getDisplayId());

    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER,
                                                  AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD)
                                        .pointer(TOUCHPAD_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());

    // The pointer should not be visible.
    ASSERT_FALSE(touchpadPc->isPointerShown());
}

TEST_P(StylusTestFixture, SetPointerIconVisibilityHidesPointerForStylus) {
    const auto& [name, source, controllerType] = GetParam();

    mChoreographer.setDisplayViewports(createViewports({DISPLAY_ID}));
    mChoreographer.setStylusPointerIconEnabled(true);

    // Hide the pointer on the display.
    mChoreographer.setPointerIconVisibility(DISPLAY_ID, false);

    mChoreographer.notifyInputDevicesChanged(
            {/*id=*/0, {generateTestDeviceInfo(DEVICE_ID, source, DISPLAY_ID)}});
    mChoreographer.notifyMotion(MotionArgsBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, source)
                                        .pointer(STYLUS_POINTER)
                                        .deviceId(DEVICE_ID)
                                        .displayId(DISPLAY_ID)
                                        .build());
    ASSERT_TRUE(mChoreographer.setPointerIcon(PointerIconStyle::TYPE_TEXT, DISPLAY_ID, DEVICE_ID));
    auto pc = assertPointerControllerCreated(controllerType);
    pc->assertPointerIconSet(PointerIconStyle::TYPE_TEXT);

    // The pointer should not be visible.
    ASSERT_FALSE(pc->isPointerShown());
}

} // namespace android
