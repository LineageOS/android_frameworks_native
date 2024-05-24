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

#include "FakeInputReaderPolicy.h"

#include <android-base/thread_annotations.h>
#include <gtest/gtest.h>

#include "TestConstants.h"
#include "ui/Rotation.h"

namespace android {

void FakeInputReaderPolicy::assertInputDevicesChanged() {
    waitForInputDevices([](bool devicesChanged) {
        if (!devicesChanged) {
            FAIL() << "Timed out waiting for notifyInputDevicesChanged() to be called.";
        }
    });
}

void FakeInputReaderPolicy::assertInputDevicesNotChanged() {
    waitForInputDevices([](bool devicesChanged) {
        if (devicesChanged) {
            FAIL() << "Expected notifyInputDevicesChanged() to not be called.";
        }
    });
}

void FakeInputReaderPolicy::assertStylusGestureNotified(int32_t deviceId) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    const bool success =
            mStylusGestureNotifiedCondition.wait_for(lock, WAIT_TIMEOUT, [this]() REQUIRES(mLock) {
                return mDeviceIdOfNotifiedStylusGesture.has_value();
            });
    ASSERT_TRUE(success) << "Timed out waiting for stylus gesture to be notified";
    ASSERT_EQ(deviceId, *mDeviceIdOfNotifiedStylusGesture);
    mDeviceIdOfNotifiedStylusGesture.reset();
}

void FakeInputReaderPolicy::assertStylusGestureNotNotified() {
    std::scoped_lock lock(mLock);
    ASSERT_FALSE(mDeviceIdOfNotifiedStylusGesture);
}

void FakeInputReaderPolicy::clearViewports() {
    mViewports.clear();
    mConfig.setDisplayViewports(mViewports);
}

std::optional<DisplayViewport> FakeInputReaderPolicy::getDisplayViewportByUniqueId(
        const std::string& uniqueId) const {
    return mConfig.getDisplayViewportByUniqueId(uniqueId);
}
std::optional<DisplayViewport> FakeInputReaderPolicy::getDisplayViewportByType(
        ViewportType type) const {
    return mConfig.getDisplayViewportByType(type);
}

std::optional<DisplayViewport> FakeInputReaderPolicy::getDisplayViewportByPort(
        uint8_t displayPort) const {
    return mConfig.getDisplayViewportByPort(displayPort);
}

void FakeInputReaderPolicy::addDisplayViewport(DisplayViewport viewport) {
    mViewports.push_back(std::move(viewport));
    mConfig.setDisplayViewports(mViewports);
}

void FakeInputReaderPolicy::addDisplayViewport(int32_t displayId, int32_t width, int32_t height,
                                               ui::Rotation orientation, bool isActive,
                                               const std::string& uniqueId,
                                               std::optional<uint8_t> physicalPort,
                                               ViewportType type) {
    const bool isRotated = orientation == ui::ROTATION_90 || orientation == ui::ROTATION_270;
    DisplayViewport v;
    v.displayId = displayId;
    v.orientation = orientation;
    v.logicalLeft = 0;
    v.logicalTop = 0;
    v.logicalRight = isRotated ? height : width;
    v.logicalBottom = isRotated ? width : height;
    v.physicalLeft = 0;
    v.physicalTop = 0;
    v.physicalRight = isRotated ? height : width;
    v.physicalBottom = isRotated ? width : height;
    v.deviceWidth = isRotated ? height : width;
    v.deviceHeight = isRotated ? width : height;
    v.isActive = isActive;
    v.uniqueId = uniqueId;
    v.physicalPort = physicalPort;
    v.type = type;

    addDisplayViewport(v);
}

bool FakeInputReaderPolicy::updateViewport(const DisplayViewport& viewport) {
    size_t count = mViewports.size();
    for (size_t i = 0; i < count; i++) {
        const DisplayViewport& currentViewport = mViewports[i];
        if (currentViewport.displayId == viewport.displayId) {
            mViewports[i] = viewport;
            mConfig.setDisplayViewports(mViewports);
            return true;
        }
    }
    // no viewport found.
    return false;
}

void FakeInputReaderPolicy::addExcludedDeviceName(const std::string& deviceName) {
    mConfig.excludedDeviceNames.push_back(deviceName);
}

void FakeInputReaderPolicy::addInputPortAssociation(const std::string& inputPort,
                                                    uint8_t displayPort) {
    mConfig.portAssociations.insert({inputPort, displayPort});
}

void FakeInputReaderPolicy::addDeviceTypeAssociation(const std::string& inputPort,
                                                     const std::string& type) {
    mConfig.deviceTypeAssociations.insert({inputPort, type});
}

void FakeInputReaderPolicy::addInputUniqueIdAssociation(const std::string& inputUniqueId,
                                                        const std::string& displayUniqueId) {
    mConfig.uniqueIdAssociations.insert({inputUniqueId, displayUniqueId});
}

void FakeInputReaderPolicy::addKeyboardLayoutAssociation(const std::string& inputUniqueId,
                                                         const KeyboardLayoutInfo& layoutInfo) {
    mConfig.keyboardLayoutAssociations.insert({inputUniqueId, layoutInfo});
}

void FakeInputReaderPolicy::addDisabledDevice(int32_t deviceId) {
    mConfig.disabledDevices.insert(deviceId);
}

void FakeInputReaderPolicy::removeDisabledDevice(int32_t deviceId) {
    mConfig.disabledDevices.erase(deviceId);
}

void FakeInputReaderPolicy::setPointerController(
        std::shared_ptr<FakePointerController> controller) {
    mPointerController = std::move(controller);
}

const InputReaderConfiguration& FakeInputReaderPolicy::getReaderConfiguration() const {
    return mConfig;
}

const std::vector<InputDeviceInfo> FakeInputReaderPolicy::getInputDevices() const {
    std::scoped_lock lock(mLock);
    return mInputDevices;
}

TouchAffineTransformation FakeInputReaderPolicy::getTouchAffineTransformation(
        const std::string& inputDeviceDescriptor, ui::Rotation surfaceRotation) {
    return transform;
}

void FakeInputReaderPolicy::setTouchAffineTransformation(const TouchAffineTransformation t) {
    transform = t;
}

PointerCaptureRequest FakeInputReaderPolicy::setPointerCapture(bool enabled) {
    mConfig.pointerCaptureRequest = {enabled, mNextPointerCaptureSequenceNumber++};
    return mConfig.pointerCaptureRequest;
}

void FakeInputReaderPolicy::setShowTouches(bool enabled) {
    mConfig.showTouches = enabled;
}

void FakeInputReaderPolicy::setDefaultPointerDisplayId(int32_t pointerDisplayId) {
    mConfig.defaultPointerDisplayId = pointerDisplayId;
}

void FakeInputReaderPolicy::setPointerGestureEnabled(bool enabled) {
    mConfig.pointerGesturesEnabled = enabled;
}

float FakeInputReaderPolicy::getPointerGestureMovementSpeedRatio() {
    return mConfig.pointerGestureMovementSpeedRatio;
}

float FakeInputReaderPolicy::getPointerGestureZoomSpeedRatio() {
    return mConfig.pointerGestureZoomSpeedRatio;
}

void FakeInputReaderPolicy::setVelocityControlParams(const VelocityControlParameters& params) {
    mConfig.pointerVelocityControlParameters = params;
    mConfig.wheelVelocityControlParameters = params;
}

void FakeInputReaderPolicy::setStylusButtonMotionEventsEnabled(bool enabled) {
    mConfig.stylusButtonMotionEventsEnabled = enabled;
}

void FakeInputReaderPolicy::setStylusPointerIconEnabled(bool enabled) {
    mConfig.stylusPointerIconEnabled = enabled;
}

void FakeInputReaderPolicy::setIsInputMethodConnectionActive(bool active) {
    mIsInputMethodConnectionActive = active;
}

bool FakeInputReaderPolicy::isInputMethodConnectionActive() {
    return mIsInputMethodConnectionActive;
}

void FakeInputReaderPolicy::getReaderConfiguration(InputReaderConfiguration* outConfig) {
    *outConfig = mConfig;
}

std::shared_ptr<PointerControllerInterface> FakeInputReaderPolicy::obtainPointerController(
        int32_t /*deviceId*/) {
    return mPointerController;
}

void FakeInputReaderPolicy::notifyInputDevicesChanged(
        const std::vector<InputDeviceInfo>& inputDevices) {
    std::scoped_lock lock(mLock);
    mInputDevices = inputDevices;
    mInputDevicesChanged = true;
    mDevicesChangedCondition.notify_all();
}

std::shared_ptr<KeyCharacterMap> FakeInputReaderPolicy::getKeyboardLayoutOverlay(
        const InputDeviceIdentifier&, const std::optional<KeyboardLayoutInfo>) {
    return nullptr;
}

std::string FakeInputReaderPolicy::getDeviceAlias(const InputDeviceIdentifier&) {
    return "";
}

void FakeInputReaderPolicy::waitForInputDevices(std::function<void(bool)> processDevicesChanged) {
    std::unique_lock<std::mutex> lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    const bool devicesChanged =
            mDevicesChangedCondition.wait_for(lock, WAIT_TIMEOUT, [this]() REQUIRES(mLock) {
                return mInputDevicesChanged;
            });
    ASSERT_NO_FATAL_FAILURE(processDevicesChanged(devicesChanged));
    mInputDevicesChanged = false;
}

void FakeInputReaderPolicy::notifyStylusGestureStarted(int32_t deviceId, nsecs_t eventTime) {
    std::scoped_lock lock(mLock);
    mDeviceIdOfNotifiedStylusGesture = deviceId;
    mStylusGestureNotifiedCondition.notify_all();
}

std::optional<DisplayViewport> FakeInputReaderPolicy::getPointerViewportForAssociatedDisplay(
        int32_t associatedDisplayId) {
    if (associatedDisplayId == ADISPLAY_ID_NONE) {
        associatedDisplayId = mConfig.defaultPointerDisplayId;
    }
    for (auto& viewport : mViewports) {
        if (viewport.displayId == associatedDisplayId) {
            return std::make_optional(viewport);
        }
    }
    return std::nullopt;
}

} // namespace android
