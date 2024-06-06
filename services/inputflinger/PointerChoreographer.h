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

#pragma once

#include "InputListener.h"
#include "NotifyArgs.h"
#include "PointerChoreographerPolicyInterface.h"

#include <android-base/thread_annotations.h>
#include <type_traits>

namespace android {

struct SpriteIcon;

/**
 * A helper class that wraps a factory method that acts as a constructor for the type returned
 * by the factory method.
 */
template <typename Factory>
struct ConstructorDelegate {
    constexpr ConstructorDelegate(Factory&& factory) : mFactory(std::move(factory)) {}

    using ConstructedType = std::invoke_result_t<const Factory&>;
    constexpr operator ConstructedType() const { return mFactory(); }

    Factory mFactory;
};

/**
 * PointerChoreographer manages the icons shown by the system for input interactions.
 * This includes showing the mouse cursor, stylus hover icons, and touch spots.
 * It is responsible for accumulating the location of the mouse cursor, and populating
 * the cursor position for incoming events, if necessary.
 */
class PointerChoreographerInterface : public InputListenerInterface {
public:
    /**
     * Set the display that pointers, like the mouse cursor and drawing tablets,
     * should be drawn on.
     */
    virtual void setDefaultMouseDisplayId(int32_t displayId) = 0;
    virtual void setDisplayViewports(const std::vector<DisplayViewport>& viewports) = 0;
    virtual std::optional<DisplayViewport> getViewportForPointerDevice(
            int32_t associatedDisplayId = ADISPLAY_ID_NONE) = 0;
    virtual FloatPoint getMouseCursorPosition(int32_t displayId) = 0;
    virtual void setShowTouchesEnabled(bool enabled) = 0;
    virtual void setStylusPointerIconEnabled(bool enabled) = 0;
    /**
     * Set the icon that is shown for the given pointer. The request may fail in some cases, such
     * as if the device or display was removed, or if the cursor was moved to a different display.
     * Returns true if the icon was changed successfully, false otherwise.
     */
    virtual bool setPointerIcon(std::variant<std::unique_ptr<SpriteIcon>, PointerIconStyle> icon,
                                int32_t displayId, DeviceId deviceId) = 0;
    /**
     * Set whether pointer icons for mice, touchpads, and styluses should be visible on the
     * given display.
     */
    virtual void setPointerIconVisibility(int32_t displayId, bool visible) = 0;

    /**
     * This method may be called on any thread (usually by the input manager on a binder thread).
     */
    virtual void dump(std::string& dump) = 0;
};

class PointerChoreographer : public PointerChoreographerInterface {
public:
    explicit PointerChoreographer(InputListenerInterface& listener,
                                  PointerChoreographerPolicyInterface&);
    ~PointerChoreographer() override = default;

    void setDefaultMouseDisplayId(int32_t displayId) override;
    void setDisplayViewports(const std::vector<DisplayViewport>& viewports) override;
    std::optional<DisplayViewport> getViewportForPointerDevice(
            int32_t associatedDisplayId) override;
    FloatPoint getMouseCursorPosition(int32_t displayId) override;
    void setShowTouchesEnabled(bool enabled) override;
    void setStylusPointerIconEnabled(bool enabled) override;
    bool setPointerIcon(std::variant<std::unique_ptr<SpriteIcon>, PointerIconStyle> icon,
                        int32_t displayId, DeviceId deviceId) override;
    void setPointerIconVisibility(int32_t displayId, bool visible) override;

    void notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) override;
    void notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) override;
    void notifyKey(const NotifyKeyArgs& args) override;
    void notifyMotion(const NotifyMotionArgs& args) override;
    void notifySwitch(const NotifySwitchArgs& args) override;
    void notifySensor(const NotifySensorArgs& args) override;
    void notifyVibratorState(const NotifyVibratorStateArgs& args) override;
    void notifyDeviceReset(const NotifyDeviceResetArgs& args) override;
    void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) override;

    void dump(std::string& dump) override;

private:
    using PointerDisplayChange =
            std::optional<std::tuple<int32_t /*displayId*/, FloatPoint /*cursorPosition*/>>;
    [[nodiscard]] PointerDisplayChange updatePointerControllersLocked() REQUIRES(mLock);
    [[nodiscard]] PointerDisplayChange calculatePointerDisplayChangeToNotify() REQUIRES(mLock);
    const DisplayViewport* findViewportByIdLocked(int32_t displayId) const REQUIRES(mLock);
    int32_t getTargetMouseDisplayLocked(int32_t associatedDisplayId) const REQUIRES(mLock);
    std::pair<int32_t /*displayId*/, PointerControllerInterface&> ensureMouseControllerLocked(
            int32_t associatedDisplayId) REQUIRES(mLock);
    InputDeviceInfo* findInputDeviceLocked(DeviceId deviceId) REQUIRES(mLock);
    bool canUnfadeOnDisplay(int32_t displayId) REQUIRES(mLock);

    NotifyMotionArgs processMotion(const NotifyMotionArgs& args);
    NotifyMotionArgs processMouseEventLocked(const NotifyMotionArgs& args) REQUIRES(mLock);
    NotifyMotionArgs processTouchpadEventLocked(const NotifyMotionArgs& args) REQUIRES(mLock);
    void processDrawingTabletEventLocked(const NotifyMotionArgs& args) REQUIRES(mLock);
    void processTouchscreenAndStylusEventLocked(const NotifyMotionArgs& args) REQUIRES(mLock);
    void processStylusHoverEventLocked(const NotifyMotionArgs& args) REQUIRES(mLock);
    void processDeviceReset(const NotifyDeviceResetArgs& args);

    using ControllerConstructor =
            ConstructorDelegate<std::function<std::shared_ptr<PointerControllerInterface>()>>;
    ControllerConstructor mTouchControllerConstructor GUARDED_BY(mLock);
    ControllerConstructor getMouseControllerConstructor(int32_t displayId) REQUIRES(mLock);
    ControllerConstructor getStylusControllerConstructor(int32_t displayId) REQUIRES(mLock);

    std::mutex mLock;

    InputListenerInterface& mNextListener;
    PointerChoreographerPolicyInterface& mPolicy;

    std::map<int32_t, std::shared_ptr<PointerControllerInterface>> mMousePointersByDisplay
            GUARDED_BY(mLock);
    std::map<DeviceId, std::shared_ptr<PointerControllerInterface>> mTouchPointersByDevice
            GUARDED_BY(mLock);
    std::map<DeviceId, std::shared_ptr<PointerControllerInterface>> mStylusPointersByDevice
            GUARDED_BY(mLock);
    std::map<DeviceId, std::shared_ptr<PointerControllerInterface>> mDrawingTabletPointersByDevice
            GUARDED_BY(mLock);

    int32_t mDefaultMouseDisplayId GUARDED_BY(mLock);
    int32_t mNotifiedPointerDisplayId GUARDED_BY(mLock);
    std::vector<InputDeviceInfo> mInputDeviceInfos GUARDED_BY(mLock);
    std::set<DeviceId> mMouseDevices GUARDED_BY(mLock);
    std::vector<DisplayViewport> mViewports GUARDED_BY(mLock);
    bool mShowTouchesEnabled GUARDED_BY(mLock);
    bool mStylusPointerIconEnabled GUARDED_BY(mLock);
    std::set<int32_t /*displayId*/> mDisplaysWithPointersHidden;
};

} // namespace android
