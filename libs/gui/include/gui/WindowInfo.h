/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <android/gui/TouchOcclusionMode.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <ftl/Flags.h>
#include <gui/constants.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <ui/Transform.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

#include "InputApplication.h"

namespace android::gui {

/*
 * Describes the properties of a window that can receive input.
 */
struct WindowInfo : public Parcelable {
    WindowInfo() = default;

    // Window flags from WindowManager.LayoutParams
    enum class Flag : uint32_t {
        ALLOW_LOCK_WHILE_SCREEN_ON = 0x00000001,
        DIM_BEHIND = 0x00000002,
        BLUR_BEHIND = 0x00000004,
        NOT_FOCUSABLE = 0x00000008,
        NOT_TOUCHABLE = 0x00000010,
        NOT_TOUCH_MODAL = 0x00000020,
        TOUCHABLE_WHEN_WAKING = 0x00000040,
        KEEP_SCREEN_ON = 0x00000080,
        LAYOUT_IN_SCREEN = 0x00000100,
        LAYOUT_NO_LIMITS = 0x00000200,
        FULLSCREEN = 0x00000400,
        FORCE_NOT_FULLSCREEN = 0x00000800,
        DITHER = 0x00001000,
        SECURE = 0x00002000,
        SCALED = 0x00004000,
        IGNORE_CHEEK_PRESSES = 0x00008000,
        LAYOUT_INSET_DECOR = 0x00010000,
        ALT_FOCUSABLE_IM = 0x00020000,
        WATCH_OUTSIDE_TOUCH = 0x00040000,
        SHOW_WHEN_LOCKED = 0x00080000,
        SHOW_WALLPAPER = 0x00100000,
        TURN_SCREEN_ON = 0x00200000,
        DISMISS_KEYGUARD = 0x00400000,
        SPLIT_TOUCH = 0x00800000,
        HARDWARE_ACCELERATED = 0x01000000,
        LAYOUT_IN_OVERSCAN = 0x02000000,
        TRANSLUCENT_STATUS = 0x04000000,
        TRANSLUCENT_NAVIGATION = 0x08000000,
        LOCAL_FOCUS_MODE = 0x10000000,
        SLIPPERY = 0x20000000,
        LAYOUT_ATTACHED_IN_DECOR = 0x40000000,
        DRAWS_SYSTEM_BAR_BACKGROUNDS = 0x80000000,
    }; // Window types from WindowManager.LayoutParams

    enum class Type : int32_t {
        UNKNOWN = 0,
        FIRST_APPLICATION_WINDOW = 1,
        BASE_APPLICATION = 1,
        APPLICATION = 2,
        APPLICATION_STARTING = 3,
        LAST_APPLICATION_WINDOW = 99,
        FIRST_SUB_WINDOW = 1000,
        APPLICATION_PANEL = FIRST_SUB_WINDOW,
        APPLICATION_MEDIA = FIRST_SUB_WINDOW + 1,
        APPLICATION_SUB_PANEL = FIRST_SUB_WINDOW + 2,
        APPLICATION_ATTACHED_DIALOG = FIRST_SUB_WINDOW + 3,
        APPLICATION_MEDIA_OVERLAY = FIRST_SUB_WINDOW + 4,
        LAST_SUB_WINDOW = 1999,
        FIRST_SYSTEM_WINDOW = 2000,
        STATUS_BAR = FIRST_SYSTEM_WINDOW,
        SEARCH_BAR = FIRST_SYSTEM_WINDOW + 1,
        PHONE = FIRST_SYSTEM_WINDOW + 2,
        SYSTEM_ALERT = FIRST_SYSTEM_WINDOW + 3,
        KEYGUARD = FIRST_SYSTEM_WINDOW + 4,
        TOAST = FIRST_SYSTEM_WINDOW + 5,
        SYSTEM_OVERLAY = FIRST_SYSTEM_WINDOW + 6,
        PRIORITY_PHONE = FIRST_SYSTEM_WINDOW + 7,
        SYSTEM_DIALOG = FIRST_SYSTEM_WINDOW + 8,
        KEYGUARD_DIALOG = FIRST_SYSTEM_WINDOW + 9,
        SYSTEM_ERROR = FIRST_SYSTEM_WINDOW + 10,
        INPUT_METHOD = FIRST_SYSTEM_WINDOW + 11,
        INPUT_METHOD_DIALOG = FIRST_SYSTEM_WINDOW + 12,
        WALLPAPER = FIRST_SYSTEM_WINDOW + 13,
        STATUS_BAR_PANEL = FIRST_SYSTEM_WINDOW + 14,
        SECURE_SYSTEM_OVERLAY = FIRST_SYSTEM_WINDOW + 15,
        DRAG = FIRST_SYSTEM_WINDOW + 16,
        STATUS_BAR_SUB_PANEL = FIRST_SYSTEM_WINDOW + 17,
        POINTER = FIRST_SYSTEM_WINDOW + 18,
        NAVIGATION_BAR = FIRST_SYSTEM_WINDOW + 19,
        VOLUME_OVERLAY = FIRST_SYSTEM_WINDOW + 20,
        BOOT_PROGRESS = FIRST_SYSTEM_WINDOW + 21,
        INPUT_CONSUMER = FIRST_SYSTEM_WINDOW + 22,
        NAVIGATION_BAR_PANEL = FIRST_SYSTEM_WINDOW + 24,
        MAGNIFICATION_OVERLAY = FIRST_SYSTEM_WINDOW + 27,
        ACCESSIBILITY_OVERLAY = FIRST_SYSTEM_WINDOW + 32,
        DOCK_DIVIDER = FIRST_SYSTEM_WINDOW + 34,
        ACCESSIBILITY_MAGNIFICATION_OVERLAY = FIRST_SYSTEM_WINDOW + 39,
        NOTIFICATION_SHADE = FIRST_SYSTEM_WINDOW + 40,
        LAST_SYSTEM_WINDOW = 2999,
    };

    enum class Feature {
        DISABLE_TOUCH_PAD_GESTURES = 1u << 0,
        NO_INPUT_CHANNEL = 1u << 1,
        DISABLE_USER_ACTIVITY = 1u << 2,
        DROP_INPUT = 1u << 3,
        DROP_INPUT_IF_OBSCURED = 1u << 4,
    };

    /* These values are filled in by the WM and passed through SurfaceFlinger
     * unless specified otherwise.
     */
    // This value should NOT be used to uniquely identify the window. There may be different
    // input windows that have the same token.
    sp<IBinder> token;

    // The token that identifies which client window this WindowInfo was created for.
    sp<IBinder> windowToken;

    // This uniquely identifies the input window.
    int32_t id = -1;
    std::string name;
    Flags<Flag> flags;
    Type type = Type::UNKNOWN;
    std::chrono::nanoseconds dispatchingTimeout = std::chrono::seconds(5);

    /* These values are filled in by SurfaceFlinger. */
    int32_t frameLeft = -1;
    int32_t frameTop = -1;
    int32_t frameRight = -1;
    int32_t frameBottom = -1;

    /*
     * SurfaceFlinger consumes this value to shrink the computed frame. This is
     * different from shrinking the touchable region in that it DOES shift the coordinate
     * space where-as the touchable region does not and is more like "cropping". This
     * is used for window shadows.
     */
    int32_t surfaceInset = 0;

    // A global scaling factor for all windows. Unlike windowScaleX/Y this results
    // in scaling of the TOUCH_MAJOR/TOUCH_MINOR axis.
    float globalScaleFactor = 1.0f;

    // The opacity of this window, from 0.0 to 1.0 (inclusive).
    // An alpha of 1.0 means fully opaque and 0.0 means fully transparent.
    float alpha;

    // Transform applied to individual windows.
    ui::Transform transform;

    // Display orientation as ui::Transform::RotationFlags. Used for compatibility raw coordinates.
    uint32_t displayOrientation = ui::Transform::ROT_0;

    // Display size in its natural rotation. Used to rotate raw coordinates for compatibility.
    int32_t displayWidth = 0;
    int32_t displayHeight = 0;

    /*
     * This is filled in by the WM relative to the frame and then translated
     * to absolute coordinates by SurfaceFlinger once the frame is computed.
     */
    Region touchableRegion;
    bool visible = false;
    bool focusable = false;
    bool hasWallpaper = false;
    bool paused = false;
    /* This flag is set when the window is of a trusted type that is allowed to silently
     * overlay other windows for the purpose of implementing the secure views feature.
     * Trusted overlays, such as IME windows, can partly obscure other windows without causing
     * motion events to be delivered to them with AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED.
     */
    bool trustedOverlay = false;
    TouchOcclusionMode touchOcclusionMode = TouchOcclusionMode::BLOCK_UNTRUSTED;
    int32_t ownerPid = -1;
    int32_t ownerUid = -1;
    std::string packageName;
    Flags<Feature> inputFeatures;
    int32_t displayId = ADISPLAY_ID_NONE;
    int32_t portalToDisplayId = ADISPLAY_ID_NONE;
    InputApplicationInfo applicationInfo;
    bool replaceTouchableRegionWithCrop = false;
    wp<IBinder> touchableRegionCropHandle;

    void addTouchableRegion(const Rect& region);

    bool touchableRegionContainsPoint(int32_t x, int32_t y) const;

    bool frameContainsPoint(int32_t x, int32_t y) const;

    bool supportsSplitTouch() const;

    bool overlaps(const WindowInfo* other) const;

    bool operator==(const WindowInfo& inputChannel) const;

    status_t writeToParcel(android::Parcel* parcel) const override;

    status_t readFromParcel(const android::Parcel* parcel) override;
};

/*
 * Handle for a window that can receive input.
 *
 * Used by the native input dispatcher to indirectly refer to the window manager objects
 * that describe a window.
 */
class WindowInfoHandle : public RefBase {
public:
    explicit WindowInfoHandle();
    WindowInfoHandle(const WindowInfoHandle& other);
    WindowInfoHandle(const WindowInfo& other);

    inline const WindowInfo* getInfo() const { return &mInfo; }

    sp<IBinder> getToken() const;

    int32_t getId() const { return mInfo.id; }

    sp<IBinder> getApplicationToken() { return mInfo.applicationInfo.token; }

    inline std::string getName() const { return !mInfo.name.empty() ? mInfo.name : "<invalid>"; }

    inline std::chrono::nanoseconds getDispatchingTimeout(
            std::chrono::nanoseconds defaultValue) const {
        return mInfo.token ? std::chrono::nanoseconds(mInfo.dispatchingTimeout) : defaultValue;
    }

    /**
     * Updates from another input window handle.
     */
    void updateFrom(const sp<WindowInfoHandle> handle);

    /**
     * Releases the channel used by the associated information when it is
     * no longer needed.
     */
    void releaseChannel();

    // Not override since this class is not derrived from Parcelable.
    status_t readFromParcel(const android::Parcel* parcel);
    status_t writeToParcel(android::Parcel* parcel) const;

protected:
    virtual ~WindowInfoHandle();

    WindowInfo mInfo;
};
} // namespace android::gui