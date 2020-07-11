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

#define LOG_TAG "InputWindow"
#define LOG_NDEBUG 0

#include <android-base/stringprintf.h>
#include <binder/Parcel.h>
#include <input/InputTransport.h>
#include <input/InputWindow.h>

#include <log/log.h>

namespace android {

const char* inputWindowFlagToString(uint32_t flag) {
    switch (flag) {
        case InputWindowInfo::FLAG_ALLOW_LOCK_WHILE_SCREEN_ON: {
            return "ALLOW_LOCK_WHILE_SCREEN_ON";
        }
        case InputWindowInfo::FLAG_DIM_BEHIND: {
            return "DIM_BEHIND";
        }
        case InputWindowInfo::FLAG_BLUR_BEHIND: {
            return "BLUR_BEHIND";
        }
        case InputWindowInfo::FLAG_NOT_FOCUSABLE: {
            return "NOT_FOCUSABLE";
        }
        case InputWindowInfo::FLAG_NOT_TOUCHABLE: {
            return "NOT_TOUCHABLE";
        }
        case InputWindowInfo::FLAG_NOT_TOUCH_MODAL: {
            return "NOT_TOUCH_MODAL";
        }
        case InputWindowInfo::FLAG_TOUCHABLE_WHEN_WAKING: {
            return "TOUCHABLE_WHEN_WAKING";
        }
        case InputWindowInfo::FLAG_KEEP_SCREEN_ON: {
            return "KEEP_SCREEN_ON";
        }
        case InputWindowInfo::FLAG_LAYOUT_IN_SCREEN: {
            return "LAYOUT_IN_SCREEN";
        }
        case InputWindowInfo::FLAG_LAYOUT_NO_LIMITS: {
            return "LAYOUT_NO_LIMITS";
        }
        case InputWindowInfo::FLAG_FULLSCREEN: {
            return "FULLSCREEN";
        }
        case InputWindowInfo::FLAG_FORCE_NOT_FULLSCREEN: {
            return "FORCE_NOT_FULLSCREEN";
        }
        case InputWindowInfo::FLAG_DITHER: {
            return "DITHER";
        }
        case InputWindowInfo::FLAG_SECURE: {
            return "SECURE";
        }
        case InputWindowInfo::FLAG_SCALED: {
            return "SCALED";
        }
        case InputWindowInfo::FLAG_IGNORE_CHEEK_PRESSES: {
            return "IGNORE_CHEEK_PRESSES";
        }
        case InputWindowInfo::FLAG_LAYOUT_INSET_DECOR: {
            return "LAYOUT_INSET_DECOR";
        }
        case InputWindowInfo::FLAG_ALT_FOCUSABLE_IM: {
            return "ALT_FOCUSABLE_IM";
        }
        case InputWindowInfo::FLAG_WATCH_OUTSIDE_TOUCH: {
            return "WATCH_OUTSIDE_TOUCH";
        }
        case InputWindowInfo::FLAG_SHOW_WHEN_LOCKED: {
            return "SHOW_WHEN_LOCKED";
        }
        case InputWindowInfo::FLAG_SHOW_WALLPAPER: {
            return "SHOW_WALLPAPER";
        }
        case InputWindowInfo::FLAG_TURN_SCREEN_ON: {
            return "TURN_SCREEN_ON";
        }
        case InputWindowInfo::FLAG_DISMISS_KEYGUARD: {
            return "DISMISS_KEYGUARD";
        }
        case InputWindowInfo::FLAG_SPLIT_TOUCH: {
            return "SPLIT_TOUCH";
        }
        case InputWindowInfo::FLAG_HARDWARE_ACCELERATED: {
            return "HARDWARE_ACCELERATED";
        }
        case InputWindowInfo::FLAG_LAYOUT_IN_OVERSCAN: {
            return "LAYOUT_IN_OVERSCAN";
        }
        case InputWindowInfo::FLAG_TRANSLUCENT_STATUS: {
            return "TRANSLUCENT_STATUS";
        }
        case InputWindowInfo::FLAG_TRANSLUCENT_NAVIGATION: {
            return "TRANSLUCENT_NAVIGATION";
        }
        case InputWindowInfo::FLAG_LOCAL_FOCUS_MODE: {
            return "LOCAL_FOCUS_MODE";
        }
        case InputWindowInfo::FLAG_SLIPPERY: {
            return "SLIPPERY";
        }
        case InputWindowInfo::FLAG_LAYOUT_ATTACHED_IN_DECOR: {
            return "LAYOUT_ATTACHED_IN_DECOR";
        }
        case InputWindowInfo::FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS: {
            return "DRAWS_SYSTEM_BAR_BACKGROUNDS";
        }
    }
    return "UNKNOWN";
}

std::string inputWindowFlagsToString(uint32_t flags) {
    std::string result;
    for (BitSet32 bits(flags); !bits.isEmpty();) {
        uint32_t bit = bits.clearLastMarkedBit(); // counts from left
        const uint32_t flag = 1 << (32 - bit - 1);
        result += android::base::StringPrintf("%s | ", inputWindowFlagToString(flag));
    }
    return result;
}

// --- InputWindowInfo ---
void InputWindowInfo::addTouchableRegion(const Rect& region) {
    touchableRegion.orSelf(region);
}

bool InputWindowInfo::touchableRegionContainsPoint(int32_t x, int32_t y) const {
    return touchableRegion.contains(x,y);
}

bool InputWindowInfo::frameContainsPoint(int32_t x, int32_t y) const {
    return x >= frameLeft && x < frameRight
            && y >= frameTop && y < frameBottom;
}

bool InputWindowInfo::supportsSplitTouch() const {
    return layoutParamsFlags & FLAG_SPLIT_TOUCH;
}

bool InputWindowInfo::overlaps(const InputWindowInfo* other) const {
    return frameLeft < other->frameRight && frameRight > other->frameLeft
            && frameTop < other->frameBottom && frameBottom > other->frameTop;
}

bool InputWindowInfo::operator==(const InputWindowInfo& info) const {
    return info.token == token && info.id == id && info.name == name &&
            info.layoutParamsFlags == layoutParamsFlags &&
            info.layoutParamsType == layoutParamsType &&
            info.dispatchingTimeout == dispatchingTimeout && info.frameLeft == frameLeft &&
            info.frameTop == frameTop && info.frameRight == frameRight &&
            info.frameBottom == frameBottom && info.surfaceInset == surfaceInset &&
            info.globalScaleFactor == globalScaleFactor && info.windowXScale == windowXScale &&
            info.windowYScale == windowYScale &&
            info.touchableRegion.hasSameRects(touchableRegion) && info.visible == visible &&
            info.canReceiveKeys == canReceiveKeys && info.trustedOverlay == trustedOverlay &&
            info.hasFocus == hasFocus && info.hasWallpaper == hasWallpaper &&
            info.paused == paused && info.ownerPid == ownerPid && info.ownerUid == ownerUid &&
            info.inputFeatures == inputFeatures && info.displayId == displayId &&
            info.portalToDisplayId == portalToDisplayId &&
            info.replaceTouchableRegionWithCrop == replaceTouchableRegionWithCrop &&
            info.applicationInfo.name == applicationInfo.name &&
            info.applicationInfo.token == applicationInfo.token &&
            info.applicationInfo.dispatchingTimeout == applicationInfo.dispatchingTimeout;
}

status_t InputWindowInfo::writeToParcel(android::Parcel* parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }
    if (name.empty()) {
        parcel->writeInt32(0);
        return OK;
    }
    parcel->writeInt32(1);

    status_t status = parcel->writeStrongBinder(token) ?:
        parcel->writeInt64(dispatchingTimeout.count()) ?:
        parcel->writeInt32(id) ?:
        parcel->writeUtf8AsUtf16(name) ?:
        parcel->writeInt32(layoutParamsFlags) ?:
        parcel->writeInt32(layoutParamsType) ?:
        parcel->writeInt32(frameLeft) ?:
        parcel->writeInt32(frameTop) ?:
        parcel->writeInt32(frameRight) ?:
        parcel->writeInt32(frameBottom) ?:
        parcel->writeInt32(surfaceInset) ?:
        parcel->writeFloat(globalScaleFactor) ?:
        parcel->writeFloat(windowXScale) ?:
        parcel->writeFloat(windowYScale) ?:
        parcel->writeBool(visible) ?:
        parcel->writeBool(canReceiveKeys) ?:
        parcel->writeBool(hasFocus) ?:
        parcel->writeBool(hasWallpaper) ?:
        parcel->writeBool(paused) ?:
        parcel->writeBool(trustedOverlay) ?:
        parcel->writeInt32(ownerPid) ?:
        parcel->writeInt32(ownerUid) ?:
        parcel->writeInt32(inputFeatures) ?:
        parcel->writeInt32(displayId) ?:
        parcel->writeInt32(portalToDisplayId) ?:
        applicationInfo.writeToParcel(parcel) ?:
        parcel->write(touchableRegion) ?:
        parcel->writeBool(replaceTouchableRegionWithCrop) ?:
        parcel->writeStrongBinder(touchableRegionCropHandle.promote());

    return status;
}

status_t InputWindowInfo::readFromParcel(const android::Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }
    if (parcel->readInt32() == 0) {
        return OK;
    }

    token = parcel->readStrongBinder();
    dispatchingTimeout = decltype(dispatchingTimeout)(parcel->readInt64());
    status_t status = parcel->readInt32(&id) ?:
        parcel->readUtf8FromUtf16(&name) ?:
        parcel->readInt32(&layoutParamsFlags) ?:
        parcel->readInt32(&layoutParamsType) ?:
        parcel->readInt32(&frameLeft) ?:
        parcel->readInt32(&frameTop) ?:
        parcel->readInt32(&frameRight) ?:
        parcel->readInt32(&frameBottom) ?:
        parcel->readInt32(&surfaceInset) ?:
        parcel->readFloat(&globalScaleFactor) ?:
        parcel->readFloat(&windowXScale) ?:
        parcel->readFloat(&windowYScale) ?:
        parcel->readBool(&visible) ?:
        parcel->readBool(&canReceiveKeys) ?:
        parcel->readBool(&hasFocus) ?:
        parcel->readBool(&hasWallpaper) ?:
        parcel->readBool(&paused) ?:
        parcel->readBool(&trustedOverlay) ?:
        parcel->readInt32(&ownerPid) ?:
        parcel->readInt32(&ownerUid) ?:
        parcel->readInt32(&inputFeatures) ?:
        parcel->readInt32(&displayId) ?:
        parcel->readInt32(&portalToDisplayId) ?:
        applicationInfo.readFromParcel(parcel) ?:
        parcel->read(touchableRegion) ?:
        parcel->readBool(&replaceTouchableRegionWithCrop);

    touchableRegionCropHandle = parcel->readStrongBinder();

    return status;
}

// --- InputWindowHandle ---

InputWindowHandle::InputWindowHandle() {}

InputWindowHandle::~InputWindowHandle() {}

InputWindowHandle::InputWindowHandle(const InputWindowHandle& other) : mInfo(other.mInfo) {}

InputWindowHandle::InputWindowHandle(const InputWindowInfo& other) : mInfo(other) {}

status_t InputWindowHandle::writeToParcel(android::Parcel* parcel) const {
    return mInfo.writeToParcel(parcel);
}

status_t InputWindowHandle::readFromParcel(const android::Parcel* parcel) {
    return mInfo.readFromParcel(parcel);
}

void InputWindowHandle::releaseChannel() {
    mInfo.token.clear();
}

sp<IBinder> InputWindowHandle::getToken() const {
    return mInfo.token;
}

void InputWindowHandle::updateFrom(sp<InputWindowHandle> handle) {
    mInfo = handle->mInfo;
}

} // namespace android
