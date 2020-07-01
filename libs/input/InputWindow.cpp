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

#include <type_traits>
#define LOG_TAG "InputWindow"
#define LOG_NDEBUG 0

#include <android-base/stringprintf.h>
#include <binder/Parcel.h>
#include <input/InputTransport.h>
#include <input/InputWindow.h>

#include <log/log.h>

namespace android {


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
    return flags.test(Flag::SPLIT_TOUCH);
}

bool InputWindowInfo::overlaps(const InputWindowInfo* other) const {
    return frameLeft < other->frameRight && frameRight > other->frameLeft
            && frameTop < other->frameBottom && frameBottom > other->frameTop;
}

bool InputWindowInfo::operator==(const InputWindowInfo& info) const {
    return info.token == token && info.id == id && info.name == name && info.flags == flags &&
            info.type == type && info.dispatchingTimeout == dispatchingTimeout &&
            info.frameLeft == frameLeft && info.frameTop == frameTop &&
            info.frameRight == frameRight && info.frameBottom == frameBottom &&
            info.surfaceInset == surfaceInset && info.globalScaleFactor == globalScaleFactor &&
            info.transform == transform &&
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
        parcel->writeInt32(flags.get()) ?:
        parcel->writeInt32(static_cast<std::underlying_type_t<InputWindowInfo::Type>>(type)) ?:
        parcel->writeInt32(frameLeft) ?:
        parcel->writeInt32(frameTop) ?:
        parcel->writeInt32(frameRight) ?:
        parcel->writeInt32(frameBottom) ?:
        parcel->writeInt32(surfaceInset) ?:
        parcel->writeFloat(globalScaleFactor) ?:
        parcel->writeFloat(transform.dsdx()) ?:
        parcel->writeFloat(transform.dtdx()) ?:
        parcel->writeFloat(transform.tx()) ?:
        parcel->writeFloat(transform.dtdy()) ?:
        parcel->writeFloat(transform.dsdy()) ?:
        parcel->writeFloat(transform.ty()) ?:
        parcel->writeBool(visible) ?:
        parcel->writeBool(canReceiveKeys) ?:
        parcel->writeBool(hasFocus) ?:
        parcel->writeBool(hasWallpaper) ?:
        parcel->writeBool(paused) ?:
        parcel->writeBool(trustedOverlay) ?:
        parcel->writeInt32(ownerPid) ?:
        parcel->writeInt32(ownerUid) ?:
        parcel->writeInt32(inputFeatures.get()) ?:
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
    dispatchingTimeout = static_cast<decltype(dispatchingTimeout)>(parcel->readInt64());
    status_t status = parcel->readInt32(&id) ?: parcel->readUtf8FromUtf16(&name);
    if (status != OK) {
        return status;
    }

    flags = Flags<Flag>(parcel->readInt32());
    type = static_cast<Type>(parcel->readInt32());
    float dsdx, dtdx, tx, dtdy, dsdy, ty;
    status = parcel->readInt32(&frameLeft) ?:
        parcel->readInt32(&frameTop) ?:
        parcel->readInt32(&frameRight) ?:
        parcel->readInt32(&frameBottom) ?:
        parcel->readInt32(&surfaceInset) ?:
        parcel->readFloat(&globalScaleFactor) ?:
        parcel->readFloat(&dsdx) ?:
        parcel->readFloat(&dtdx) ?:
        parcel->readFloat(&tx) ?:
        parcel->readFloat(&dtdy) ?:
        parcel->readFloat(&dsdy) ?:
        parcel->readFloat(&ty) ?:
        parcel->readBool(&visible) ?:
        parcel->readBool(&canReceiveKeys) ?:
        parcel->readBool(&hasFocus) ?:
        parcel->readBool(&hasWallpaper) ?:
        parcel->readBool(&paused) ?:
        parcel->readBool(&trustedOverlay) ?:
        parcel->readInt32(&ownerPid) ?:
        parcel->readInt32(&ownerUid);

    if (status != OK) {
        return status;
    }

    inputFeatures = Flags<Feature>(parcel->readInt32());
    status = parcel->readInt32(&displayId) ?:
        parcel->readInt32(&portalToDisplayId) ?:
        applicationInfo.readFromParcel(parcel) ?:
        parcel->read(touchableRegion) ?:
        parcel->readBool(&replaceTouchableRegionWithCrop);

    if (status != OK) {
        return status;
    }

    touchableRegionCropHandle = parcel->readStrongBinder();
    transform.set(std::array<float, 9>{dsdx, dtdx, tx, dtdy, dsdy, ty, 0, 0, 1});

    return OK;
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

std::optional<std::string> InputWindowInfo::flagToString(Flag flag) {
    switch (flag) {
        case InputWindowInfo::Flag::ALLOW_LOCK_WHILE_SCREEN_ON: {
            return "ALLOW_LOCK_WHILE_SCREEN_ON";
        }
        case InputWindowInfo::Flag::DIM_BEHIND: {
            return "DIM_BEHIND";
        }
        case InputWindowInfo::Flag::BLUR_BEHIND: {
            return "BLUR_BEHIND";
        }
        case InputWindowInfo::Flag::NOT_FOCUSABLE: {
            return "NOT_FOCUSABLE";
        }
        case InputWindowInfo::Flag::NOT_TOUCHABLE: {
            return "NOT_TOUCHABLE";
        }
        case InputWindowInfo::Flag::NOT_TOUCH_MODAL: {
            return "NOT_TOUCH_MODAL";
        }
        case InputWindowInfo::Flag::TOUCHABLE_WHEN_WAKING: {
            return "TOUCHABLE_WHEN_WAKING";
        }
        case InputWindowInfo::Flag::KEEP_SCREEN_ON: {
            return "KEEP_SCREEN_ON";
        }
        case InputWindowInfo::Flag::LAYOUT_IN_SCREEN: {
            return "LAYOUT_IN_SCREEN";
        }
        case InputWindowInfo::Flag::LAYOUT_NO_LIMITS: {
            return "LAYOUT_NO_LIMITS";
        }
        case InputWindowInfo::Flag::FULLSCREEN: {
            return "FULLSCREEN";
        }
        case InputWindowInfo::Flag::FORCE_NOT_FULLSCREEN: {
            return "FORCE_NOT_FULLSCREEN";
        }
        case InputWindowInfo::Flag::DITHER: {
            return "DITHER";
        }
        case InputWindowInfo::Flag::SECURE: {
            return "SECURE";
        }
        case InputWindowInfo::Flag::SCALED: {
            return "SCALED";
        }
        case InputWindowInfo::Flag::IGNORE_CHEEK_PRESSES: {
            return "IGNORE_CHEEK_PRESSES";
        }
        case InputWindowInfo::Flag::LAYOUT_INSET_DECOR: {
            return "LAYOUT_INSET_DECOR";
        }
        case InputWindowInfo::Flag::ALT_FOCUSABLE_IM: {
            return "ALT_FOCUSABLE_IM";
        }
        case InputWindowInfo::Flag::WATCH_OUTSIDE_TOUCH: {
            return "WATCH_OUTSIDE_TOUCH";
        }
        case InputWindowInfo::Flag::SHOW_WHEN_LOCKED: {
            return "SHOW_WHEN_LOCKED";
        }
        case InputWindowInfo::Flag::SHOW_WALLPAPER: {
            return "SHOW_WALLPAPER";
        }
        case InputWindowInfo::Flag::TURN_SCREEN_ON: {
            return "TURN_SCREEN_ON";
        }
        case InputWindowInfo::Flag::DISMISS_KEYGUARD: {
            return "DISMISS_KEYGUARD";
        }
        case InputWindowInfo::Flag::SPLIT_TOUCH: {
            return "SPLIT_TOUCH";
        }
        case InputWindowInfo::Flag::HARDWARE_ACCELERATED: {
            return "HARDWARE_ACCELERATED";
        }
        case InputWindowInfo::Flag::LAYOUT_IN_OVERSCAN: {
            return "LAYOUT_IN_OVERSCAN";
        }
        case InputWindowInfo::Flag::TRANSLUCENT_STATUS: {
            return "TRANSLUCENT_STATUS";
        }
        case InputWindowInfo::Flag::TRANSLUCENT_NAVIGATION: {
            return "TRANSLUCENT_NAVIGATION";
        }
        case InputWindowInfo::Flag::LOCAL_FOCUS_MODE: {
            return "LOCAL_FOCUS_MODE";
        }
        case InputWindowInfo::Flag::SLIPPERY: {
            return "SLIPPERY";
        }
        case InputWindowInfo::Flag::LAYOUT_ATTACHED_IN_DECOR: {
            return "LAYOUT_ATTACHED_IN_DECOR";
        }
        case InputWindowInfo::Flag::DRAWS_SYSTEM_BAR_BACKGROUNDS: {
            return "DRAWS_SYSTEM_BAR_BACKGROUNDS";
        }
    }
    return std::nullopt;
}

} // namespace android
