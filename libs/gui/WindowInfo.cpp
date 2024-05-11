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

#define LOG_TAG "WindowInfo"
#define LOG_NDEBUG 0

#include <type_traits>

#include <binder/Parcel.h>
#include <gui/WindowInfo.h>

#include <log/log.h>

namespace android::gui {

namespace {

std::ostream& operator<<(std::ostream& out, const sp<IBinder>& binder) {
    if (binder == nullptr) {
        out << "<null>";
    } else {
        out << binder.get();
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const Region& region) {
    if (region.isEmpty()) {
        out << "<empty>";
        return out;
    }

    bool first = true;
    Region::const_iterator cur = region.begin();
    Region::const_iterator const tail = region.end();
    while (cur != tail) {
        if (first) {
            first = false;
        } else {
            out << "|";
        }
        out << "[" << cur->left << "," << cur->top << "][" << cur->right << "," << cur->bottom
            << "]";
        cur++;
    }
    return out;
}

} // namespace

void WindowInfo::setInputConfig(ftl::Flags<InputConfig> config, bool value) {
    if (value) {
        inputConfig |= config;
        return;
    }
    inputConfig &= ~config;
}

void WindowInfo::addTouchableRegion(const Rect& region) {
    touchableRegion.orSelf(region);
}

bool WindowInfo::supportsSplitTouch() const {
    return !inputConfig.test(InputConfig::PREVENT_SPLITTING);
}

bool WindowInfo::isSpy() const {
    return inputConfig.test(InputConfig::SPY);
}

bool WindowInfo::interceptsStylus() const {
    return inputConfig.test(InputConfig::INTERCEPTS_STYLUS);
}

bool WindowInfo::overlaps(const WindowInfo* other) const {
    return !frame.isEmpty() && frame.left < other->frame.right && frame.right > other->frame.left &&
            frame.top < other->frame.bottom && frame.bottom > other->frame.top;
}

bool WindowInfo::operator==(const WindowInfo& info) const {
    return info.token == token && info.id == id && info.name == name &&
            info.dispatchingTimeout == dispatchingTimeout && info.frame == frame &&
            info.contentSize == contentSize && info.surfaceInset == surfaceInset &&
            info.globalScaleFactor == globalScaleFactor && info.transform == transform &&
            info.touchableRegion.hasSameRects(touchableRegion) &&
            info.touchOcclusionMode == touchOcclusionMode && info.ownerPid == ownerPid &&
            info.ownerUid == ownerUid && info.packageName == packageName &&
            info.inputConfig == inputConfig && info.displayId == displayId &&
            info.replaceTouchableRegionWithCrop == replaceTouchableRegionWithCrop &&
            info.applicationInfo == applicationInfo && info.layoutParamsType == layoutParamsType &&
            info.layoutParamsFlags == layoutParamsFlags &&
            info.canOccludePresentation == canOccludePresentation;
}

status_t WindowInfo::writeToParcel(android::Parcel* parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }
    if (name.empty()) {
        parcel->writeInt32(0);
        return OK;
    }
    parcel->writeInt32(1);

    // Ensure that the size of custom types are what we expect for writing into the parcel.
    static_assert(sizeof(inputConfig) == 4u);
    static_assert(sizeof(ownerPid.val()) == 4u);
    static_assert(sizeof(ownerUid.val()) == 4u);

    // clang-format off
    status_t status = parcel->writeStrongBinder(token) ?:
        parcel->writeInt64(dispatchingTimeout.count()) ?:
        parcel->writeInt32(id) ?:
        parcel->writeUtf8AsUtf16(name) ?:
        parcel->writeInt32(layoutParamsFlags.get()) ?:
        parcel->writeInt32(
                static_cast<std::underlying_type_t<WindowInfo::Type>>(layoutParamsType)) ?:
        parcel->write(frame) ?:
        parcel->writeInt32(contentSize.width) ?:
        parcel->writeInt32(contentSize.height) ?:
        parcel->writeInt32(surfaceInset) ?:
        parcel->writeFloat(globalScaleFactor) ?:
        parcel->writeFloat(alpha) ?:
        parcel->writeFloat(transform.dsdx()) ?:
        parcel->writeFloat(transform.dtdx()) ?:
        parcel->writeFloat(transform.tx()) ?:
        parcel->writeFloat(transform.dtdy()) ?:
        parcel->writeFloat(transform.dsdy()) ?:
        parcel->writeFloat(transform.ty()) ?:
        parcel->writeInt32(static_cast<int32_t>(touchOcclusionMode)) ?:
        parcel->writeInt32(ownerPid.val()) ?:
        parcel->writeInt32(ownerUid.val()) ?:
        parcel->writeUtf8AsUtf16(packageName) ?:
        parcel->writeInt32(inputConfig.get()) ?:
        parcel->writeInt32(displayId.val()) ?:
        applicationInfo.writeToParcel(parcel) ?:
        parcel->write(touchableRegion) ?:
        parcel->writeBool(replaceTouchableRegionWithCrop) ?:
        parcel->writeStrongBinder(touchableRegionCropHandle.promote()) ?:
        parcel->writeStrongBinder(windowToken) ?:
        parcel->writeStrongBinder(focusTransferTarget) ?:
        parcel->writeBool(canOccludePresentation);
    // clang-format on
    return status;
}

status_t WindowInfo::readFromParcel(const android::Parcel* parcel) {
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

    float dsdx, dtdx, tx, dtdy, dsdy, ty;
    int32_t lpFlags, lpType, touchOcclusionModeInt, inputConfigInt, ownerPidInt, ownerUidInt,
            displayIdInt;
    sp<IBinder> touchableRegionCropHandleSp;

    // clang-format off
    status = parcel->readInt32(&lpFlags) ?:
        parcel->readInt32(&lpType) ?:
        parcel->read(frame) ?:
        parcel->readInt32(&contentSize.width) ?:
        parcel->readInt32(&contentSize.height) ?:
        parcel->readInt32(&surfaceInset) ?:
        parcel->readFloat(&globalScaleFactor) ?:
        parcel->readFloat(&alpha) ?:
        parcel->readFloat(&dsdx) ?:
        parcel->readFloat(&dtdx) ?:
        parcel->readFloat(&tx) ?:
        parcel->readFloat(&dtdy) ?:
        parcel->readFloat(&dsdy) ?:
        parcel->readFloat(&ty) ?:
        parcel->readInt32(&touchOcclusionModeInt) ?:
        parcel->readInt32(&ownerPidInt) ?:
        parcel->readInt32(&ownerUidInt) ?:
        parcel->readUtf8FromUtf16(&packageName) ?:
        parcel->readInt32(&inputConfigInt) ?:
        parcel->readInt32(&displayIdInt) ?:
        applicationInfo.readFromParcel(parcel) ?:
        parcel->read(touchableRegion) ?:
        parcel->readBool(&replaceTouchableRegionWithCrop) ?:
        parcel->readNullableStrongBinder(&touchableRegionCropHandleSp) ?:
        parcel->readNullableStrongBinder(&windowToken) ?:
        parcel->readNullableStrongBinder(&focusTransferTarget) ?:
        parcel->readBool(&canOccludePresentation);

    // clang-format on

    if (status != OK) {
        return status;
    }

    layoutParamsFlags = ftl::Flags<Flag>(lpFlags);
    layoutParamsType = static_cast<Type>(lpType);
    transform.set({dsdx, dtdx, tx, dtdy, dsdy, ty, 0, 0, 1});
    touchOcclusionMode = static_cast<TouchOcclusionMode>(touchOcclusionModeInt);
    inputConfig = ftl::Flags<InputConfig>(inputConfigInt);
    ownerPid = Pid{ownerPidInt};
    ownerUid = Uid{static_cast<uid_t>(ownerUidInt)};
    touchableRegionCropHandle = touchableRegionCropHandleSp;
    displayId = ui::LogicalDisplayId{displayIdInt};

    return OK;
}

WindowInfoHandle::WindowInfoHandle() {}

WindowInfoHandle::~WindowInfoHandle() {}

WindowInfoHandle::WindowInfoHandle(const WindowInfoHandle& other) : mInfo(other.mInfo) {}

WindowInfoHandle::WindowInfoHandle(const WindowInfo& other) : mInfo(other) {}

status_t WindowInfoHandle::writeToParcel(android::Parcel* parcel) const {
    return mInfo.writeToParcel(parcel);
}

status_t WindowInfoHandle::readFromParcel(const android::Parcel* parcel) {
    return mInfo.readFromParcel(parcel);
}

void WindowInfoHandle::releaseChannel() {
    mInfo.token.clear();
}

sp<IBinder> WindowInfoHandle::getToken() const {
    return mInfo.token;
}

void WindowInfoHandle::updateFrom(sp<WindowInfoHandle> handle) {
    mInfo = handle->mInfo;
}

std::ostream& operator<<(std::ostream& out, const WindowInfo& info) {
    out << "name=" << info.name << ", id=" << info.id << ", displayId=" << info.displayId
        << ", inputConfig=" << info.inputConfig.string() << ", alpha=" << info.alpha << ", frame=["
        << info.frame.left << "," << info.frame.top << "][" << info.frame.right << ","
        << info.frame.bottom << "], globalScale=" << info.globalScaleFactor
        << ", applicationInfo.name=" << info.applicationInfo.name
        << ", applicationInfo.token=" << info.applicationInfo.token
        << ", touchableRegion=" << info.touchableRegion << ", ownerPid=" << info.ownerPid.toString()
        << ", ownerUid=" << info.ownerUid.toString() << ", dispatchingTimeout="
        << std::chrono::duration_cast<std::chrono::milliseconds>(info.dispatchingTimeout).count()
        << "ms, token=" << info.token.get()
        << ", touchOcclusionMode=" << ftl::enum_string(info.touchOcclusionMode);
    if (info.canOccludePresentation) out << ", canOccludePresentation";
    std::string transform;
    info.transform.dump(transform, "transform", "    ");
    out << "\n" << transform;
    return out;
}

std::ostream& operator<<(std::ostream& out, const WindowInfoHandle& window) {
    const WindowInfo& info = *window.getInfo();
    out << info;
    return out;
}

} // namespace android::gui
