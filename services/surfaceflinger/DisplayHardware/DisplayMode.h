/*
 * Copyright 2020 The Android Open Source Project
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

#include "DisplayHardware/Hal.h"
#include "Scheduler/StrongTyping.h"

#include <android/configuration.h>
#include <utils/Timers.h>

#include <cstddef>
#include <memory>
#include <vector>

namespace android {

namespace hal = android::hardware::graphics::composer::hal;

class DisplayMode;
using DisplayModePtr = std::shared_ptr<const DisplayMode>;
using DisplayModes = std::vector<DisplayModePtr>;
using DisplayModeId = StrongTyping<size_t, struct DisplayModeIdTag, Compare, Hash>;

class DisplayMode {
public:
    class Builder {
    public:
        explicit Builder(hal::HWConfigId id) : mDisplayMode(new DisplayMode(id)) {}

        DisplayModePtr build() {
            return std::const_pointer_cast<const DisplayMode>(std::move(mDisplayMode));
        }

        Builder& setId(DisplayModeId id) {
            mDisplayMode->mId = id;
            return *this;
        }

        Builder& setWidth(int32_t width) {
            mDisplayMode->mWidth = width;
            return *this;
        }

        Builder& setHeight(int32_t height) {
            mDisplayMode->mHeight = height;
            return *this;
        }

        Builder& setVsyncPeriod(int32_t vsyncPeriod) {
            mDisplayMode->mVsyncPeriod = vsyncPeriod;
            return *this;
        }

        Builder& setDpiX(int32_t dpiX) {
            if (dpiX == -1) {
                mDisplayMode->mDpiX = getDefaultDensity();
            } else {
                mDisplayMode->mDpiX = dpiX / 1000.0f;
            }
            return *this;
        }

        Builder& setDpiY(int32_t dpiY) {
            if (dpiY == -1) {
                mDisplayMode->mDpiY = getDefaultDensity();
            } else {
                mDisplayMode->mDpiY = dpiY / 1000.0f;
            }
            return *this;
        }

        Builder& setConfigGroup(int32_t configGroup) {
            mDisplayMode->mConfigGroup = configGroup;
            return *this;
        }

    private:
        float getDefaultDensity() {
            // Default density is based on TVs: 1080p displays get XHIGH density, lower-
            // resolution displays get TV density. Maybe eventually we'll need to update
            // it for 4k displays, though hopefully those will just report accurate DPI
            // information to begin with. This is also used for virtual displays and
            // older HWC implementations, so be careful about orientation.

            auto longDimension = std::max(mDisplayMode->mWidth, mDisplayMode->mHeight);
            if (longDimension >= 1080) {
                return ACONFIGURATION_DENSITY_XHIGH;
            } else {
                return ACONFIGURATION_DENSITY_TV;
            }
        }
        std::shared_ptr<DisplayMode> mDisplayMode;
    };

    DisplayModeId getId() const { return mId; }
    hal::HWConfigId getHwcId() const { return mHwcId; }

    int32_t getWidth() const { return mWidth; }
    int32_t getHeight() const { return mHeight; }
    nsecs_t getVsyncPeriod() const { return mVsyncPeriod; }
    float getDpiX() const { return mDpiX; }
    float getDpiY() const { return mDpiY; }
    int32_t getConfigGroup() const { return mConfigGroup; }

private:
    explicit DisplayMode(hal::HWConfigId id) : mHwcId(id) {}

    hal::HWConfigId mHwcId;
    DisplayModeId mId;

    int32_t mWidth = -1;
    int32_t mHeight = -1;
    nsecs_t mVsyncPeriod = -1;
    float mDpiX = -1;
    float mDpiY = -1;
    int32_t mConfigGroup = -1;
};

} // namespace android