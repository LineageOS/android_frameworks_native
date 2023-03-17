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

#include "FakePointerController.h"

#include <gtest/gtest.h>

namespace android {

void FakePointerController::setBounds(float minX, float minY, float maxX, float maxY) {
    mHaveBounds = true;
    mMinX = minX;
    mMinY = minY;
    mMaxX = maxX;
    mMaxY = maxY;
}

const std::map<int32_t, std::vector<int32_t>>& FakePointerController::getSpots() {
    return mSpotsByDisplay;
}

void FakePointerController::setPosition(float x, float y) {
    mX = x;
    mY = y;
}

FloatPoint FakePointerController::getPosition() const {
    return {mX, mY};
}

int32_t FakePointerController::getDisplayId() const {
    return mDisplayId;
}

void FakePointerController::setDisplayViewport(const DisplayViewport& viewport) {
    mDisplayId = viewport.displayId;
}

void FakePointerController::assertPosition(float x, float y) {
    const auto [actualX, actualY] = getPosition();
    ASSERT_NEAR(x, actualX, 1);
    ASSERT_NEAR(y, actualY, 1);
}

bool FakePointerController::isPointerShown() {
    return mIsPointerShown;
}

std::optional<FloatRect> FakePointerController::getBounds() const {
    return mHaveBounds ? std::make_optional<FloatRect>(mMinX, mMinY, mMaxX, mMaxY) : std::nullopt;
}

void FakePointerController::move(float deltaX, float deltaY) {
    mX += deltaX;
    if (mX < mMinX) mX = mMinX;
    if (mX > mMaxX) mX = mMaxX;
    mY += deltaY;
    if (mY < mMinY) mY = mMinY;
    if (mY > mMaxY) mY = mMaxY;
}

void FakePointerController::fade(Transition) {
    mIsPointerShown = false;
}
void FakePointerController::unfade(Transition) {
    mIsPointerShown = true;
}

void FakePointerController::setSpots(const PointerCoords*, const uint32_t*, BitSet32 spotIdBits,
                                     int32_t displayId) {
    std::vector<int32_t> newSpots;
    // Add spots for fingers that are down.
    for (BitSet32 idBits(spotIdBits); !idBits.isEmpty();) {
        uint32_t id = idBits.clearFirstMarkedBit();
        newSpots.push_back(id);
    }

    mSpotsByDisplay[displayId] = newSpots;
}

void FakePointerController::clearSpots() {
    mSpotsByDisplay.clear();
}

} // namespace android
