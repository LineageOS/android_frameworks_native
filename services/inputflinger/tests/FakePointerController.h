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

#pragma once

#include <PointerControllerInterface.h>
#include <input/DisplayViewport.h>
#include <input/Input.h>
#include <utils/BitSet.h>
#include <unordered_set>

namespace android {

struct SpriteIcon {
    PointerIconStyle style;
};

class FakePointerController : public PointerControllerInterface {
public:
    FakePointerController() : FakePointerController(/*enabled=*/true) {}
    FakePointerController(bool enabled) : mEnabled(enabled) {}

    virtual ~FakePointerController() {}

    void setBounds(float minX, float minY, float maxX, float maxY);
    void clearBounds();
    const std::map<ui::LogicalDisplayId, std::vector<int32_t>>& getSpots();

    void setPosition(float x, float y) override;
    FloatPoint getPosition() const override;
    ui::LogicalDisplayId getDisplayId() const override;
    void setDisplayViewport(const DisplayViewport& viewport) override;
    void updatePointerIcon(PointerIconStyle iconId) override;
    void setCustomPointerIcon(const SpriteIcon& icon) override;
    void setSkipScreenshotFlagForDisplay(ui::LogicalDisplayId displayId) override;
    void clearSkipScreenshotFlags() override;
    void fade(Transition) override;

    void assertViewportSet(ui::LogicalDisplayId displayId);
    void assertViewportNotSet();
    void assertPosition(float x, float y);
    void assertSpotCount(ui::LogicalDisplayId displayId, int32_t count);
    void assertPointerIconSet(PointerIconStyle iconId);
    void assertPointerIconNotSet();
    void assertCustomPointerIconSet(PointerIconStyle iconId);
    void assertCustomPointerIconNotSet();
    void assertIsSkipScreenshotFlagSet(ui::LogicalDisplayId displayId);
    void assertIsSkipScreenshotFlagNotSet(ui::LogicalDisplayId displayId);
    void assertSkipScreenshotFlagChanged();
    void assertSkipScreenshotFlagNotChanged();
    bool isPointerShown();

private:
    std::string dump() override { return ""; }
    std::optional<FloatRect> getBounds() const override;
    void move(float deltaX, float deltaY) override;
    void unfade(Transition) override;
    void setPresentation(Presentation) override {}
    void setSpots(const PointerCoords*, const uint32_t*, BitSet32 spotIdBits,
                  ui::LogicalDisplayId displayId) override;
    void clearSpots() override;

    const bool mEnabled;
    bool mHaveBounds{false};
    float mMinX{0}, mMinY{0}, mMaxX{0}, mMaxY{0};
    float mX{0}, mY{0};
    std::optional<ui::LogicalDisplayId> mDisplayId;
    bool mIsPointerShown{false};
    std::optional<PointerIconStyle> mIconStyle;
    std::optional<PointerIconStyle> mCustomIconStyle;

    std::map<ui::LogicalDisplayId, std::vector<int32_t>> mSpotsByDisplay;
    std::unordered_set<ui::LogicalDisplayId> mDisplaysToSkipScreenshot;
    bool mDisplaysToSkipScreenshotFlagChanged{false};
};

} // namespace android
