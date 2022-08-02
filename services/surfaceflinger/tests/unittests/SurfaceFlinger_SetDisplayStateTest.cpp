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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include "DisplayTransactionTestHelpers.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android {
namespace {

constexpr ui::LayerStack LAYER_STACK{456u};

class SetDisplayStateLockedTest : public DisplayTransactionTest {};

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedDoesNothingWithUnknownDisplay) {
    // --------------------------------------------------------------------
    // Preconditions

    // We have an unknown display token not associated with a known display
    sp<BBinder> displayToken = sp<BBinder>::make();

    // The requested display state references the unknown display.
    DisplayState state;
    state.what = DisplayState::eLayerStackChanged;
    state.token = displayToken;
    state.layerStack = LAYER_STACK;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags are empty
    EXPECT_EQ(0u, flags);

    // The display token still doesn't match anything known.
    EXPECT_FALSE(hasCurrentDisplayState(displayToken));
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedDoesNothingWhenNoChanges) {
    using Case = SimplePrimaryDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // A display is already set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // No changes are made to the display
    DisplayState state;
    state.what = 0;
    state.token = display.token();

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags are empty
    EXPECT_EQ(0u, flags);
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedDoesNothingIfSurfaceDidNotChange) {
    using Case = SimplePrimaryDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // A display is already set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // There is a surface that can be set.
    sp<mock::GraphicBufferProducer> surface = sp<mock::GraphicBufferProducer>::make();

    // The current display state has the surface set
    display.mutableCurrentDisplayState().surface = surface;

    // The incoming request sets the same surface
    DisplayState state;
    state.what = DisplayState::eSurfaceChanged;
    state.token = display.token();
    state.surface = surface;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags are empty
    EXPECT_EQ(0u, flags);

    // The current display state is unchanged.
    EXPECT_EQ(surface.get(), display.getCurrentDisplayState().surface.get());
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedRequestsUpdateIfSurfaceChanged) {
    using Case = SimplePrimaryDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // A display is already set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // There is a surface that can be set.
    sp<mock::GraphicBufferProducer> surface = sp<mock::GraphicBufferProducer>::make();

    // The current display state does not have a surface
    display.mutableCurrentDisplayState().surface = nullptr;

    // The incoming request sets a surface
    DisplayState state;
    state.what = DisplayState::eSurfaceChanged;
    state.token = display.token();
    state.surface = surface;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags indicate a transaction is needed
    EXPECT_EQ(eDisplayTransactionNeeded, flags);

    // The current display layer stack state is set to the new value
    EXPECT_EQ(surface.get(), display.getCurrentDisplayState().surface.get());
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedDoesNothingIfLayerStackDidNotChange) {
    using Case = SimplePrimaryDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // A display is already set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The display has a layer stack set
    display.mutableCurrentDisplayState().layerStack = LAYER_STACK;

    // The incoming request sets the same layer stack
    DisplayState state;
    state.what = DisplayState::eLayerStackChanged;
    state.token = display.token();
    state.layerStack = LAYER_STACK;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags are empty
    EXPECT_EQ(0u, flags);

    // The current display state is unchanged
    EXPECT_EQ(LAYER_STACK, display.getCurrentDisplayState().layerStack);
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedRequestsUpdateIfLayerStackChanged) {
    using Case = SimplePrimaryDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // A display is set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The display has a layer stack set
    display.mutableCurrentDisplayState().layerStack = ui::LayerStack{LAYER_STACK.id + 1};

    // The incoming request sets a different layer stack
    DisplayState state;
    state.what = DisplayState::eLayerStackChanged;
    state.token = display.token();
    state.layerStack = LAYER_STACK;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags indicate a transaction is needed
    EXPECT_EQ(eDisplayTransactionNeeded, flags);

    // The desired display state has been set to the new value.
    EXPECT_EQ(LAYER_STACK, display.getCurrentDisplayState().layerStack);
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedDoesNothingIfFlagsNotChanged) {
    using Case = SimplePrimaryDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // A display is set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The display has flags set
    display.mutableCurrentDisplayState().flags = 1u;

    // The incoming request sets a different layer stack
    DisplayState state;
    state.what = DisplayState::eFlagsChanged;
    state.token = display.token();
    state.flags = 1u;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags are empty
    EXPECT_EQ(0u, flags);

    // The desired display state has been set to the new value.
    EXPECT_EQ(1u, display.getCurrentDisplayState().flags);
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedRequestsUpdateIfFlagsChanged) {
    using Case = SimplePrimaryDisplayCase;

    // --------------------------------------------------------------------
    // Preconditions

    // A display is set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The display has a layer stack set
    display.mutableCurrentDisplayState().flags = 0u;

    // The incoming request sets a different layer stack
    DisplayState state;
    state.what = DisplayState::eFlagsChanged;
    state.token = display.token();
    state.flags = 1u;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags indicate a transaction is needed
    EXPECT_EQ(eDisplayTransactionNeeded, flags);

    // The desired display state has been set to the new value.
    EXPECT_EQ(1u, display.getCurrentDisplayState().flags);
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedDoesNothingIfProjectionDidNotChange) {
    using Case = SimplePrimaryDisplayCase;
    constexpr ui::Rotation initialOrientation = ui::ROTATION_180;
    const Rect initialOrientedDisplayRect = {1, 2, 3, 4};
    const Rect initialLayerStackRect = {5, 6, 7, 8};

    // --------------------------------------------------------------------
    // Preconditions

    // A display is set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The current display state projection state is all set
    display.mutableCurrentDisplayState().orientation = initialOrientation;
    display.mutableCurrentDisplayState().orientedDisplaySpaceRect = initialOrientedDisplayRect;
    display.mutableCurrentDisplayState().layerStackSpaceRect = initialLayerStackRect;

    // The incoming request sets the same projection state
    DisplayState state;
    state.what = DisplayState::eDisplayProjectionChanged;
    state.token = display.token();
    state.orientation = initialOrientation;
    state.orientedDisplaySpaceRect = initialOrientedDisplayRect;
    state.layerStackSpaceRect = initialLayerStackRect;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags are empty
    EXPECT_EQ(0u, flags);

    // The current display state is unchanged
    EXPECT_EQ(initialOrientation, display.getCurrentDisplayState().orientation);

    EXPECT_EQ(initialOrientedDisplayRect,
              display.getCurrentDisplayState().orientedDisplaySpaceRect);
    EXPECT_EQ(initialLayerStackRect, display.getCurrentDisplayState().layerStackSpaceRect);
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedRequestsUpdateIfOrientationChanged) {
    using Case = SimplePrimaryDisplayCase;
    constexpr ui::Rotation initialOrientation = ui::ROTATION_90;
    constexpr ui::Rotation desiredOrientation = ui::ROTATION_180;

    // --------------------------------------------------------------------
    // Preconditions

    // A display is set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The current display state has an orientation set
    display.mutableCurrentDisplayState().orientation = initialOrientation;

    // The incoming request sets a different orientation
    DisplayState state;
    state.what = DisplayState::eDisplayProjectionChanged;
    state.token = display.token();
    state.orientation = desiredOrientation;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags indicate a transaction is needed
    EXPECT_EQ(eDisplayTransactionNeeded, flags);

    // The current display state has the new value.
    EXPECT_EQ(desiredOrientation, display.getCurrentDisplayState().orientation);
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedRequestsUpdateIfFrameChanged) {
    using Case = SimplePrimaryDisplayCase;
    const Rect initialOrientedDisplayRect = {0, 0, 0, 0};
    const Rect desiredOrientedDisplayRect = {5, 6, 7, 8};

    // --------------------------------------------------------------------
    // Preconditions

    // A display is set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The current display state does not have a orientedDisplaySpaceRect
    display.mutableCurrentDisplayState().orientedDisplaySpaceRect = initialOrientedDisplayRect;

    // The incoming request sets a orientedDisplaySpaceRect
    DisplayState state;
    state.what = DisplayState::eDisplayProjectionChanged;
    state.token = display.token();
    state.orientedDisplaySpaceRect = desiredOrientedDisplayRect;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags indicate a transaction is needed
    EXPECT_EQ(eDisplayTransactionNeeded, flags);

    // The current display state has the new value.
    EXPECT_EQ(desiredOrientedDisplayRect,
              display.getCurrentDisplayState().orientedDisplaySpaceRect);
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedRequestsUpdateIfLayerStackRectChanged) {
    using Case = SimplePrimaryDisplayCase;
    const Rect initialLayerStackRect = {0, 0, 0, 0};
    const Rect desiredLayerStackRect = {5, 6, 7, 8};

    // --------------------------------------------------------------------
    // Preconditions

    // A display is set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The current display state does not have a layerStackSpaceRect
    display.mutableCurrentDisplayState().layerStackSpaceRect = initialLayerStackRect;

    // The incoming request sets a layerStackSpaceRect
    DisplayState state;
    state.what = DisplayState::eDisplayProjectionChanged;
    state.token = display.token();
    state.layerStackSpaceRect = desiredLayerStackRect;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags indicate a transaction is needed
    EXPECT_EQ(eDisplayTransactionNeeded, flags);

    // The current display state has the new value.
    EXPECT_EQ(desiredLayerStackRect, display.getCurrentDisplayState().layerStackSpaceRect);
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedDoesNothingIfSizeDidNotChange) {
    using Case = SimplePrimaryDisplayCase;
    constexpr uint32_t initialWidth = 1024;
    constexpr uint32_t initialHeight = 768;

    // --------------------------------------------------------------------
    // Preconditions

    // A display is set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The current display state has a size set
    display.mutableCurrentDisplayState().width = initialWidth;
    display.mutableCurrentDisplayState().height = initialHeight;

    // The incoming request sets the same display size
    DisplayState state;
    state.what = DisplayState::eDisplaySizeChanged;
    state.token = display.token();
    state.width = initialWidth;
    state.height = initialHeight;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags are empty
    EXPECT_EQ(0u, flags);

    // The current display state is unchanged
    EXPECT_EQ(initialWidth, display.getCurrentDisplayState().width);
    EXPECT_EQ(initialHeight, display.getCurrentDisplayState().height);
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedRequestsUpdateIfWidthChanged) {
    using Case = SimplePrimaryDisplayCase;
    constexpr uint32_t initialWidth = 0;
    constexpr uint32_t desiredWidth = 1024;

    // --------------------------------------------------------------------
    // Preconditions

    // A display is set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The display does not yet have a width
    display.mutableCurrentDisplayState().width = initialWidth;

    // The incoming request sets a display width
    DisplayState state;
    state.what = DisplayState::eDisplaySizeChanged;
    state.token = display.token();
    state.width = desiredWidth;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags indicate a transaction is needed
    EXPECT_EQ(eDisplayTransactionNeeded, flags);

    // The current display state has the new value.
    EXPECT_EQ(desiredWidth, display.getCurrentDisplayState().width);
}

TEST_F(SetDisplayStateLockedTest, setDisplayStateLockedRequestsUpdateIfHeightChanged) {
    using Case = SimplePrimaryDisplayCase;
    constexpr uint32_t initialHeight = 0;
    constexpr uint32_t desiredHeight = 768;

    // --------------------------------------------------------------------
    // Preconditions

    // A display is set up
    auto display = Case::Display::makeFakeExistingDisplayInjector(this);
    display.inject();

    // The display does not yet have a height
    display.mutableCurrentDisplayState().height = initialHeight;

    // The incoming request sets a display height
    DisplayState state;
    state.what = DisplayState::eDisplaySizeChanged;
    state.token = display.token();
    state.height = desiredHeight;

    // --------------------------------------------------------------------
    // Invocation

    uint32_t flags = mFlinger.setDisplayStateLocked(state);

    // --------------------------------------------------------------------
    // Postconditions

    // The returned flags indicate a transaction is needed
    EXPECT_EQ(eDisplayTransactionNeeded, flags);

    // The current display state has the new value.
    EXPECT_EQ(desiredHeight, display.getCurrentDisplayState().height);
}

} // namespace
} // namespace android
