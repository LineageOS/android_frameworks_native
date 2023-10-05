/*
 * Copyright (C) 2022 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <gui/BufferItemConsumer.h>
#include <ui/Transform.h>
#include <thread>
#include "TransactionTestHarnesses.h"

namespace android {
struct PresentationCallbackHelper {
    void callbackArrived(bool state) {
        std::unique_lock l(mMutex);
        mGotCallback = true;
        mState = state;
        mCondition.notify_all();
    }
    bool awaitCallback() {
        std::unique_lock l(mMutex);
        mGotCallback = false;
        mCondition.wait_for(l, 5000ms);
        EXPECT_TRUE(mGotCallback);
        return mState;
    }

    bool mState;
    bool mGotCallback;
    std::mutex mMutex;
    std::condition_variable mCondition;
};

TrustedPresentationThresholds thresh() {
    TrustedPresentationThresholds thresholds;
    thresholds.minAlpha = 1.0;
    thresholds.minFractionRendered = 1.0;
    thresholds.stabilityRequirementMs = 100;
    return thresholds;
}

class LayerTrustedPresentationListenerTest : public LayerTransactionTest {
public:
    void SetUp() override {
        LayerTransactionTest::SetUp();
        mainLayer = makeLayer();
        thresholds = thresh();
    }

    void TearDown() override {
        LayerTransactionTest::TearDown();
        mCallback = nullptr;
        t.reparent(mainLayer, nullptr).apply();
        mainLayer = nullptr;
    }

    void thresholdsPrepared() {
        t.show(mainLayer)
                .setLayer(mainLayer, INT32_MAX)
                .setTrustedPresentationCallback(
                        mainLayer,
                        [&](void* context, bool state) {
                            PresentationCallbackHelper* helper =
                                    (PresentationCallbackHelper*)context;
                            helper->callbackArrived(state);
                        },
                        thresholds, &pch, mCallback)
                .setPosition(mainLayer, 100, 100)
                .apply();
    }

    sp<SurfaceControl> makeLayer() {
        sp<SurfaceControl> layer =
                createLayer("test", 100, 100, ISurfaceComposerClient::eFXSurfaceBufferState,
                            mBlackBgSurface.get());
        fillBufferLayerColor(layer, Color::RED, 100, 100);
        return layer;
    }
    sp<SurfaceControl> mainLayer;
    PresentationCallbackHelper pch;
    SurfaceComposerClient::Transaction t;
    TrustedPresentationThresholds thresholds;
    sp<SurfaceComposerClient::PresentationCallbackRAII> mCallback;
};

// The layer is fully presented with the default test setup.
TEST_F(LayerTrustedPresentationListenerTest, callback_arrives) {
    thresholdsPrepared();
    EXPECT_TRUE(pch.awaitCallback());
}

// A hidden layer can't be considered presented!
TEST_F(LayerTrustedPresentationListenerTest, hiding_layer_clears_state) {
    thresholdsPrepared();
    EXPECT_TRUE(pch.awaitCallback());
    t.hide(mainLayer).apply();
    EXPECT_FALSE(pch.awaitCallback());
}

// A fully obscured layer can't be considered presented!
TEST_F(LayerTrustedPresentationListenerTest, obscuring_clears_state) {
    thresholdsPrepared();
    EXPECT_TRUE(pch.awaitCallback());

    auto otherLayer = makeLayer();
    t.show(otherLayer)
            .setPosition(otherLayer, 100, 100)
            .setLayer(otherLayer, INT32_MAX)
            .setLayer(mainLayer, INT32_MAX - 1)
            .apply();
    EXPECT_FALSE(pch.awaitCallback());
}

// Even if the layer obscuring us has an Alpha channel, we are still considered
// obscured.
TEST_F(LayerTrustedPresentationListenerTest, obscuring_with_transparency_clears_state) {
    thresholdsPrepared();
    EXPECT_TRUE(pch.awaitCallback());

    auto otherLayer = makeLayer();
    t.show(otherLayer)
            .setPosition(otherLayer, 100, 100)
            .setLayer(otherLayer, INT32_MAX)
            .setFlags(otherLayer, 0, layer_state_t::eLayerOpaque)
            .setLayer(mainLayer, INT32_MAX - 1)
            .apply();
    EXPECT_FALSE(pch.awaitCallback());
}

// We can't be presented if our alpha is below the threshold.
TEST_F(LayerTrustedPresentationListenerTest, alpha_below_threshold) {
    thresholdsPrepared();
    EXPECT_TRUE(pch.awaitCallback());
    t.setAlpha(mainLayer, 0.9).apply();
    EXPECT_FALSE(pch.awaitCallback());
    t.setAlpha(mainLayer, 1.0).apply();
    EXPECT_TRUE(pch.awaitCallback());
}

// Verify that the passed in threshold is actually respected!
TEST_F(LayerTrustedPresentationListenerTest, alpha_below_other_threshold) {
    thresholds.minAlpha = 0.8;
    thresholdsPrepared();
    EXPECT_TRUE(pch.awaitCallback());
    t.setAlpha(mainLayer, 0.8).apply();
    EXPECT_FALSE(pch.awaitCallback());
    t.setAlpha(mainLayer, 0.9).apply();
    EXPECT_TRUE(pch.awaitCallback());
}

// (86*86)/(100*100) = 0.73...so a crop of 86x86 is below the threshold
// (87*87)/(100*100) = 0.76...so a crop of 87x87 is above the threshold!
TEST_F(LayerTrustedPresentationListenerTest, crop_below_threshold) {
    thresholds.minFractionRendered = 0.75;
    thresholdsPrepared();
    EXPECT_TRUE(pch.awaitCallback());
    t.setCrop(mainLayer, Rect(0, 0, 86, 86)).apply();
    EXPECT_FALSE(pch.awaitCallback());
    t.setCrop(mainLayer, Rect(0, 0, 87, 87)).apply();
    EXPECT_TRUE(pch.awaitCallback());
}

TEST_F(LayerTrustedPresentationListenerTest, scale_below_threshold) {
    thresholds.minFractionRendered = 0.64;
    thresholdsPrepared();
    EXPECT_TRUE(pch.awaitCallback());
    // 0.8 = sqrt(0.64)
    t.setMatrix(mainLayer, 0.79, 0, 0, 0.79).apply();
    EXPECT_FALSE(pch.awaitCallback());
    t.setMatrix(mainLayer, 0.81, 0, 0, 0.81).apply();
    EXPECT_TRUE(pch.awaitCallback());
}

TEST_F(LayerTrustedPresentationListenerTest, obscuring_with_threshold_1) {
    thresholds.minFractionRendered = 0.75;
    thresholdsPrepared();
    EXPECT_TRUE(pch.awaitCallback());

    auto otherLayer = makeLayer();
    t.show(otherLayer)
            .setPosition(otherLayer, 100, 100)
            .setLayer(otherLayer, INT32_MAX)
            .setLayer(mainLayer, INT32_MAX - 1)
            .apply();
    EXPECT_FALSE(pch.awaitCallback());
    t.setMatrix(otherLayer, 0.49, 0, 0, 0.49).apply();
    EXPECT_TRUE(pch.awaitCallback());
    t.setMatrix(otherLayer, 0.51, 0, 0, 0.51).apply();
    EXPECT_FALSE(pch.awaitCallback());
}

TEST_F(LayerTrustedPresentationListenerTest, obscuring_with_threshold_2) {
    thresholds.minFractionRendered = 0.9;
    thresholdsPrepared();
    EXPECT_TRUE(pch.awaitCallback());

    auto otherLayer = makeLayer();
    t.show(otherLayer)
            .setPosition(otherLayer, 100, 100)
            .setLayer(otherLayer, INT32_MAX)
            .setLayer(mainLayer, INT32_MAX - 1)
            .apply();
    EXPECT_FALSE(pch.awaitCallback());
    t.setMatrix(otherLayer, 0.3, 0, 0, 0.3).apply();
    EXPECT_TRUE(pch.awaitCallback());
    t.setMatrix(otherLayer, 0.33, 0, 0, 0.33).apply();
    EXPECT_FALSE(pch.awaitCallback());
}

TEST_F(LayerTrustedPresentationListenerTest, obscuring_with_alpha) {
    thresholds.minFractionRendered = 0.9;
    thresholdsPrepared();
    EXPECT_TRUE(pch.awaitCallback());

    auto otherLayer = makeLayer();
    t.show(otherLayer)
            .setPosition(otherLayer, 100, 100)
            .setLayer(otherLayer, INT32_MAX)
            .setLayer(mainLayer, INT32_MAX - 1)
            .setAlpha(otherLayer, 0.01)
            .apply();
    EXPECT_FALSE(pch.awaitCallback());
    t.setAlpha(otherLayer, 0.0).apply();
    EXPECT_TRUE(pch.awaitCallback());
}

TEST_F(LayerTrustedPresentationListenerTest, obscuring_with_display_overlay) {
    auto otherLayer = makeLayer();
    t.show(otherLayer)
            .setPosition(otherLayer, 100, 100)
            .setLayer(otherLayer, INT32_MAX)
            .setFlags(otherLayer, layer_state_t::eLayerSkipScreenshot,
                      layer_state_t::eLayerSkipScreenshot)
            .setLayer(mainLayer, INT32_MAX - 1)
            .show(mainLayer)
            .setPosition(mainLayer, 100, 100)
            .setTrustedPresentationCallback(
                    mainLayer,
                    [&](void* context, bool state) {
                        PresentationCallbackHelper* helper = (PresentationCallbackHelper*)context;
                        helper->callbackArrived(state);
                    },
                    thresholds, &pch, mCallback)
            .apply();
    EXPECT_TRUE(pch.awaitCallback());
}

TEST_F(LayerTrustedPresentationListenerTest, obscuring_with_non_overlapping_bounds) {
    thresholds.minFractionRendered = 0.5;
    auto otherLayer1 = makeLayer();
    auto otherLayer2 = makeLayer();
    t.show(otherLayer1)
            .show(otherLayer2)
            .setPosition(otherLayer1, 100, 25)
            .setLayer(otherLayer1, INT32_MAX)
            .setPosition(otherLayer2, 100, 175)
            .setLayer(otherLayer2, INT32_MAX)
            .setLayer(mainLayer, INT32_MAX - 1)
            .show(mainLayer)
            .setPosition(mainLayer, 100, 100)
            .setTrustedPresentationCallback(
                    mainLayer,
                    [&](void* context, bool state) {
                        PresentationCallbackHelper* helper = (PresentationCallbackHelper*)context;
                        helper->callbackArrived(state);
                    },
                    thresholds, &pch, mCallback)
            .apply();

    EXPECT_TRUE(pch.awaitCallback());
}

} // namespace android
