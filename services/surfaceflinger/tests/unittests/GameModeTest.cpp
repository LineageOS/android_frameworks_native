/*
 * Copyright 2021 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/LayerMetadata.h>
#include <gui/SurfaceComposerClient.h>
#include <log/log.h>

#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockComposer.h"

namespace android {

using testing::_;
using testing::Mock;
using testing::Return;

using gui::GameMode;
using gui::LayerMetadata;

class GameModeTest : public testing::Test {
public:
    GameModeTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
        mFlinger.setupMockScheduler();
        setupComposer();
    }

    ~GameModeTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    sp<Layer> createLayer() {
        sp<Client> client;
        LayerCreationArgs args(mFlinger.flinger(), client, "layer", 0, LayerMetadata());
        return sp<Layer>::make(args);
    }

    void setupComposer() {
        mComposer = new Hwc2::mock::Composer();
        mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));

        Mock::VerifyAndClear(mComposer);
    }

    // Mocks the behavior of applying a transaction from WMShell
    void setGameModeMetadata(sp<Layer> layer, GameMode gameMode) {
        mLayerMetadata.setInt32(gui::METADATA_GAME_MODE, static_cast<int32_t>(gameMode));
        layer->setMetadata(mLayerMetadata);
        layer->setGameModeForTree(gameMode);
    }

    TestableSurfaceFlinger mFlinger;
    Hwc2::mock::Composer* mComposer = nullptr;
    client_cache_t mClientCache;
    LayerMetadata mLayerMetadata;
};

TEST_F(GameModeTest, SetGameModeSetsForAllCurrentChildren) {
    sp<Layer> rootLayer = createLayer();
    sp<Layer> childLayer1 = createLayer();
    sp<Layer> childLayer2 = createLayer();
    rootLayer->addChild(childLayer1);
    rootLayer->addChild(childLayer2);
    rootLayer->setGameModeForTree(GameMode::Performance);

    EXPECT_EQ(rootLayer->getGameMode(), GameMode::Performance);
    EXPECT_EQ(childLayer1->getGameMode(), GameMode::Performance);
    EXPECT_EQ(childLayer2->getGameMode(), GameMode::Performance);
}

TEST_F(GameModeTest, AddChildAppliesGameModeFromParent) {
    sp<Layer> rootLayer = createLayer();
    sp<Layer> childLayer = createLayer();
    rootLayer->setGameModeForTree(GameMode::Performance);
    rootLayer->addChild(childLayer);

    EXPECT_EQ(rootLayer->getGameMode(), GameMode::Performance);
    EXPECT_EQ(childLayer->getGameMode(), GameMode::Performance);
}

TEST_F(GameModeTest, RemoveChildResetsGameMode) {
    sp<Layer> rootLayer = createLayer();
    sp<Layer> childLayer = createLayer();
    rootLayer->setGameModeForTree(GameMode::Performance);
    rootLayer->addChild(childLayer);

    EXPECT_EQ(rootLayer->getGameMode(), GameMode::Performance);
    EXPECT_EQ(childLayer->getGameMode(), GameMode::Performance);

    rootLayer->removeChild(childLayer);
    EXPECT_EQ(childLayer->getGameMode(), GameMode::Unsupported);
}

TEST_F(GameModeTest, ReparentingDoesNotOverrideMetadata) {
    sp<Layer> rootLayer = createLayer();
    sp<Layer> childLayer1 = createLayer();
    sp<Layer> childLayer2 = createLayer();
    rootLayer->setGameModeForTree(GameMode::Standard);
    rootLayer->addChild(childLayer1);

    setGameModeMetadata(childLayer2, GameMode::Performance);
    rootLayer->addChild(childLayer2);

    EXPECT_EQ(rootLayer->getGameMode(), GameMode::Standard);
    EXPECT_EQ(childLayer1->getGameMode(), GameMode::Standard);
    EXPECT_EQ(childLayer2->getGameMode(), GameMode::Performance);

    rootLayer->removeChild(childLayer2);
    EXPECT_EQ(childLayer2->getGameMode(), GameMode::Performance);
}

} // namespace android
