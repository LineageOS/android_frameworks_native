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
#include "mock/MockEventThread.h"
#include "mock/MockVsyncController.h"

namespace android {

using testing::_;
using testing::Mock;
using testing::Return;
using FakeHwcDisplayInjector = TestableSurfaceFlinger::FakeHwcDisplayInjector;

class GameModeTest : public testing::Test {
public:
    GameModeTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
        setupScheduler();
        setupComposer();
    }

    ~GameModeTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    sp<BufferStateLayer> createBufferStateLayer() {
        sp<Client> client;
        LayerCreationArgs args(mFlinger.flinger(), client, "buffer-state-layer", 0,
                               LayerMetadata());
        return new BufferStateLayer(args);
    }

    void setupScheduler() {
        auto eventThread = std::make_unique<mock::EventThread>();
        auto sfEventThread = std::make_unique<mock::EventThread>();

        EXPECT_CALL(*eventThread, registerDisplayEventConnection(_));
        EXPECT_CALL(*eventThread, createEventConnection(_, _))
                .WillOnce(Return(new EventThreadConnection(eventThread.get(), /*callingUid=*/0,
                                                           ResyncCallback())));

        EXPECT_CALL(*sfEventThread, registerDisplayEventConnection(_));
        EXPECT_CALL(*sfEventThread, createEventConnection(_, _))
                .WillOnce(Return(new EventThreadConnection(sfEventThread.get(), /*callingUid=*/0,
                                                           ResyncCallback())));

        auto vsyncController = std::make_unique<mock::VsyncController>();
        auto vsyncTracker = std::make_unique<mock::VSyncTracker>();

        EXPECT_CALL(*vsyncTracker, nextAnticipatedVSyncTimeFrom(_)).WillRepeatedly(Return(0));
        EXPECT_CALL(*vsyncTracker, currentPeriod())
                .WillRepeatedly(Return(FakeHwcDisplayInjector::DEFAULT_VSYNC_PERIOD));
        EXPECT_CALL(*vsyncTracker, nextAnticipatedVSyncTimeFrom(_)).WillRepeatedly(Return(0));
        mFlinger.setupScheduler(std::move(vsyncController), std::move(vsyncTracker),
                                std::move(eventThread), std::move(sfEventThread));
    }

    void setupComposer() {
        mComposer = new Hwc2::mock::Composer();
        mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));

        Mock::VerifyAndClear(mComposer);
    }

    // Mocks the behavior of applying a transaction from WMShell
    void setGameModeMetadata(sp<Layer> layer, GameMode gameMode) {
        mLayerMetadata.setInt32(METADATA_GAME_MODE, static_cast<int32_t>(gameMode));
        layer->setMetadata(mLayerMetadata);
        layer->setGameModeForTree(gameMode);
    }

    TestableSurfaceFlinger mFlinger;
    Hwc2::mock::Composer* mComposer = nullptr;
    client_cache_t mClientCache;
    LayerMetadata mLayerMetadata;
};

TEST_F(GameModeTest, SetGameModeSetsForAllCurrentChildren) {
    sp<BufferStateLayer> rootLayer = createBufferStateLayer();
    sp<BufferStateLayer> childLayer1 = createBufferStateLayer();
    sp<BufferStateLayer> childLayer2 = createBufferStateLayer();
    rootLayer->addChild(childLayer1);
    rootLayer->addChild(childLayer2);
    rootLayer->setGameModeForTree(GameMode::Performance);

    EXPECT_EQ(rootLayer->getGameMode(), GameMode::Performance);
    EXPECT_EQ(childLayer1->getGameMode(), GameMode::Performance);
    EXPECT_EQ(childLayer2->getGameMode(), GameMode::Performance);
}

TEST_F(GameModeTest, AddChildAppliesGameModeFromParent) {
    sp<BufferStateLayer> rootLayer = createBufferStateLayer();
    sp<BufferStateLayer> childLayer = createBufferStateLayer();
    rootLayer->setGameModeForTree(GameMode::Performance);
    rootLayer->addChild(childLayer);

    EXPECT_EQ(rootLayer->getGameMode(), GameMode::Performance);
    EXPECT_EQ(childLayer->getGameMode(), GameMode::Performance);
}

TEST_F(GameModeTest, RemoveChildResetsGameMode) {
    sp<BufferStateLayer> rootLayer = createBufferStateLayer();
    sp<BufferStateLayer> childLayer = createBufferStateLayer();
    rootLayer->setGameModeForTree(GameMode::Performance);
    rootLayer->addChild(childLayer);

    EXPECT_EQ(rootLayer->getGameMode(), GameMode::Performance);
    EXPECT_EQ(childLayer->getGameMode(), GameMode::Performance);

    rootLayer->removeChild(childLayer);
    EXPECT_EQ(childLayer->getGameMode(), GameMode::Unsupported);
}

TEST_F(GameModeTest, ReparentingDoesNotOverrideMetadata) {
    sp<BufferStateLayer> rootLayer = createBufferStateLayer();
    sp<BufferStateLayer> childLayer1 = createBufferStateLayer();
    sp<BufferStateLayer> childLayer2 = createBufferStateLayer();
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
