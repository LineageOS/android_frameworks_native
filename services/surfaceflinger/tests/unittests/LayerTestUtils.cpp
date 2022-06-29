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

#include "LayerTestUtils.h"

#include "mock/MockEventThread.h"

namespace android {

using testing::_;
using testing::Return;

using FakeHwcDisplayInjector = TestableSurfaceFlinger::FakeHwcDisplayInjector;

sp<Layer> BufferStateLayerFactory::createLayer(TestableSurfaceFlinger& flinger) {
    sp<Client> client;
    LayerCreationArgs args(flinger.flinger(), client, "buffer-state-layer", LAYER_FLAGS,
                           LayerMetadata());
    return new BufferStateLayer(args);
}

sp<Layer> EffectLayerFactory::createLayer(TestableSurfaceFlinger& flinger) {
    sp<Client> client;
    LayerCreationArgs args(flinger.flinger(), client, "color-layer", LAYER_FLAGS, LayerMetadata());
    return new EffectLayer(args);
}

std::string PrintToStringParamName(
        const ::testing::TestParamInfo<std::shared_ptr<LayerFactory>>& info) {
    return info.param->name();
}

BaseLayerTest::BaseLayerTest() {
    setupScheduler();
}

void BaseLayerTest::setupScheduler() {
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
                            std::move(eventThread), std::move(sfEventThread),
                            TestableSurfaceFlinger::SchedulerCallbackImpl::kNoOp,
                            TestableSurfaceFlinger::kTwoDisplayModes);
}

} // namespace android
