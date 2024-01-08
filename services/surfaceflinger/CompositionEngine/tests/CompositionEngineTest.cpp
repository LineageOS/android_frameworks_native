/*
 * Copyright 2018 The Android Open Source Project
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

#include <com_android_graphics_surfaceflinger_flags.h>
#include <common/test/FlagUtils.h>
#include <compositionengine/CompositionRefreshArgs.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/impl/CompositionEngine.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/Output.h>
#include <compositionengine/mock/OutputLayer.h>
#include <ftl/future.h>
#include <gtest/gtest.h>
#include <renderengine/mock/RenderEngine.h>

#include "MockHWComposer.h"
#include "TimeStats/TimeStats.h"
#include "gmock/gmock.h"

#include <variant>

using namespace com::android::graphics::surfaceflinger;

namespace android::compositionengine {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::InSequence;
using ::testing::Ref;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SaveArg;
using ::testing::StrictMock;

struct CompositionEngineTest : public testing::Test {
    std::shared_ptr<TimeStats> mTimeStats;

    impl::CompositionEngine mEngine;
    CompositionRefreshArgs mRefreshArgs;

    std::shared_ptr<mock::Output> mOutput1{std::make_shared<StrictMock<mock::Output>>()};
    std::shared_ptr<mock::Output> mOutput2{std::make_shared<StrictMock<mock::Output>>()};
    std::shared_ptr<mock::Output> mOutput3{std::make_shared<StrictMock<mock::Output>>()};
};

TEST_F(CompositionEngineTest, canInstantiateCompositionEngine) {
    auto engine = impl::createCompositionEngine();
    EXPECT_TRUE(engine.get() != nullptr);
}

TEST_F(CompositionEngineTest, canSetHWComposer) {
    android::mock::HWComposer* hwc = new StrictMock<android::mock::HWComposer>();
    mEngine.setHwComposer(std::unique_ptr<android::HWComposer>(hwc));

    EXPECT_EQ(hwc, &mEngine.getHwComposer());
}

TEST_F(CompositionEngineTest, canSetRenderEngine) {
    auto renderEngine = std::make_unique<StrictMock<renderengine::mock::RenderEngine>>();
    mEngine.setRenderEngine(renderEngine.get());

    EXPECT_EQ(renderEngine.get(), &mEngine.getRenderEngine());
}

TEST_F(CompositionEngineTest, canSetTimeStats) {
    mEngine.setTimeStats(mTimeStats);

    EXPECT_EQ(mTimeStats.get(), mEngine.getTimeStats());
}

/*
 * CompositionEngine::present
 */

struct CompositionEnginePresentTest : public CompositionEngineTest {
    struct CompositionEnginePartialMock : public impl::CompositionEngine {
        // These are the overridable functions CompositionEngine::present() may
        // call, and have separate test coverage.
        MOCK_METHOD1(preComposition, void(CompositionRefreshArgs&));
        MOCK_METHOD1(postComposition, void(CompositionRefreshArgs&));
    };

    StrictMock<CompositionEnginePartialMock> mEngine;
};

TEST_F(CompositionEnginePresentTest, worksWithEmptyRequest) {
    // present() always calls preComposition() and postComposition()
    EXPECT_CALL(mEngine, preComposition(Ref(mRefreshArgs)));
    EXPECT_CALL(mEngine, postComposition(Ref(mRefreshArgs)));

    mEngine.present(mRefreshArgs);
}

TEST_F(CompositionEnginePresentTest, worksAsExpected) {
    // Expect calls to in a certain sequence
    InSequence seq;

    // present() always calls preComposition()
    EXPECT_CALL(mEngine, preComposition(Ref(mRefreshArgs)));

    // The first step in presenting is to make sure all outputs are prepared.
    EXPECT_CALL(*mOutput1, prepare(Ref(mRefreshArgs), _));
    EXPECT_CALL(*mOutput2, prepare(Ref(mRefreshArgs), _));
    EXPECT_CALL(*mOutput3, prepare(Ref(mRefreshArgs), _));

    // All of mOutput<i> are StrictMocks. If the flag is true, it will introduce
    // calls to getDisplayId, which are not relevant to this test.
    SET_FLAG_FOR_TEST(flags::multithreaded_present, false);

    // The last step is to actually present each output.
    EXPECT_CALL(*mOutput1, present(Ref(mRefreshArgs)))
            .WillOnce(Return(ftl::yield<std::monostate>({})));
    EXPECT_CALL(*mOutput2, present(Ref(mRefreshArgs)))
            .WillOnce(Return(ftl::yield<std::monostate>({})));
    EXPECT_CALL(*mOutput3, present(Ref(mRefreshArgs)))
            .WillOnce(Return(ftl::yield<std::monostate>({})));

    // present() always calls postComposition()
    EXPECT_CALL(mEngine, postComposition(Ref(mRefreshArgs)));

    mRefreshArgs.outputs = {mOutput1, mOutput2, mOutput3};
    mEngine.present(mRefreshArgs);
}

/*
 * CompositionEngine::updateCursorAsync
 */

struct CompositionEngineUpdateCursorAsyncTest : public CompositionEngineTest {
public:
    struct Layer {
        Layer() { EXPECT_CALL(outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*layerFE)); }

        StrictMock<mock::OutputLayer> outputLayer;
        sp<StrictMock<mock::LayerFE>> layerFE = sp<StrictMock<mock::LayerFE>>::make();
        LayerFECompositionState layerFEState;
    };

    CompositionEngineUpdateCursorAsyncTest() {
        EXPECT_CALL(*mOutput1, getOutputLayerCount()).WillRepeatedly(Return(0u));
        EXPECT_CALL(*mOutput1, getOutputLayerOrderedByZByIndex(_)).Times(0);

        EXPECT_CALL(*mOutput2, getOutputLayerCount()).WillRepeatedly(Return(1u));
        EXPECT_CALL(*mOutput2, getOutputLayerOrderedByZByIndex(0))
                .WillRepeatedly(Return(&mOutput2Layer1.outputLayer));

        EXPECT_CALL(*mOutput3, getOutputLayerCount()).WillRepeatedly(Return(2u));
        EXPECT_CALL(*mOutput3, getOutputLayerOrderedByZByIndex(0))
                .WillRepeatedly(Return(&mOutput3Layer1.outputLayer));
        EXPECT_CALL(*mOutput3, getOutputLayerOrderedByZByIndex(1))
                .WillRepeatedly(Return(&mOutput3Layer2.outputLayer));
    }

    Layer mOutput2Layer1;
    Layer mOutput3Layer1;
    Layer mOutput3Layer2;
};

TEST_F(CompositionEngineUpdateCursorAsyncTest, handlesNoOutputs) {
    mEngine.updateCursorAsync(mRefreshArgs);
}

TEST_F(CompositionEngineUpdateCursorAsyncTest, handlesNoLayersBeingCursorLayers) {
    EXPECT_CALL(mOutput3Layer1.outputLayer, isHardwareCursor()).WillRepeatedly(Return(false));
    EXPECT_CALL(mOutput3Layer2.outputLayer, isHardwareCursor()).WillRepeatedly(Return(false));
    EXPECT_CALL(mOutput2Layer1.outputLayer, isHardwareCursor()).WillRepeatedly(Return(false));

    mRefreshArgs.outputs = {mOutput1, mOutput2, mOutput3};

    mEngine.updateCursorAsync(mRefreshArgs);
}

TEST_F(CompositionEngineUpdateCursorAsyncTest, handlesMultipleLayersBeingCursorLayers) {
    {
        InSequence seq;
        EXPECT_CALL(mOutput2Layer1.outputLayer, isHardwareCursor()).WillRepeatedly(Return(true));
        EXPECT_CALL(mOutput2Layer1.outputLayer, writeCursorPositionToHWC());
    }

    {
        InSequence seq;
        EXPECT_CALL(mOutput3Layer1.outputLayer, isHardwareCursor()).WillRepeatedly(Return(true));
        EXPECT_CALL(mOutput3Layer1.outputLayer, writeCursorPositionToHWC());
    }

    {
        InSequence seq;
        EXPECT_CALL(mOutput3Layer2.outputLayer, isHardwareCursor()).WillRepeatedly(Return(true));
        EXPECT_CALL(mOutput3Layer2.outputLayer, writeCursorPositionToHWC());
    }

    mRefreshArgs.outputs = {mOutput1, mOutput2, mOutput3};

    mEngine.updateCursorAsync(mRefreshArgs);
}

/*
 * CompositionEngine::preComposition
 */

struct CompositionTestPreComposition : public CompositionEngineTest {
    sp<StrictMock<mock::LayerFE>> mLayer1FE = sp<StrictMock<mock::LayerFE>>::make();
    sp<StrictMock<mock::LayerFE>> mLayer2FE = sp<StrictMock<mock::LayerFE>>::make();
    sp<StrictMock<mock::LayerFE>> mLayer3FE = sp<StrictMock<mock::LayerFE>>::make();
};

TEST_F(CompositionTestPreComposition, preCompositionSetsFrameTimestamp) {
    const nsecs_t before = systemTime(SYSTEM_TIME_MONOTONIC);
    mRefreshArgs.refreshStartTime = systemTime(SYSTEM_TIME_MONOTONIC);
    mEngine.preComposition(mRefreshArgs);
    const nsecs_t after = systemTime(SYSTEM_TIME_MONOTONIC);

    // The frame timestamp should be between the before and after timestamps
    EXPECT_GE(mEngine.getLastFrameRefreshTimestamp(), before);
    EXPECT_LE(mEngine.getLastFrameRefreshTimestamp(), after);
}

TEST_F(CompositionTestPreComposition, preCompositionInvokesLayerPreCompositionWithFrameTimestamp) {
    nsecs_t ts1 = 0;
    nsecs_t ts2 = 0;
    nsecs_t ts3 = 0;
    EXPECT_CALL(*mLayer1FE, onPreComposition(_)).WillOnce(DoAll(SaveArg<0>(&ts1), Return(false)));
    EXPECT_CALL(*mLayer2FE, onPreComposition(_)).WillOnce(DoAll(SaveArg<0>(&ts2), Return(false)));
    EXPECT_CALL(*mLayer3FE, onPreComposition(_)).WillOnce(DoAll(SaveArg<0>(&ts3), Return(false)));

    mRefreshArgs.outputs = {mOutput1};
    mRefreshArgs.layers = {mLayer1FE, mLayer2FE, mLayer3FE};

    mEngine.preComposition(mRefreshArgs);

    // Each of the onPreComposition calls should used the same refresh timestamp
    EXPECT_EQ(ts1, mEngine.getLastFrameRefreshTimestamp());
    EXPECT_EQ(ts2, mEngine.getLastFrameRefreshTimestamp());
    EXPECT_EQ(ts3, mEngine.getLastFrameRefreshTimestamp());
}

TEST_F(CompositionTestPreComposition, preCompositionDefaultsToNoUpdateNeeded) {
    EXPECT_CALL(*mLayer1FE, onPreComposition(_)).WillOnce(Return(false));
    EXPECT_CALL(*mLayer2FE, onPreComposition(_)).WillOnce(Return(false));
    EXPECT_CALL(*mLayer3FE, onPreComposition(_)).WillOnce(Return(false));

    mEngine.setNeedsAnotherUpdateForTest(true);

    mRefreshArgs.outputs = {mOutput1};
    mRefreshArgs.layers = {mLayer1FE, mLayer2FE, mLayer3FE};

    mEngine.preComposition(mRefreshArgs);

    // The call should have cleared the needsAnotherUpdate flag
    EXPECT_FALSE(mEngine.needsAnotherUpdate());
}

TEST_F(CompositionTestPreComposition,
       preCompositionSetsNeedsAnotherUpdateIfAtLeastOneLayerRequestsIt) {
    EXPECT_CALL(*mLayer1FE, onPreComposition(_)).WillOnce(Return(true));
    EXPECT_CALL(*mLayer2FE, onPreComposition(_)).WillOnce(Return(false));
    EXPECT_CALL(*mLayer3FE, onPreComposition(_)).WillOnce(Return(false));

    mRefreshArgs.outputs = {mOutput1};
    mRefreshArgs.layers = {mLayer1FE, mLayer2FE, mLayer3FE};

    mEngine.preComposition(mRefreshArgs);

    EXPECT_TRUE(mEngine.needsAnotherUpdate());
}

struct CompositionEngineOffloadTest : public testing::Test {
    impl::CompositionEngine mEngine;
    CompositionRefreshArgs mRefreshArgs;

    std::shared_ptr<mock::Output> mDisplay1{std::make_shared<StrictMock<mock::Output>>()};
    std::shared_ptr<mock::Output> mDisplay2{std::make_shared<StrictMock<mock::Output>>()};
    std::shared_ptr<mock::Output> mVirtualDisplay{std::make_shared<StrictMock<mock::Output>>()};
    std::shared_ptr<mock::Output> mHalVirtualDisplay{std::make_shared<StrictMock<mock::Output>>()};

    static constexpr PhysicalDisplayId kDisplayId1 = PhysicalDisplayId::fromPort(123u);
    static constexpr PhysicalDisplayId kDisplayId2 = PhysicalDisplayId::fromPort(234u);
    static constexpr GpuVirtualDisplayId kGpuVirtualDisplayId{789u};
    static constexpr HalVirtualDisplayId kHalVirtualDisplayId{456u};

    std::array<impl::OutputCompositionState, 4> mOutputStates;

    void SetUp() override {
        EXPECT_CALL(*mDisplay1, getDisplayId)
                .WillRepeatedly(Return(std::make_optional<DisplayId>(kDisplayId1)));
        EXPECT_CALL(*mDisplay2, getDisplayId)
                .WillRepeatedly(Return(std::make_optional<DisplayId>(kDisplayId2)));
        EXPECT_CALL(*mVirtualDisplay, getDisplayId)
                .WillRepeatedly(Return(std::make_optional<DisplayId>(kGpuVirtualDisplayId)));
        EXPECT_CALL(*mHalVirtualDisplay, getDisplayId)
                .WillRepeatedly(Return(std::make_optional<DisplayId>(kHalVirtualDisplayId)));

        // Most tests will depend on the outputs being enabled.
        for (auto& state : mOutputStates) {
            state.isEnabled = true;
        }

        EXPECT_CALL(*mDisplay1, getState).WillRepeatedly(ReturnRef(mOutputStates[0]));
        EXPECT_CALL(*mDisplay2, getState).WillRepeatedly(ReturnRef(mOutputStates[1]));
        EXPECT_CALL(*mVirtualDisplay, getState).WillRepeatedly(ReturnRef(mOutputStates[2]));
        EXPECT_CALL(*mHalVirtualDisplay, getState).WillRepeatedly(ReturnRef(mOutputStates[3]));
    }

    void setOutputs(std::initializer_list<std::shared_ptr<mock::Output>> outputs) {
        for (auto& output : outputs) {
            // If we call mEngine.present, prepare and present will be called on all the
            // outputs in mRefreshArgs, but that's not the interesting part of the test.
            EXPECT_CALL(*output, prepare(Ref(mRefreshArgs), _)).Times(1);
            EXPECT_CALL(*output, present(Ref(mRefreshArgs)))
                    .WillOnce(Return(ftl::yield<std::monostate>({})));

            mRefreshArgs.outputs.push_back(std::move(output));
        }
    }
};

TEST_F(CompositionEngineOffloadTest, basic) {
    EXPECT_CALL(*mDisplay1, supportsOffloadPresent).WillOnce(Return(true));
    EXPECT_CALL(*mDisplay2, supportsOffloadPresent).WillOnce(Return(true));

    EXPECT_CALL(*mDisplay1, offloadPresentNextFrame).Times(1);
    EXPECT_CALL(*mDisplay2, offloadPresentNextFrame).Times(0);

    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    setOutputs({mDisplay1, mDisplay2});

    mEngine.present(mRefreshArgs);
}

TEST_F(CompositionEngineOffloadTest, dependsOnSupport) {
    EXPECT_CALL(*mDisplay1, supportsOffloadPresent).WillOnce(Return(false));
    EXPECT_CALL(*mDisplay2, supportsOffloadPresent).Times(0);

    EXPECT_CALL(*mDisplay1, offloadPresentNextFrame).Times(0);
    EXPECT_CALL(*mDisplay2, offloadPresentNextFrame).Times(0);

    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    setOutputs({mDisplay1, mDisplay2});

    mEngine.present(mRefreshArgs);
}

TEST_F(CompositionEngineOffloadTest, dependsOnSupport2) {
    EXPECT_CALL(*mDisplay1, supportsOffloadPresent).WillOnce(Return(true));
    EXPECT_CALL(*mDisplay2, supportsOffloadPresent).WillOnce(Return(false));

    EXPECT_CALL(*mDisplay1, offloadPresentNextFrame).Times(0);
    EXPECT_CALL(*mDisplay2, offloadPresentNextFrame).Times(0);

    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    setOutputs({mDisplay1, mDisplay2});

    mEngine.present(mRefreshArgs);
}

TEST_F(CompositionEngineOffloadTest, dependsOnFlag) {
    EXPECT_CALL(*mDisplay1, supportsOffloadPresent).Times(0);
    EXPECT_CALL(*mDisplay2, supportsOffloadPresent).Times(0);

    EXPECT_CALL(*mDisplay1, offloadPresentNextFrame).Times(0);
    EXPECT_CALL(*mDisplay2, offloadPresentNextFrame).Times(0);

    SET_FLAG_FOR_TEST(flags::multithreaded_present, false);
    setOutputs({mDisplay1, mDisplay2});

    mEngine.present(mRefreshArgs);
}

TEST_F(CompositionEngineOffloadTest, oneDisplay) {
    EXPECT_CALL(*mDisplay1, supportsOffloadPresent).Times(0);

    EXPECT_CALL(*mDisplay1, offloadPresentNextFrame).Times(0);

    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    setOutputs({mDisplay1});

    mEngine.present(mRefreshArgs);
}

TEST_F(CompositionEngineOffloadTest, virtualDisplay) {
    EXPECT_CALL(*mDisplay1, supportsOffloadPresent).WillOnce(Return(true));
    EXPECT_CALL(*mDisplay2, supportsOffloadPresent).WillOnce(Return(true));
    EXPECT_CALL(*mVirtualDisplay, supportsOffloadPresent).Times(0);

    EXPECT_CALL(*mDisplay1, offloadPresentNextFrame).Times(1);
    EXPECT_CALL(*mDisplay2, offloadPresentNextFrame).Times(0);
    EXPECT_CALL(*mVirtualDisplay, offloadPresentNextFrame).Times(0);

    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    setOutputs({mDisplay1, mDisplay2, mVirtualDisplay});

    mEngine.present(mRefreshArgs);
}

TEST_F(CompositionEngineOffloadTest, virtualDisplay2) {
    EXPECT_CALL(*mDisplay1, supportsOffloadPresent).WillOnce(Return(true));
    EXPECT_CALL(*mVirtualDisplay, supportsOffloadPresent).Times(0);

    EXPECT_CALL(*mDisplay1, offloadPresentNextFrame).Times(0);
    EXPECT_CALL(*mVirtualDisplay, offloadPresentNextFrame).Times(0);

    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    setOutputs({mDisplay1, mVirtualDisplay});

    mEngine.present(mRefreshArgs);
}

TEST_F(CompositionEngineOffloadTest, halVirtual) {
    EXPECT_CALL(*mDisplay1, supportsOffloadPresent).WillOnce(Return(true));
    EXPECT_CALL(*mHalVirtualDisplay, supportsOffloadPresent).WillOnce(Return(true));

    EXPECT_CALL(*mDisplay1, offloadPresentNextFrame).Times(1);
    EXPECT_CALL(*mHalVirtualDisplay, offloadPresentNextFrame).Times(0);

    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    setOutputs({mDisplay1, mHalVirtualDisplay});

    mEngine.present(mRefreshArgs);
}

TEST_F(CompositionEngineOffloadTest, ordering) {
    EXPECT_CALL(*mVirtualDisplay, supportsOffloadPresent).Times(0);
    EXPECT_CALL(*mHalVirtualDisplay, supportsOffloadPresent).WillOnce(Return(true));
    EXPECT_CALL(*mDisplay1, supportsOffloadPresent).WillOnce(Return(true));
    EXPECT_CALL(*mDisplay2, supportsOffloadPresent).WillOnce(Return(true));

    EXPECT_CALL(*mVirtualDisplay, offloadPresentNextFrame).Times(0);
    EXPECT_CALL(*mHalVirtualDisplay, offloadPresentNextFrame).Times(1);
    EXPECT_CALL(*mDisplay1, offloadPresentNextFrame).Times(1);
    EXPECT_CALL(*mDisplay2, offloadPresentNextFrame).Times(0);

    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    setOutputs({mVirtualDisplay, mHalVirtualDisplay, mDisplay1, mDisplay2});

    mEngine.present(mRefreshArgs);
}

TEST_F(CompositionEngineOffloadTest, dependsOnEnabled) {
    // Disable mDisplay2.
    mOutputStates[1].isEnabled = false;
    EXPECT_CALL(*mDisplay1, supportsOffloadPresent).WillOnce(Return(true));

    // This is not actually called, because it is not enabled, but this distinguishes
    // from the case where it did not return true.
    EXPECT_CALL(*mDisplay2, supportsOffloadPresent).WillRepeatedly(Return(true));

    EXPECT_CALL(*mDisplay1, offloadPresentNextFrame).Times(0);
    EXPECT_CALL(*mDisplay2, offloadPresentNextFrame).Times(0);

    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    setOutputs({mDisplay1, mDisplay2});

    mEngine.present(mRefreshArgs);
}

TEST_F(CompositionEngineOffloadTest, disabledDisplaysDoNotPreventOthersFromOffloading) {
    // Disable mDisplay2.
    mOutputStates[1].isEnabled = false;
    EXPECT_CALL(*mDisplay1, supportsOffloadPresent).WillOnce(Return(true));

    // This is not actually called, because it is not enabled, but this distinguishes
    // from the case where it did not return true.
    EXPECT_CALL(*mDisplay2, supportsOffloadPresent).WillRepeatedly(Return(true));
    EXPECT_CALL(*mHalVirtualDisplay, supportsOffloadPresent).WillOnce(Return(true));

    EXPECT_CALL(*mDisplay1, offloadPresentNextFrame).Times(1);
    EXPECT_CALL(*mDisplay2, offloadPresentNextFrame).Times(0);
    EXPECT_CALL(*mHalVirtualDisplay, offloadPresentNextFrame).Times(0);

    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);
    setOutputs({mDisplay1, mDisplay2, mHalVirtualDisplay});

    mEngine.present(mRefreshArgs);
}

struct CompositionEnginePostCompositionTest : public CompositionEngineTest {
    sp<StrictMock<mock::LayerFE>> mLayer1FE = sp<StrictMock<mock::LayerFE>>::make();
    sp<StrictMock<mock::LayerFE>> mLayer2FE = sp<StrictMock<mock::LayerFE>>::make();
    sp<StrictMock<mock::LayerFE>> mLayer3FE = sp<StrictMock<mock::LayerFE>>::make();
};

TEST_F(CompositionEnginePostCompositionTest, postCompositionReleasesAllFences) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::ce_fence_promise, true);
    ASSERT_TRUE(FlagManager::getInstance().ce_fence_promise());

    EXPECT_CALL(*mLayer1FE, getReleaseFencePromiseStatus)
            .WillOnce(Return(LayerFE::ReleaseFencePromiseStatus::FULFILLED));
    EXPECT_CALL(*mLayer2FE, getReleaseFencePromiseStatus)
            .WillOnce(Return(LayerFE::ReleaseFencePromiseStatus::FULFILLED));
    EXPECT_CALL(*mLayer3FE, getReleaseFencePromiseStatus)
            .WillOnce(Return(LayerFE::ReleaseFencePromiseStatus::INITIALIZED));
    mRefreshArgs.layers = {mLayer1FE, mLayer2FE, mLayer3FE};

    EXPECT_CALL(*mLayer1FE, setReleaseFence(_)).Times(0);
    EXPECT_CALL(*mLayer2FE, setReleaseFence(_)).Times(0);
    EXPECT_CALL(*mLayer3FE, setReleaseFence(_)).Times(1);

    mEngine.postComposition(mRefreshArgs);
}
} // namespace
} // namespace android::compositionengine
