/*
 * Copyright 2023 The Android Open Source Project
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
#define LOG_TAG "CommitTest"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <renderengine/mock/RenderEngine.h>
#include "TestableSurfaceFlinger.h"

namespace android {

class CommitTest : public testing::Test {
protected:
    CommitTest() {
        mFlinger.setupMockScheduler();
        mFlinger.setupComposer(std::make_unique<Hwc2::mock::Composer>());
        mFlinger.setupRenderEngine(std::unique_ptr<renderengine::RenderEngine>(mRenderEngine));
    }
    TestableSurfaceFlinger mFlinger;
    renderengine::mock::RenderEngine* mRenderEngine = new renderengine::mock::RenderEngine();
};

namespace {

TEST_F(CommitTest, noUpdatesDoesNotScheduleComposite) {
    bool unused;
    bool mustComposite = mFlinger.updateLayerSnapshots(VsyncId{1}, /*frameTimeNs=*/0,
                                                       /*transactionsFlushed=*/0, unused);
    EXPECT_FALSE(mustComposite);
}

// Ensure that we handle eTransactionNeeded correctly
TEST_F(CommitTest, eTransactionNeededFlagSchedulesComposite) {
    // update display level color matrix
    mFlinger.setDaltonizerType(ColorBlindnessType::Deuteranomaly);
    bool unused;
    bool mustComposite = mFlinger.updateLayerSnapshots(VsyncId{1}, /*frameTimeNs=*/0,
                                                       /*transactionsFlushed=*/0, unused);
    EXPECT_TRUE(mustComposite);
}

} // namespace
} // namespace android
