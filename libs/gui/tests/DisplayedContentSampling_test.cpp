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

#include <gtest/gtest.h>

#include <binder/ProcessState.h>
#include <gui/ISurfaceComposer.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <inttypes.h>

namespace android {

using Transaction = SurfaceComposerClient::Transaction;

static constexpr uint32_t INVALID_MASK = 0x10;
class DisplayedContentSamplingTest : public ::testing::Test {
protected:
    void SetUp() {
        mComposerClient = new SurfaceComposerClient;
        ASSERT_EQ(OK, mComposerClient->initCheck());
        mDisplayToken = mComposerClient->getBuiltInDisplay(ISurfaceComposer::eDisplayIdMain);
        ASSERT_TRUE(mDisplayToken);
    }

    bool shouldSkipTest(status_t status) {
        if (status == PERMISSION_DENIED) {
            SUCCEED() << "permissions denial, skipping test";
            return true;
        }
        if (status == INVALID_OPERATION) {
            SUCCEED() << "optional function not supported, skipping test";
            return true;
        }
        return false;
    }

    sp<SurfaceComposerClient> mComposerClient;
    sp<IBinder> mDisplayToken;
};

TEST_F(DisplayedContentSamplingTest, GetDisplayedContentSamplingAttributesAreSane) {
    ui::PixelFormat format;
    ui::Dataspace dataspace;
    uint8_t componentMask = 0;
    status_t status =
            mComposerClient->getDisplayedContentSamplingAttributes(mDisplayToken, &format,
                                                                   &dataspace, &componentMask);
    if (shouldSkipTest(status)) {
        return;
    }
    EXPECT_EQ(OK, status);
    EXPECT_LE(componentMask, INVALID_MASK);
}
} // namespace android
