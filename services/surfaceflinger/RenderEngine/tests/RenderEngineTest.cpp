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

#include <renderengine/RenderEngine.h>
#include <ui/PixelFormat.h>

namespace android {

class RenderEngineTest : public ::testing::Test {
public:
    RenderEngineTest() {
        // Initialize with some sane defaults.
        // TODO(alecmouri): This should probably be the same instance used by
        // SurfaceFlinger eventually.
        mRE = renderengine::RenderEngine::create(static_cast<int32_t>(ui::PixelFormat::RGBA_8888),
                                                 0);
    }

    status_t drawEmptyLayers() {
        renderengine::DisplaySettings settings;
        std::vector<renderengine::LayerSettings> layers;
        // Meaningless buffer since we don't do any drawing
        sp<GraphicBuffer> buffer = new GraphicBuffer();
        base::unique_fd fence;
        return mRE->drawLayers(settings, layers, buffer->getNativeBuffer(), &fence);
    }

private:
    std::unique_ptr<renderengine::RenderEngine> mRE;
};

TEST_F(RenderEngineTest, drawLayers_noLayersToDraw_works) {
    status_t result = drawEmptyLayers();
    ASSERT_EQ(NO_ERROR, result);
}

} // namespace android
