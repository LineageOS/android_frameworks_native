/*
 * Copyright 2019 The Android Open Source Project
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

#include <compositionengine/impl/OutputLayer.h>
#include <compositionengine/mock/Layer.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/Output.h>
#include <gtest/gtest.h>

namespace android::compositionengine {
namespace {

using testing::StrictMock;

class OutputLayerTest : public testing::Test {
public:
    ~OutputLayerTest() override = default;

    compositionengine::mock::Output mOutput;
    std::shared_ptr<compositionengine::mock::Layer> mLayer{
            new StrictMock<compositionengine::mock::Layer>()};
    sp<compositionengine::mock::LayerFE> mLayerFE{
            new StrictMock<compositionengine::mock::LayerFE>()};
    impl::OutputLayer mOutputLayer{mOutput, mLayer, mLayerFE};
};

/* ------------------------------------------------------------------------
 * Basic construction
 */

TEST_F(OutputLayerTest, canInstantiateOutputLayer) {}

} // namespace
} // namespace android::compositionengine
