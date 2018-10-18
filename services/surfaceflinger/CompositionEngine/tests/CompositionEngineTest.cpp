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

#include <compositionengine/impl/CompositionEngine.h>
#include <gtest/gtest.h>

namespace android::compositionengine {
namespace {

class CompositionEngineTest : public testing::Test {
public:
    ~CompositionEngineTest() override;

    impl::CompositionEngine engine;
};

CompositionEngineTest::~CompositionEngineTest() = default;

TEST_F(CompositionEngineTest, canInstantiateCompositionEngine) {
    auto engine = impl::createCompositionEngine();
    EXPECT_TRUE(engine.get() != nullptr);
}

} // namespace
} // namespace android::compositionengine
