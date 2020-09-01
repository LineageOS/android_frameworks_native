/*
 * Copyright (C) 2020 The Android Open Source Project
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
#include <input/Input.h>
#include <ios>
#include <memory>
#include <unordered_set>

namespace android::test {

class IdGeneratorTest : public testing::TestWithParam<IdGenerator::Source> {
protected:
    void SetUp() override { mGenerator.reset(new IdGenerator(GetParam())); }

    std::unique_ptr<IdGenerator> mGenerator;
};

TEST_P(IdGeneratorTest, GenerateRandomNumber) {
    for (int i = 0; i < 500; ++i) {
        mGenerator->nextId();
    }
}

TEST_P(IdGeneratorTest, GenerateRandomNumberWithProperFlag) {
    for (int i = 0; i < 500; ++i) {
        int32_t id = mGenerator->nextId();
        IdGenerator::Source source = IdGenerator::getSource(id);
        EXPECT_EQ(source, GetParam())
                << std::hex << "Generator generated a value with wrong source. Value: 0x" << id
                << " Source: 0x" << static_cast<int32_t>(source);
    }
}

INSTANTIATE_TEST_SUITE_P(SourceInstantiation, IdGeneratorTest,
                         testing::Values(IdGenerator::Source::INPUT_READER,
                                         IdGenerator::Source::INPUT_DISPATCHER,
                                         IdGenerator::Source::OTHER));
} // namespace android::test
