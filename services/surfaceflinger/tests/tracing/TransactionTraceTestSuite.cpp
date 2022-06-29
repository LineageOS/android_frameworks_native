/*
 * Copyright 2022 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include <LayerTraceGenerator.h>
#include <Tracing/TransactionProtoParser.h>
#include <layerproto/LayerProtoHeader.h>
#include <log/log.h>

using namespace android::surfaceflinger;

namespace android {

class TransactionTraceTestSuite : public testing::Test,
                                  public testing::WithParamInterface<std::filesystem::path> {
public:
    static std::vector<std::filesystem::path> sTransactionTraces;
    static constexpr std::string_view sTransactionTracePrefix = "transactions_trace_";
    static constexpr std::string_view sLayersTracePrefix = "layers_trace_";
    static constexpr std::string_view sTracePostfix = ".winscope";

    proto::TransactionTraceFile mTransactionTrace;
    LayersTraceFileProto mExpectedLayersTraceProto;
    LayersTraceFileProto mActualLayersTraceProto;

protected:
    void SetUp() override {
        std::filesystem::path transactionTracePath = GetParam();
        parseTransactionTraceFromFile(transactionTracePath.c_str(), mTransactionTrace);

        std::string expectedLayersFilename = std::string(sLayersTracePrefix) +
                transactionTracePath.filename().string().substr(sTransactionTracePrefix.length());
        std::string expectedLayersTracePath =
                transactionTracePath.parent_path().string() + "/" + expectedLayersFilename;
        EXPECT_TRUE(std::filesystem::exists(std::filesystem::path(expectedLayersTracePath)));
        parseLayersTraceFromFile(expectedLayersTracePath.c_str(), mExpectedLayersTraceProto);
        TemporaryDir temp_dir;
        std::string actualLayersTracePath =
                std::string(temp_dir.path) + "/" + expectedLayersFilename + "_actual";

        EXPECT_TRUE(
                LayerTraceGenerator().generate(mTransactionTrace, actualLayersTracePath.c_str()))
                << "Failed to generate layers trace from " << transactionTracePath;
        EXPECT_TRUE(std::filesystem::exists(std::filesystem::path(actualLayersTracePath)));
        parseLayersTraceFromFile(actualLayersTracePath.c_str(), mActualLayersTraceProto);
    }

    void parseTransactionTraceFromFile(const char* transactionTracePath,
                                       proto::TransactionTraceFile& outProto) {
        ALOGD("Parsing file %s...", transactionTracePath);
        std::fstream input(transactionTracePath, std::ios::in | std::ios::binary);
        EXPECT_TRUE(input) << "Error could not open " << transactionTracePath;
        EXPECT_TRUE(outProto.ParseFromIstream(&input))
                << "Failed to parse " << transactionTracePath;
    }

    void parseLayersTraceFromFile(const char* layersTracePath, LayersTraceFileProto& outProto) {
        ALOGD("Parsing file %s...", layersTracePath);
        std::fstream input(layersTracePath, std::ios::in | std::ios::binary);
        EXPECT_TRUE(input) << "Error could not open " << layersTracePath;
        EXPECT_TRUE(outProto.ParseFromIstream(&input)) << "Failed to parse " << layersTracePath;
    }
};

std::vector<std::filesystem::path> TransactionTraceTestSuite::sTransactionTraces{};

TEST_P(TransactionTraceTestSuite, validateEndState) {
    ASSERT_GT(mActualLayersTraceProto.entry_size(), 0);
    ASSERT_GT(mExpectedLayersTraceProto.entry_size(), 0);

    auto expectedLastEntry =
            mExpectedLayersTraceProto.entry(mExpectedLayersTraceProto.entry_size() - 1);
    auto actualLastEntry = mActualLayersTraceProto.entry(mActualLayersTraceProto.entry_size() - 1);

    EXPECT_EQ(expectedLastEntry.layers().layers_size(), actualLastEntry.layers().layers_size());
    for (int i = 0;
         i < expectedLastEntry.layers().layers_size() && i < actualLastEntry.layers().layers_size();
         i++) {
        auto expectedLayer = expectedLastEntry.layers().layers(i);
        auto actualLayer = actualLastEntry.layers().layers(i);
        EXPECT_EQ(expectedLayer.id(), actualLayer.id());
        EXPECT_EQ(expectedLayer.name(), actualLayer.name());
        EXPECT_EQ(expectedLayer.parent(), actualLayer.parent());
        EXPECT_EQ(expectedLayer.z(), actualLayer.z());
        EXPECT_EQ(expectedLayer.curr_frame(), actualLayer.curr_frame());
        ALOGV("Validating %s[%d] parent=%d z=%d frame=%" PRIu64, expectedLayer.name().c_str(),
              expectedLayer.id(), expectedLayer.parent(), expectedLayer.z(),
              expectedLayer.curr_frame());
    }
}

std::string PrintToStringParamName(const ::testing::TestParamInfo<std::filesystem::path>& info) {
    const auto& prefix = android::TransactionTraceTestSuite::sTransactionTracePrefix;
    const auto& postfix = android::TransactionTraceTestSuite::sTracePostfix;

    const auto& filename = info.param.filename().string();
    return filename.substr(prefix.length(), filename.length() - prefix.length() - postfix.length());
}

INSTANTIATE_TEST_CASE_P(TransactionTraceTestSuites, TransactionTraceTestSuite,
                        testing::ValuesIn(TransactionTraceTestSuite::sTransactionTraces),
                        PrintToStringParamName);

} // namespace android

int main(int argc, char** argv) {
    for (const auto& entry : std::filesystem::directory_iterator(
                 android::base::GetExecutableDirectory() + "/testdata/")) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto& filename = entry.path().filename().string();
        const auto& prefix = android::TransactionTraceTestSuite::sTransactionTracePrefix;
        if (filename.compare(0, prefix.length(), prefix)) {
            continue;
        }
        const std::string& path = entry.path().string();
        const auto& postfix = android::TransactionTraceTestSuite::sTracePostfix;
        if (path.compare(path.length() - postfix.length(), postfix.length(), postfix)) {
            continue;
        }
        android::TransactionTraceTestSuite::sTransactionTraces.push_back(path);
    }
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}