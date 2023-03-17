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
#include <unordered_map>

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

struct LayerInfo {
    int32_t id;
    std::string name;
    int32_t parent;
    int z;
    uint64_t curr_frame;
    float x;
    float y;
    uint32_t bufferWidth;
    uint32_t bufferHeight;
};

bool operator==(const LayerInfo& lh, const LayerInfo& rh) {
    return std::make_tuple(lh.id, lh.name, lh.parent, lh.z, lh.curr_frame) ==
            std::make_tuple(rh.id, rh.name, rh.parent, rh.z, rh.curr_frame);
}

bool compareById(const LayerInfo& a, const LayerInfo& b) {
    return a.id < b.id;
}

inline void PrintTo(const LayerInfo& info, ::std::ostream* os) {
    *os << "Layer [" << info.id << "] name=" << info.name << " parent=" << info.parent
        << " z=" << info.z << " curr_frame=" << info.curr_frame << " x=" << info.x
        << " y=" << info.y << " bufferWidth=" << info.bufferWidth
        << " bufferHeight=" << info.bufferHeight;
}

struct find_id : std::unary_function<LayerInfo, bool> {
    int id;
    find_id(int id) : id(id) {}
    bool operator()(LayerInfo const& m) const { return m.id == id; }
};

static LayerInfo getLayerInfoFromProto(::android::surfaceflinger::LayerProto& proto) {
    return {proto.id(),
            proto.name(),
            proto.parent(),
            proto.z(),
            proto.curr_frame(),
            proto.has_position() ? proto.position().x() : -1,
            proto.has_position() ? proto.position().y() : -1,
            proto.has_active_buffer() ? proto.active_buffer().width() : 0,
            proto.has_active_buffer() ? proto.active_buffer().height() : 0};
}

TEST_P(TransactionTraceTestSuite, validateEndState) {
    ASSERT_GT(mActualLayersTraceProto.entry_size(), 0);
    ASSERT_GT(mExpectedLayersTraceProto.entry_size(), 0);

    auto expectedLastEntry =
            mExpectedLayersTraceProto.entry(mExpectedLayersTraceProto.entry_size() - 1);
    auto actualLastEntry = mActualLayersTraceProto.entry(mActualLayersTraceProto.entry_size() - 1);

    EXPECT_EQ(expectedLastEntry.layers().layers_size(), actualLastEntry.layers().layers_size());

    std::vector<LayerInfo> expectedLayers;
    expectedLayers.reserve(static_cast<size_t>(expectedLastEntry.layers().layers_size()));
    for (int i = 0; i < expectedLastEntry.layers().layers_size(); i++) {
        auto layer = expectedLastEntry.layers().layers(i);
        LayerInfo layerInfo = getLayerInfoFromProto(layer);
        expectedLayers.push_back(layerInfo);
    }
    std::sort(expectedLayers.begin(), expectedLayers.end(), compareById);

    std::unordered_map<int32_t /* snapshotId*/, int32_t /*layerId*/> snapshotIdToLayerId;
    std::vector<LayerInfo> actualLayers;
    actualLayers.reserve(static_cast<size_t>(actualLastEntry.layers().layers_size()));
    for (int i = 0; i < actualLastEntry.layers().layers_size(); i++) {
        auto layer = actualLastEntry.layers().layers(i);
        LayerInfo layerInfo = getLayerInfoFromProto(layer);
        snapshotIdToLayerId[layerInfo.id] = static_cast<int32_t>(layer.original_id());
        actualLayers.push_back(layerInfo);
    }

    for (auto& layer : actualLayers) {
        layer.id = snapshotIdToLayerId[layer.id];
        auto it = snapshotIdToLayerId.find(layer.parent);
        layer.parent = it == snapshotIdToLayerId.end() ? -1 : it->second;
    }

    std::sort(actualLayers.begin(), actualLayers.end(), compareById);

    size_t i = 0;
    for (; i < actualLayers.size() && i < expectedLayers.size(); i++) {
        auto it = std::find_if(actualLayers.begin(), actualLayers.end(),
                               find_id(expectedLayers[i].id));
        EXPECT_NE(it, actualLayers.end());
        EXPECT_EQ(expectedLayers[i], *it);
        ALOGV("Validating %s[%d] parent=%d z=%d frame=%" PRIu64, expectedLayers[i].name.c_str(),
              expectedLayers[i].id, expectedLayers[i].parent, expectedLayers[i].z,
              expectedLayers[i].curr_frame);
    }

    EXPECT_EQ(expectedLayers.size(), actualLayers.size());

    if (i < actualLayers.size()) {
        for (size_t j = 0; j < actualLayers.size(); j++) {
            if (std::find_if(expectedLayers.begin(), expectedLayers.end(),
                             find_id(actualLayers[j].id)) == expectedLayers.end()) {
                ALOGD("actualLayers [%d]:%s parent=%d z=%d frame=%" PRIu64, actualLayers[j].id,
                      actualLayers[j].name.c_str(), actualLayers[j].parent, actualLayers[j].z,
                      actualLayers[j].curr_frame);
            }
        }
        FAIL();
    }

    if (i < expectedLayers.size()) {
        for (size_t j = 0; j < expectedLayers.size(); j++) {
            if (std::find_if(actualLayers.begin(), actualLayers.end(),
                             find_id(expectedLayers[j].id)) == actualLayers.end()) {
                ALOGD("expectedLayers [%d]:%s parent=%d z=%d frame=%" PRIu64, expectedLayers[j].id,
                      expectedLayers[j].name.c_str(), expectedLayers[j].parent, expectedLayers[j].z,
                      expectedLayers[j].curr_frame);
            }
        }
        FAIL();
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