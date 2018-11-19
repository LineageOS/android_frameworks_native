#undef LOG_TAG
#define LOG_TAG "LayerHistoryUnittests"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <log/log.h>

#include <mutex>

#include "Scheduler/LayerHistory.h"

using testing::_;
using testing::Return;

namespace android {

class LayerHistoryTest : public testing::Test {
public:
    LayerHistoryTest();
    ~LayerHistoryTest() override;

protected:
    std::unique_ptr<LayerHistory> mLayerHistory;
};

LayerHistoryTest::LayerHistoryTest() {
    mLayerHistory = std::make_unique<LayerHistory>();
}
LayerHistoryTest::~LayerHistoryTest() {}

namespace {
TEST_F(LayerHistoryTest, simpleInsertAndGet) {
    mLayerHistory->insert("TestLayer", 0);

    const std::unordered_map<std::string, nsecs_t>& testMap = mLayerHistory->get(0);
    EXPECT_EQ(1, testMap.size());
    auto element = testMap.find("TestLayer");
    EXPECT_EQ("TestLayer", element->first);
    EXPECT_EQ(0, element->second);

    // Testing accessing object at an empty container will return an empty map.
    const std::unordered_map<std::string, nsecs_t>& emptyMap = mLayerHistory->get(1);
    EXPECT_EQ(0, emptyMap.size());
}

TEST_F(LayerHistoryTest, multipleInserts) {
    mLayerHistory->insert("TestLayer0", 0);
    mLayerHistory->insert("TestLayer1", 1);
    mLayerHistory->insert("TestLayer2", 2);
    mLayerHistory->insert("TestLayer3", 3);

    const std::unordered_map<std::string, nsecs_t>& testMap = mLayerHistory->get(0);
    // Because the counter was not incremented, all elements were inserted into the first
    // container.
    EXPECT_EQ(4, testMap.size());
    auto element = testMap.find("TestLayer0");
    EXPECT_EQ("TestLayer0", element->first);
    EXPECT_EQ(0, element->second);

    element = testMap.find("TestLayer1");
    EXPECT_EQ("TestLayer1", element->first);
    EXPECT_EQ(1, element->second);

    element = testMap.find("TestLayer2");
    EXPECT_EQ("TestLayer2", element->first);
    EXPECT_EQ(2, element->second);

    element = testMap.find("TestLayer3");
    EXPECT_EQ("TestLayer3", element->first);
    EXPECT_EQ(3, element->second);

    // Testing accessing object at an empty container will return an empty map.
    const std::unordered_map<std::string, nsecs_t>& emptyMap = mLayerHistory->get(1);
    EXPECT_EQ(0, emptyMap.size());
}

TEST_F(LayerHistoryTest, incrementingCounter) {
    mLayerHistory->insert("TestLayer0", 0);
    mLayerHistory->incrementCounter();
    mLayerHistory->insert("TestLayer1", 1);
    mLayerHistory->insert("TestLayer2", 2);
    mLayerHistory->incrementCounter();
    mLayerHistory->insert("TestLayer3", 3);

    // Because the counter was incremented, the elements were inserted into different
    // containers.
    const std::unordered_map<std::string, nsecs_t>& testMap1 = mLayerHistory->get(0);
    EXPECT_EQ(1, testMap1.size());
    auto element = testMap1.find("TestLayer0");
    EXPECT_EQ("TestLayer0", element->first);
    EXPECT_EQ(0, element->second);

    const std::unordered_map<std::string, nsecs_t>& testMap2 = mLayerHistory->get(1);
    EXPECT_EQ(2, testMap2.size());
    element = testMap2.find("TestLayer1");
    EXPECT_EQ("TestLayer1", element->first);
    EXPECT_EQ(1, element->second);
    element = testMap2.find("TestLayer2");
    EXPECT_EQ("TestLayer2", element->first);
    EXPECT_EQ(2, element->second);

    const std::unordered_map<std::string, nsecs_t>& testMap3 = mLayerHistory->get(2);
    EXPECT_EQ(1, testMap3.size());
    element = testMap3.find("TestLayer3");
    EXPECT_EQ("TestLayer3", element->first);
    EXPECT_EQ(3, element->second);

    // Testing accessing object at an empty container will return an empty map.
    const std::unordered_map<std::string, nsecs_t>& emptyMap = mLayerHistory->get(3);
    EXPECT_EQ(0, emptyMap.size());
}

TEST_F(LayerHistoryTest, clearTheMap) {
    mLayerHistory->insert("TestLayer0", 0);
    mLayerHistory->incrementCounter();

    const std::unordered_map<std::string, nsecs_t>& testMap1 = mLayerHistory->get(0);
    EXPECT_EQ(1, testMap1.size());
    auto element = testMap1.find("TestLayer0");
    EXPECT_EQ("TestLayer0", element->first);
    EXPECT_EQ(0, element->second);

    // The array currently contains 30 elements.
    for (int i = 1; i < 30; ++i) {
        mLayerHistory->insert("TestLayer0", i);
        mLayerHistory->incrementCounter();
    }
    // Expect the map to be cleared.
    const std::unordered_map<std::string, nsecs_t>& testMap2 = mLayerHistory->get(0);
    EXPECT_EQ(0, testMap2.size());

    mLayerHistory->insert("TestLayer30", 30);
    const std::unordered_map<std::string, nsecs_t>& testMap3 = mLayerHistory->get(0);
    element = testMap3.find("TestLayer30");
    EXPECT_EQ("TestLayer30", element->first);
    EXPECT_EQ(30, element->second);
    // The original element in this location does not exist anymore.
    element = testMap3.find("TestLayer0");
    EXPECT_EQ(testMap3.end(), element);
}

} // namespace
} // namespace android