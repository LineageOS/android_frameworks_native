#include <bufferhub/BufferHubIdGenerator.h>
#include <gtest/gtest.h>

namespace android {
namespace frameworks {
namespace bufferhub {
namespace V1_0 {
namespace implementation {

namespace {

class BufferHubIdGeneratorTest : public testing::Test {
protected:
    BufferHubIdGenerator* mIdGenerator = &BufferHubIdGenerator::getInstance();
};

TEST_F(BufferHubIdGeneratorTest, TestGenerateAndFreeID) {
    uint32_t id = mIdGenerator->getId();
    EXPECT_NE(id, BufferHubIdGenerator::kInvalidId);

    EXPECT_TRUE(mIdGenerator->freeId(id));
    EXPECT_FALSE(mIdGenerator->freeId(id));
}

TEST_F(BufferHubIdGeneratorTest, TestGenerateUniqueIncrementalID) {
    // 10 IDs should not overflow the UniqueIdGenerator to cause a roll back to start, so the
    // resulting IDs should still keep incresing.
    const size_t kTestSize = 10U;
    uint32_t ids[kTestSize];
    for (size_t i = 0UL; i < kTestSize; ++i) {
        ids[i] = mIdGenerator->getId();
        EXPECT_NE(ids[i], BufferHubIdGenerator::kInvalidId);
        if (i >= 1) {
            EXPECT_GT(ids[i], ids[i - 1]);
        }
    }
}

} // namespace

} // namespace implementation
} // namespace V1_0
} // namespace bufferhub
} // namespace frameworks
} // namespace android