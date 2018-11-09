#include <bufferhub/UniqueIdGenerator.h>
#include <gtest/gtest.h>

namespace android {
namespace frameworks {
namespace bufferhub {
namespace V1_0 {
namespace implementation {

namespace {

class UniqueIdGeneratorTest : public testing::Test {
protected:
    UniqueIdGenerator mIdGenerator;
};

TEST_F(UniqueIdGeneratorTest, TestGenerateAndFreeID) {
    uint32_t id = mIdGenerator.getId();
    EXPECT_NE(id, UniqueIdGenerator::kInvalidId);

    EXPECT_TRUE(mIdGenerator.freeId(id));
    EXPECT_FALSE(mIdGenerator.freeId(id));
}

TEST_F(UniqueIdGeneratorTest, TestGenerateUniqueIncrementalID) {
    // 10 IDs should not overflow the UniqueIdGenerator to cause a roll back to start, so the
    // resulting IDs should still keep incresing.
    const size_t kTestSize = 10U;
    uint32_t ids[kTestSize];
    for (int i = 0; i < kTestSize; ++i) {
        ids[i] = mIdGenerator.getId();
        EXPECT_NE(ids[i], UniqueIdGenerator::kInvalidId);
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