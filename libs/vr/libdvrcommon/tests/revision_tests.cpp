#include <gtest/gtest.h>
#include <private/dvr/revision.h>

namespace {

TEST(RevisionTests, GetProduct) {
  ASSERT_NE(DVR_PRODUCT_UNKNOWN, dvr_get_product());
}

TEST(RevisionTests, GetRevision) {
  ASSERT_NE(DVR_REVISION_UNKNOWN, dvr_get_revision());
}

TEST(RevisionTests, GetRevisionStr) {
  ASSERT_NE(nullptr, dvr_get_product_revision_str());
}

TEST(RevisionTests, GetSerialNo) {
  ASSERT_NE(nullptr, dvr_get_serial_number());
}

}  // namespace

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
