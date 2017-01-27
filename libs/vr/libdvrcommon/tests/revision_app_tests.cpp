#include <dvr/test/app_test.h>
#include <gtest/gtest.h>
#include <private/dvr/revision.h>

// Making sure this information is not available
// inside the sandbox

namespace {

TEST(RevisionTests, GetProduct) {
  ASSERT_EQ(DVR_PRODUCT_UNKNOWN, dvr_get_product());
}

TEST(RevisionTests, GetRevision) {
  ASSERT_EQ(DVR_REVISION_UNKNOWN, dvr_get_revision());
}

TEST(RevisionTests, GetRevisionStr) {
  ASSERT_STREQ("", dvr_get_product_revision_str());
}

TEST(RevisionTests, GetSerialNo) {
  ASSERT_EQ(nullptr, dvr_get_serial_number());
}

}  // namespace

int main(int argc, char* argv[]) {
  dreamos::test::AppTestBegin();
  ::testing::InitGoogleTest(&argc, argv);
  int result = RUN_ALL_TESTS();
  dreamos::test::AppTestEnd(result);
  return result;
}
