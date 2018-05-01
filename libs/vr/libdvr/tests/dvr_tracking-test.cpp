#include <android/log.h>
#include <gtest/gtest.h>

#include "dvr_api_test.h"

namespace {

class DvrTrackingTest : public DvrApiTest {};

#if DVR_TRACKING_IMPLEMENTED
// TODO(b/78173557): Implement dvrTrackingXXX API test.
#else

TEST_F(DvrTrackingTest, NotImplemented) {
  ASSERT_TRUE(api_.TrackingCameraCreate != nullptr);
  ASSERT_TRUE(api_.TrackingCameraDestroy != nullptr);
  ASSERT_TRUE(api_.TrackingCameraStart != nullptr);
  ASSERT_TRUE(api_.TrackingCameraStop != nullptr);

  EXPECT_EQ(api_.TrackingCameraCreate(nullptr), -ENOSYS);
  EXPECT_EQ(api_.TrackingCameraStart(nullptr, nullptr), -ENOSYS);
  EXPECT_EQ(api_.TrackingCameraStop(nullptr), -ENOSYS);
}

#endif  // DVR_TRACKING_IMPLEMENTED

}  // namespace
