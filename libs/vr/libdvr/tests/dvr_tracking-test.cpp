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

  ASSERT_TRUE(api_.TrackingSensorsCreate != nullptr);
  ASSERT_TRUE(api_.TrackingSensorsDestroy != nullptr);
  ASSERT_TRUE(api_.TrackingSensorsStart != nullptr);
  ASSERT_TRUE(api_.TrackingSensorsStop != nullptr);

  EXPECT_EQ(api_.TrackingSensorsCreate(nullptr, nullptr), -ENOSYS);
  EXPECT_EQ(api_.TrackingSensorsStart(nullptr, nullptr), -ENOSYS);
  EXPECT_EQ(api_.TrackingSensorsStop(nullptr), -ENOSYS);
}

#endif  // DVR_TRACKING_IMPLEMENTED

}  // namespace
