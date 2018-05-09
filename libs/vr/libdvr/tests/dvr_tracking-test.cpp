#include <android/log.h>
#include <gtest/gtest.h>

#include "dvr_api_test.h"

namespace {

class DvrTrackingTest : public DvrApiTest {};

#if DVR_TRACKING_IMPLEMENTED

TEST_F(DvrTrackingTest, Implemented) {
  ASSERT_TRUE(api_.TrackingCameraCreate != nullptr);
  ASSERT_TRUE(api_.TrackingCameraStart != nullptr);
  ASSERT_TRUE(api_.TrackingCameraStop != nullptr);
}

TEST_F(DvrTrackingTest, CreateFailsForInvalidInput) {
  int ret;
  ret = api_.TrackingCameraCreate(nullptr);
  EXPECT_EQ(ret, -EINVAL);

  DvrTrackingCamera* camera = reinterpret_cast<DvrTrackingCamera*>(42);
  ret = api_.TrackingCameraCreate(&camera);
  EXPECT_EQ(ret, -EINVAL);
}

TEST_F(DvrTrackingTest, CreateDestroy) {
  DvrTrackingCamera* camera = nullptr;
  int ret = api_.TrackingCameraCreate(&camera);

  EXPECT_EQ(ret, 0);
  ASSERT_TRUE(camera != nullptr);

  api_.TrackingCameraDestroy(camera);
}

#else  // !DVR_TRACKING_IMPLEMENTED

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
  EXPECT_EQ(api_.TrackingSensorsStart(nullptr, nullptr, nullptr), -ENOSYS);
  EXPECT_EQ(api_.TrackingSensorsStop(nullptr), -ENOSYS);
}

#endif  // DVR_TRACKING_IMPLEMENTED

}  // namespace
