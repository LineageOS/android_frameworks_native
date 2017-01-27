#include <iostream>
#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <dvr/graphics.h>
#include <private/dvr/display_client.h>

#include <cpp_free_mock/cpp_free_mock.h>

// Checks querying the VSync of the device on display surface creation.
TEST(CreateDisplaySurface, QueryVSyncPeriod) {
  using ::testing::_;

  const uint64_t kExpectedVSync = 123456;

  // We only care about the expected VSync value
  android::dvr::DisplayMetrics metrics;
  metrics.vsync_period_ns = kExpectedVSync;

  uint64_t outPeriod;

  DvrSurfaceParameter display_params[] = {
      DVR_SURFACE_PARAMETER_IN(WIDTH, 256),
      DVR_SURFACE_PARAMETER_IN(HEIGHT, 256),
      DVR_SURFACE_PARAMETER_OUT(VSYNC_PERIOD, &outPeriod),
      DVR_SURFACE_PARAMETER_LIST_END,
  };

  // inject the mocking code to the target method
  auto mocked_function =
      MOCKER(&android::dvr::DisplayClient::GetDisplayMetrics);

  // instrument the mock function to return our custom metrics
  EXPECT_CALL(*mocked_function, MOCK_FUNCTION(_, _))
      .WillOnce(::testing::DoAll(::testing::SetArgPointee<1>(metrics),
                                 ::testing::Return(0)));

  ASSERT_NE(nullptr, dvrCreateDisplaySurfaceExtended(display_params));

  EXPECT_EQ(kExpectedVSync, outPeriod);
}
