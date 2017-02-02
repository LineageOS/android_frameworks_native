#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <math.h>

#include <dvr/graphics.h>
#include <dvr/pose_client.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <private/dvr/types.h>

using android::dvr::vec4;

namespace {

vec4 ToVec4(float32x4_t rhs) { return vec4(rhs[0], rhs[1], rhs[2], rhs[3]); }

}

DvrGraphicsContext* CreateContext() {
  DvrGraphicsContext* context = nullptr;
  int display_width = 0, display_height = 0;
  int surface_width = 0, surface_height = 0;
  float inter_lens_meters = 0.0f;
  float left_fov[4] = {0.0f};
  float right_fov[4] = {0.0f};
  int disable_warp = 0;
  DvrSurfaceParameter surface_params[] = {
      DVR_SURFACE_PARAMETER_IN(DISABLE_DISTORTION, disable_warp),
      DVR_SURFACE_PARAMETER_OUT(DISPLAY_WIDTH, &display_width),
      DVR_SURFACE_PARAMETER_OUT(DISPLAY_HEIGHT, &display_height),
      DVR_SURFACE_PARAMETER_OUT(SURFACE_WIDTH, &surface_width),
      DVR_SURFACE_PARAMETER_OUT(SURFACE_HEIGHT, &surface_height),
      DVR_SURFACE_PARAMETER_OUT(INTER_LENS_METERS, &inter_lens_meters),
      DVR_SURFACE_PARAMETER_OUT(LEFT_FOV_LRBT, left_fov),
      DVR_SURFACE_PARAMETER_OUT(RIGHT_FOV_LRBT, right_fov),
      DVR_SURFACE_PARAMETER_LIST_END,
  };
  dvrGraphicsContextCreate(surface_params, &context);
  return context;
}

TEST(SensorAppTests, GetPose) {
  DvrGraphicsContext* context = CreateContext();
  ASSERT_NE(nullptr, context);
  DvrPose* client = dvrPoseCreate();
  ASSERT_NE(nullptr, client);

  DvrPoseAsync last_pose;
  uint32_t last_vsync_count = 0;
  for (int i = 0; i < 10; ++i) {
    DvrFrameSchedule schedule;
    dvrGraphicsWaitNextFrame(context, 0, &schedule);
    DvrPoseAsync pose;
    int ret = dvrPoseGet(client, schedule.vsync_count, &pose);
    ASSERT_EQ(0, ret);

    // Check for unit-length quaternion to verify valid pose.
    vec4 quaternion = ToVec4(pose.orientation);
    float length = quaternion.norm();
    EXPECT_GT(0.001, fabs(1.0f - length));

    // Check for different data each frame, but skip first few to allow
    // startup anomalies.
    if (i > 0) {
      if (last_vsync_count == schedule.vsync_count)
        ALOGE("vsync did not increment: %u", schedule.vsync_count);
      if (pose.timestamp_ns == last_pose.timestamp_ns)
        ALOGE("timestamp did not change: %" PRIu64, pose.timestamp_ns);
      // TODO(jbates) figure out why the bots are not passing this check.
      // EXPECT_NE(last_vsync_count, schedule.vsync_count);
      // EXPECT_NE(pose.timestamp_ns, last_pose.timestamp_ns);
    }
    last_pose = pose;
    last_vsync_count = schedule.vsync_count;
    dvrBeginRenderFrame(context);
    glClear(GL_DEPTH_BUFFER_BIT | GL_COLOR_BUFFER_BIT);
    dvrPresent(context);
  }

  dvrPoseDestroy(client);
  dvrGraphicsContextDestroy(context);
}

TEST(SensorAppTests, PoseRingBuffer) {
  DvrGraphicsContext* context = CreateContext();
  ASSERT_NE(nullptr, context);
  DvrPose* client = dvrPoseCreate();
  ASSERT_NE(nullptr, client);

  DvrPoseRingBufferInfo info;
  int ret = dvrPoseGetRingBuffer(client, &info);
  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, info.buffer);
  EXPECT_LE(2u, info.min_future_count);
  EXPECT_LE(8u, info.total_count);

  DvrPoseAsync last_pose;
  uint32_t last_vsync_count = 0;
  for (int i = 0; i < 10; ++i) {
    DvrFrameSchedule schedule;
    dvrGraphicsWaitNextFrame(context, 0, &schedule);
    DvrPoseAsync pose;
    ret = dvrPoseGet(client, schedule.vsync_count, &pose);
    ASSERT_EQ(0, ret);

    // Check for unit-length quaternion to verify valid pose.
    vec4 quaternion = ToVec4(pose.orientation);
    float length = quaternion.norm();
    EXPECT_GT(0.001, fabs(1.0f - length));

    // Check for different data each frame, but skip first few to allow
    // startup anomalies.
    if (i > 0) {
      if (last_vsync_count == schedule.vsync_count)
        ALOGE("vsync did not increment: %u", schedule.vsync_count);
      if (pose.timestamp_ns == last_pose.timestamp_ns)
        ALOGE("timestamp did not change: %" PRIu64, pose.timestamp_ns);
      // TODO(jbates) figure out why the bots are not passing this check.
      // EXPECT_NE(last_vsync_count, schedule.vsync_count);
      // EXPECT_NE(pose.timestamp_ns, last_pose.timestamp_ns);
    }
    last_pose = pose;
    last_vsync_count = schedule.vsync_count;
    dvrBeginRenderFrame(context);
    glClear(GL_DEPTH_BUFFER_BIT | GL_COLOR_BUFFER_BIT);
    dvrPresent(context);
  }

  dvrPoseDestroy(client);
  dvrGraphicsContextDestroy(context);
}
