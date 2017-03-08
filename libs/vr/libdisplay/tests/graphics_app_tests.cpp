#include <dvr/graphics.h>
#include <gtest/gtest.h>

TEST(GraphicsAppTests, CreateWarpedDisplaySurfaceParams) {
  int width = 0, height = 0;
  EGLNativeWindowType window = dvrCreateWarpedDisplaySurface(&width, &height);
  EXPECT_GT(width, 0);
  EXPECT_GT(height, 0);
  EXPECT_NE(window, nullptr);
}

TEST(GraphicsAppTests, CreateDisplaySurface) {
  EGLNativeWindowType window = dvrCreateDisplaySurface();
  EXPECT_NE(window, nullptr);
}

TEST(GraphicsAppTests, CreateDisplaySurfaceExtended) {
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

  EGLNativeWindowType window = dvrCreateDisplaySurfaceExtended(surface_params);
  EXPECT_NE(window, nullptr);
  EXPECT_GT(display_width, 0);
  EXPECT_GT(display_height, 0);
  EXPECT_GT(surface_width, 0);
  EXPECT_GT(surface_height, 0);
  EXPECT_GT(inter_lens_meters, 0);
  EXPECT_GT(left_fov[0], 0);
  EXPECT_GT(left_fov[1], 0);
  EXPECT_GT(left_fov[2], 0);
  EXPECT_GT(left_fov[3], 0);
  EXPECT_GT(right_fov[0], 0);
  EXPECT_GT(right_fov[1], 0);
  EXPECT_GT(right_fov[2], 0);
  EXPECT_GT(right_fov[3], 0);
}

TEST(GraphicsAppTests, GetNativeDisplayDimensions) {
  int width, height;
  dvrGetNativeDisplayDimensions(&width, &height);
  EXPECT_GT(width, 0);
  EXPECT_GT(height, 0);
}

TEST(GraphicsAppTests, GetDisplaySurfaceInfo) {
  int ret, width, height, format;
  EGLNativeWindowType window = dvrCreateDisplaySurface();
  ASSERT_NE(window, nullptr);
  ret = dvrGetDisplaySurfaceInfo(window, &width, &height, &format);
  ASSERT_EQ(0, ret);
  ASSERT_GT(width, 0);
  ASSERT_GT(height, 0);
  ASSERT_NE(0, format);
}

// TODO(jpoichet) How to check it worked?
TEST(GraphicsAppTests, GraphicsSurfaceSetVisible) {
  DvrSurfaceParameter surface_params[] = {DVR_SURFACE_PARAMETER_LIST_END};
  DvrGraphicsContext* context = nullptr;
  int result = dvrGraphicsContextCreate(surface_params, &context);
  ASSERT_GE(result, 0);
  ASSERT_NE(context, nullptr);
  dvrGraphicsSurfaceSetVisible(context, 0);
  dvrGraphicsSurfaceSetVisible(context, 1);
  dvrGraphicsSurfaceSetVisible(context, 2);
}

// TODO(jpoichet) How to check it worked?
TEST(GraphicsAppTests, GraphicsSurfaceSetZOrder) {
  DvrSurfaceParameter surface_params[] = {DVR_SURFACE_PARAMETER_LIST_END};
  DvrGraphicsContext* context = nullptr;
  int result = dvrGraphicsContextCreate(surface_params, &context);
  ASSERT_GE(result, 0);
  ASSERT_NE(context, nullptr);
  dvrGraphicsSurfaceSetZOrder(context, -1);
  dvrGraphicsSurfaceSetZOrder(context, 0);
  dvrGraphicsSurfaceSetZOrder(context, 1);
  dvrGraphicsSurfaceSetZOrder(context, 2);
}

TEST(GraphicsAppTests, GraphicsContext) {
  DvrGraphicsContext* context = 0;
  int display_width = 0, display_height = 0;
  int surface_width = 0, surface_height = 0;
  float inter_lens_meters = 0.0f;
  float left_fov[4] = {0.0f};
  float right_fov[4] = {0.0f};
  uint64_t vsync_period = 0;
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
      DVR_SURFACE_PARAMETER_OUT(VSYNC_PERIOD, &vsync_period),
      DVR_SURFACE_PARAMETER_LIST_END,
  };
  dvrGraphicsContextCreate(surface_params, &context);
  EXPECT_NE(nullptr, context);

  DvrFrameSchedule schedule;
  int wait_result = dvrGraphicsWaitNextFrame(context, 0, &schedule);
  EXPECT_EQ(wait_result, 0);
  EXPECT_GE(schedule.vsync_count, 0u);

  dvrBeginRenderFrame(context);

  // Check range of vsync period from 70fps to 100fps.
  // TODO(jbates) Once we have stable hardware, clamp this range down further.
  EXPECT_LT(vsync_period, 1000000000ul / 70ul);
  EXPECT_GT(vsync_period, 1000000000ul / 100ul);

  dvrPresent(context);
  dvrGraphicsContextDestroy(context);
}

TEST(GraphicsAppTests, CustomSurfaceSize) {
  DvrGraphicsContext* context = 0;
  int display_width = 0, display_height = 0;
  int surface_width = 0, surface_height = 0;
  float inter_lens_meters = 0.0f;
  float left_fov[4] = {0.0f};
  float right_fov[4] = {0.0f};
  int disable_warp = 0;
  int req_width = 256, req_height = 128;
  DvrSurfaceParameter surface_params[] = {
      DVR_SURFACE_PARAMETER_IN(WIDTH, req_width),
      DVR_SURFACE_PARAMETER_IN(HEIGHT, req_height),
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
  EXPECT_NE(nullptr, context);

  EXPECT_EQ(req_width, surface_width);
  EXPECT_EQ(req_height, surface_height);
  dvrGraphicsContextDestroy(context);
}

TEST(GraphicsAppTests, CreateVideoMeshSurface) {
  DvrSurfaceParameter surface_params[] = {DVR_SURFACE_PARAMETER_LIST_END};
  DvrGraphicsContext* context = nullptr;
  int result = dvrGraphicsContextCreate(surface_params, &context);
  EXPECT_NE(nullptr, context);
  EXPECT_EQ(result, 0);

  DvrVideoMeshSurface* surface = dvrGraphicsVideoMeshSurfaceCreate(context);
  EXPECT_NE(nullptr, surface);

  dvrGraphicsVideoMeshSurfaceDestroy(surface);
}
