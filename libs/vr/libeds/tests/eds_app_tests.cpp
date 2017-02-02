#include <EGL/egl.h>
#include <GLES2/gl2.h>

#include <dvr/graphics.h>
#include <dvr/pose_client.h>
#include <gtest/gtest.h>
#include <private/dvr/graphics/shader_program.h>
#include <private/dvr/types.h>

namespace {

#define POSE_BINDING 0

#ifndef STRINGIFY
#define STRINGIFY2(s) #s
#define STRINGIFY(s) STRINGIFY2(s)
#endif

static const char g_vert_shader[] =
    "layout(binding = " STRINGIFY(POSE_BINDING) ", std140)\n"
    "uniform LateLatchData {\n"
    "  mat4 uViewProjection;\n"
    "};\n"
    "void main() {\n"
    "  vec2 verts[4];\n"
    "  verts[0] = vec2(-1, -1);\n"
    "  verts[1] = vec2(-1, 1);\n"
    "  verts[2] = vec2(1, -1);\n"
    "  verts[3] = vec2(1, 1);\n"
    "  gl_Position = uViewProjection * vec4(verts[gl_VertexID], 0.0, 1.0);\n"
    "}\n";

static const char g_frag_shader[] =
    "precision mediump float;\n"
    "out vec4 outColor;\n"
    "void main() {\n"
    "  outColor = vec4(1.0);\n"
    "}\n";

DvrGraphicsContext* CreateContext(int* surface_width, int* surface_height) {
  DvrGraphicsContext* context = nullptr;
  int display_width = 0, display_height = 0;
  float inter_lens_meters = 0.0f;
  float left_fov[4] = {0.0f};
  float right_fov[4] = {0.0f};
  int disable_warp = 0;
  int enable_late_latch = 1;
  DvrSurfaceParameter surface_params[] = {
      DVR_SURFACE_PARAMETER_IN(DISABLE_DISTORTION, disable_warp),
      DVR_SURFACE_PARAMETER_IN(ENABLE_LATE_LATCH, enable_late_latch),
      DVR_SURFACE_PARAMETER_OUT(DISPLAY_WIDTH, &display_width),
      DVR_SURFACE_PARAMETER_OUT(DISPLAY_HEIGHT, &display_height),
      DVR_SURFACE_PARAMETER_OUT(SURFACE_WIDTH, surface_width),
      DVR_SURFACE_PARAMETER_OUT(SURFACE_HEIGHT, surface_height),
      DVR_SURFACE_PARAMETER_OUT(INTER_LENS_METERS, &inter_lens_meters),
      DVR_SURFACE_PARAMETER_OUT(LEFT_FOV_LRBT, left_fov),
      DVR_SURFACE_PARAMETER_OUT(RIGHT_FOV_LRBT, right_fov),
      DVR_SURFACE_PARAMETER_LIST_END,
  };
  dvrGraphicsContextCreate(surface_params, &context);
  return context;
}

}  // namespace

TEST(SensorAppTests, EdsWithLateLatch) {
  int surface_width = 0, surface_height = 0;
  DvrGraphicsContext* context = CreateContext(&surface_width, &surface_height);
  ASSERT_NE(nullptr, context);

  android::dvr::ShaderProgram shader(g_vert_shader, g_frag_shader);

  for (int i = 0; i < 5; ++i) {
    DvrFrameSchedule schedule;
    dvrGraphicsWaitNextFrame(context, 0, &schedule);

    const auto ident_mat = android::dvr::mat4::Identity();
    const float* ident_mats[] = { ident_mat.data(), ident_mat.data() };
    GLuint late_latch_buffer_id = 0;
    int ret = dvrBeginRenderFrameLateLatch(context, 0, schedule.vsync_count, 2,
                                           ident_mats, ident_mats, ident_mats,
                                           &late_latch_buffer_id);
    EXPECT_EQ(0, ret);
    for (int eye = 0; eye < 2; ++eye) {
      if (eye == 0)
        glViewport(0, 0, surface_width / 2, surface_height);
      else
        glViewport(surface_width / 2, 0, surface_width / 2, surface_height);

      glClear(GL_DEPTH_BUFFER_BIT | GL_COLOR_BUFFER_BIT);
      shader.Use();

      // Bind late latch pose matrix buffer.
      glBindBufferRange(
          GL_UNIFORM_BUFFER, POSE_BINDING, late_latch_buffer_id,
          offsetof(DvrGraphicsLateLatchData, view_proj_matrix[eye]),
          16 * sizeof(float));

      // TODO(jbates): use transform feedback here to grab the vertex output
      // and verify that it received late-latch pose data. Combine this with
      // mocked pose data to verify that late-latching is working.
      glDrawArrays(GL_POINTS, 0, 4);
    }
    dvrPresent(context);
  }

  glFinish();
  dvrGraphicsContextDestroy(context);
}

TEST(SensorAppTests, EdsWithoutLateLatch) {
  int surface_width = 0, surface_height = 0;
  DvrGraphicsContext* context = CreateContext(&surface_width, &surface_height);
  ASSERT_NE(nullptr, context);
  DvrPose* client = dvrPoseCreate();
  ASSERT_NE(nullptr, client);

  for (int i = 0; i < 5; ++i) {
    DvrFrameSchedule schedule;
    dvrGraphicsWaitNextFrame(context, 0, &schedule);
    DvrPoseAsync pose;
    int ret = dvrPoseGet(client, schedule.vsync_count, &pose);
    ASSERT_EQ(0, ret);

    dvrBeginRenderFrameEds(context, pose.orientation, pose.translation);
    for (int eye = 0; eye < 2; ++eye) {
      if (eye == 0)
        glViewport(0, 0, surface_width / 2, surface_height);
      else
        glViewport(surface_width / 2, 0, surface_width / 2, surface_height);

      glClear(GL_DEPTH_BUFFER_BIT | GL_COLOR_BUFFER_BIT);
      EXPECT_EQ(0, ret);
    }
    dvrPresent(context);
  }

  dvrPoseDestroy(client);
  dvrGraphicsContextDestroy(context);
}
