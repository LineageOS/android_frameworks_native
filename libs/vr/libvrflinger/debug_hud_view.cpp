#include "debug_hud_view.h"

#include <dvr/pose_client.h>

#include "debug_hud_data.h"

namespace android {
namespace dvr {

DebugHudView::DebugHudView(const CompositeHmd& hmd) {
  pose_client_ = dvrPoseCreate();

  display_size_ = hmd.GetDisplayMetrics().GetSizePixels();
  vec2 display_size_meters = hmd.GetDisplayMetrics().GetSizeMeters();
  inter_lens_dist_screen_space_ =
      2.0f * hmd.GetHeadMountMetrics().GetInterLensDistance() /
      std::max(display_size_meters[0], display_size_meters[1]);
}

DebugHudView::~DebugHudView() {
  if (pose_client_)
    dvrPoseDestroy(pose_client_);
  pose_client_ = nullptr;
}

void DebugHudView::Update() {
  // Check for gesture that enables the debug stats HUD.
  if (!pose_client_)
    return;
  DvrPoseAsync pose;
  dvrPoseGet(pose_client_, 0, &pose);
  float32x4_t q = pose.orientation;
  quat orientation(q[3], q[0], q[1], q[2]);
  vec3 up = orientation * vec3(0, 1, 0);
  if (up[1] < -0.8f) {
    ++switch_timer_;
  } else {
    switch_timer_ = 0;
  }
  // A few seconds upside down => toggle stats HUD.
  if (switch_timer_ > 200) {
    switch_timer_ = 0;
    enabled_ = !enabled_;
    DebugHudData::data.ResetStats();
    ALOGE("Toggle debug stats HUD: %s", enabled_ ? "ON" : "OFF");
  }
}

void DebugHudView::Draw() {
  if (!enabled_)
    return;
  if (!debug_text_)
    debug_text_.reset(new DebugText(400, display_size_[0], display_size_[1]));

  const DebugHudData& data = DebugHudData::data;
  const size_t layer_char_count = 50;
  char layer_data[DebugHudData::kMaxLayers][layer_char_count];
  for (size_t i = 0; i < data.num_layers; ++i) {
    float fps = data.layer_data[i].frame_stats.frame_time.GetAverageFps();
    snprintf(layer_data[i], layer_char_count,
             "Layer %d %dx%d%s FPS: %.2f Drops: %d\n", static_cast<int>(i),
             data.layer_data[i].width, data.layer_data[i].height,
             data.layer_data[i].is_separate ? "x2" : "", fps,
             data.layer_data[i].frame_stats.drops);
  }

  float hwc_fps = data.hwc_frame_stats.frame_time.GetAverageFps();

  char text[400];
  float hwc_latency_ms = static_cast<float>(data.hwc_latency) / 1000000.0f;
  snprintf(text, sizeof(text), "HWC FPS: %.2f Latency: %.3f ms Skips: %d\n",
           hwc_fps, hwc_latency_ms, data.hwc_frame_stats.drops);

  for (size_t i = 0; i < data.num_layers; ++i) {
    strncat(text, layer_data[i], sizeof(text) - strlen(text) - 1);
  }

  // Ensure text termination.
  text[sizeof(text) - 1] = '\0';

  glViewport(0, 0, display_size_[0], display_size_[1]);
  glEnable(GL_BLEND);
  // No stereo, because you can see the HUD OK in one eye. Stereo actually
  // makes it more difficult to focus sometimes. To enable stereo:
  // replace the second to last parameter with inter_lens_dist_screen_space_.
  debug_text_->Draw(0.0f, -0.7f * inter_lens_dist_screen_space_, text, 0.0f, 1);
  glDisable(GL_BLEND);
}

}  // namespace dvr
}  // namespace android
