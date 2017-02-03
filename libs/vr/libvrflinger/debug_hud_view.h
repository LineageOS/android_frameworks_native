#ifndef ANDROID_DVR_SERVICES_DISPLAYD_DEBUG_HUD_VIEW_H_
#define ANDROID_DVR_SERVICES_DISPLAYD_DEBUG_HUD_VIEW_H_

#include <stdint.h>

#include <utils/Log.h>

#include <private/dvr/composite_hmd.h>
#include <private/dvr/graphics/debug_text.h>

struct DvrPose;

namespace android {
namespace dvr {

class CompositeHmd;

// The view and the controller for the displayd debug HUD.
// The HUD is enabled and disabled by internally tracking the head pose.
// When the head pose is upside down for ~3 seconds, the enabled state toggles.
// See DebugHudData for the data that is reported.
class DebugHudView {
 public:
  DebugHudView(const CompositeHmd& hmd);
  ~DebugHudView();

  // Updates HUD state.
  void Update();

  // Draws HUD into the current framebuffer if it is currently enabled.
  void Draw();

 private:
  DebugHudView(const DebugHudView&) = delete;
  DebugHudView& operator=(const DebugHudView&) = delete;

  DvrPose* pose_client_ = nullptr;
  vec2i display_size_;
  bool enabled_ = false;
  int switch_timer_ = 0;
  float inter_lens_dist_screen_space_ = 0.0f;
  std::unique_ptr<DebugText> debug_text_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SERVICES_DISPLAYD_DEBUG_HUD_VIEW_H_
