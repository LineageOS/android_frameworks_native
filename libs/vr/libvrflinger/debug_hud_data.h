#ifndef ANDROID_DVR_SERVICES_DISPLAYD_DEBUG_HUD_DATA_H_
#define ANDROID_DVR_SERVICES_DISPLAYD_DEBUG_HUD_DATA_H_

#include <stdint.h>

#include <private/dvr/clock_ns.h>
#include <private/dvr/frame_time_history.h>

namespace android {
namespace dvr {

// Tracks debug stats for the displayd debug HUD. Unless otherwise noted,
// there is no synchronization of data accesses to avoid performance impact.
// All accesses to this data are on the displayd HWC post thread. Accesses from
// other threads will need to be duly protected from races.
// This is a lightweight struct to make it easy to add and remove
// tracking data.
struct DebugHudData {
  // Maximum supported layers for the debug HUD.
  enum { kMaxLayers = 4 };

  // The global singleton HUD data instance.
  static DebugHudData data;

  // Tracks framerate and skipped frames.
  struct FrameStats {
    void AddFrame() {
      int64_t now = GetSystemClockNs();
      frame_time.AddSample(now - last_frame_ts);
      last_frame_ts = now;
    }

    void SkipFrame() {
      AddFrame();
      ++drops;
    }

    int drops = 0;
    int64_t last_frame_ts = 0;
    FrameTimeHistory frame_time;
  };

  // Debug data for compositor layers (applications, system UI, etc).
  struct LayerData {
    void Reset() {
      ResetStats();
      width = 0;
      height = 0;
      is_separate = false;
    }

    void ResetStats() { frame_stats.drops = 0; }

    FrameStats frame_stats;
    int width = 0;
    int height = 0;
    bool is_separate = false;
  };

  // Resets the stats.
  void ResetStats() {
    hwc_frame_stats.drops = 0;
    hwc_latency = 0;
    for (auto& l : layer_data)
      l.ResetStats();
  }

  // Resets the layer configuration.
  void ResetLayers() {
    num_layers = 0;
    for (auto& l : layer_data)
      l.Reset();
  }

  // Tracks a frame arrival for the given layer.
  void AddLayerFrame(size_t layer) {
    if (layer < kMaxLayers) {
      num_layers = std::max(layer + 1, num_layers);
      layer_data[layer].frame_stats.AddFrame();
    }
  }

  // Tracks a frame skip/drop for the given layer.
  void SkipLayerFrame(size_t layer) {
    if (layer < kMaxLayers) {
      num_layers = std::max(layer + 1, num_layers);
      layer_data[layer].frame_stats.SkipFrame();
    }
  }

  // Sets the resolution and other details of the layer.
  void SetLayerInfo(size_t layer, int width, int height, bool is_separate) {
    if (layer < kMaxLayers) {
      num_layers = std::max(layer + 1, num_layers);
      layer_data[layer].width = width;
      layer_data[layer].height = height;
      layer_data[layer].is_separate = is_separate;
    }
  }

  FrameStats hwc_frame_stats;
  int64_t hwc_latency = 0;
  size_t num_layers = 0;
  LayerData layer_data[kMaxLayers];
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SERVICES_DISPLAYD_DEBUG_HUD_DATA_H_
