#include "hwc_callback.h"

#include <android-base/unique_fd.h>
#include <log/log.h>
#include <private/dvr/native_buffer.h>
#include <sync/sync.h>
#include <ui/GraphicBufferMapper.h>

namespace android {
namespace dvr {

namespace {

HwcCallback::FrameStatus GetFrameStatus(const HwcCallback::Frame& frame) {
  for (const auto& layer : frame.layers()) {
    // If there is no fence it means the buffer is already finished.
    if (layer.fence->isValid()) {
      status_t result = layer.fence->wait(0);
      if (result != OK) {
        if (result != -ETIME) {
          ALOGE("fence wait on buffer fence failed. status=%d (%s).",
                result, strerror(-result));
          return HwcCallback::FrameStatus::kError;
        }
        return HwcCallback::FrameStatus::kUnfinished;
      }
    }
  }

  return HwcCallback::FrameStatus::kFinished;
}

}  // namespace

HwcCallback::HwcCallback(Client* client) : client_(client) {
}

HwcCallback::~HwcCallback() {
}

base::unique_fd HwcCallback::OnNewFrame(const ComposerView::Frame& display_frame) {
  auto& frame = display_frame.layers;
  std::vector<HwcLayer> hwc_frame(frame.size());

  for (size_t i = 0; i < frame.size(); ++i) {
    hwc_frame[i] = HwcLayer{
      .fence = frame[i].fence,
      .buffer = frame[i].buffer,
      .crop = frame[i].crop,
      .display_frame = frame[i].display_frame,
      .blending = static_cast<int32_t>(frame[i].blend_mode),
      .appid = frame[i].app_id,
      .type = static_cast<HwcLayer::LayerType>(frame[i].type),
      .alpha = frame[i].alpha,
    };
  }

  return client_->OnFrame(std::make_unique<Frame>(
      std::move(hwc_frame), display_frame.display_id, display_frame.removed,
      display_frame.display_width, display_frame.display_height));
}

HwcCallback::Frame::Frame(std::vector<HwcLayer>&& layers, uint32_t display_id,
                          bool removed, int32_t display_width,
                          int32_t display_height)
    : display_id_(display_id),
      removed_(removed),
      display_width_(display_width),
      display_height_(display_height),
      layers_(std::move(layers)) {}

HwcCallback::FrameStatus HwcCallback::Frame::Finish() {
  if (status_ == FrameStatus::kUnfinished)
    status_ = GetFrameStatus(*this);
  return status_;
}

}  // namespace dvr
}  // namespace android
