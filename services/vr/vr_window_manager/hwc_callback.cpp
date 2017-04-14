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

void HwcCallback::HwcLayer::PrintLayer() {
  ALOGI("appid=%d, type=%d, alpha=%.2f, cursor=%dx%d, color=%02X%02X%02X%02X, "
      "crop=%.1f,%.1f,%.1f,%.1f, display=%d,%d,%d,%d, dataspace=%d, "
      "transform=%d", appid, type, alpha, cursor_x, cursor_y, color.r, color.g,
      color.b, color.a, crop.left, crop.top, crop.right, crop.bottom,
      display_frame.left, display_frame.right, display_frame.top,
      display_frame.bottom, dataspace, transform);
}

HwcCallback::HwcCallback(Client* client) : client_(client) {
}

HwcCallback::~HwcCallback() {
}

binder::Status HwcCallback::onNewFrame(
    const ParcelableComposerFrame& parcelable_frame,
    ParcelableUniqueFd* fence) {
  ComposerView::Frame frame = parcelable_frame.frame();
  std::vector<HwcLayer> hwc_frame(frame.layers.size());
  for (size_t i = 0; i < frame.layers.size(); ++i) {
    const ComposerView::ComposerLayer& layer = frame.layers[i];
    hwc_frame[i] = HwcLayer{
      .fence = layer.fence,
      .buffer = layer.buffer,
      .crop = layer.crop,
      .display_frame = layer.display_frame,
      .blending = static_cast<int32_t>(layer.blend_mode),
      .appid = layer.app_id,
      .type = static_cast<HwcLayer::LayerType>(layer.type),
      .alpha = layer.alpha,
      .cursor_x = layer.cursor_x,
      .cursor_y = layer.cursor_y,
      .color = layer.color,
      .dataspace = layer.dataspace,
      .transform = layer.transform,
    };
  }

  fence->set_fence(client_->OnFrame(std::make_unique<Frame>(
      std::move(hwc_frame), frame.display_id, frame.removed,
      frame.display_width, frame.display_height)));
  return binder::Status::ok();
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
