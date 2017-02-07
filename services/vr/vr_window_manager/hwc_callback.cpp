#include "hwc_callback.h"

#include <android-base/unique_fd.h>
#include <log/log.h>
#include <private/dvr/native_buffer.h>
#include <sync/sync.h>
#include <ui/GraphicBufferMapper.h>

namespace android {
namespace dvr {

namespace {

sp<GraphicBuffer> GetBufferFromHandle(const native_handle_t* handle) {
  uint32_t width = 0, height = 0, stride = 0, layer_count = 1;
  uint64_t producer_usage = 0, consumer_usage = 0;
  int32_t format = 0;

  GraphicBufferMapper& mapper = GraphicBufferMapper::get();
  if (mapper.getDimensions(handle, &width, &height) ||
      mapper.getStride(handle, &stride) ||
      mapper.getFormat(handle, &format) ||
      mapper.getProducerUsage(handle, &producer_usage) ||
      mapper.getConsumerUsage(handle, &consumer_usage)) {
    ALOGE("Failed to read handle properties");
    return nullptr;
  }

  // This will only succeed if gralloc has GRALLOC1_CAPABILITY_LAYERED_BUFFERS
  // capability. Otherwise assume a count of 1.
  mapper.getLayerCount(handle, &layer_count);

  sp<GraphicBuffer> buffer = new GraphicBuffer(
      width, height, format, layer_count, producer_usage, consumer_usage,
      stride, native_handle_clone(handle), true);
  if (mapper.registerBuffer(buffer.get()) != OK) {
    ALOGE("Failed to register buffer");
    return nullptr;
  }

  return buffer;
}

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

void HwcCallback::OnNewFrame(const ComposerView::Frame& frame) {
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

  client_->OnFrame(std::make_unique<Frame>(std::move(hwc_frame)));
}

HwcCallback::Frame::Frame(std::vector<HwcLayer>&& layers)
    : layers_(std::move(layers)) {}

HwcCallback::FrameStatus HwcCallback::Frame::Finish() {
  if (status_ == FrameStatus::kUnfinished)
    status_ = GetFrameStatus(*this);
  return status_;
}

}  // namespace dvr
}  // namespace android
