#include "hwc_callback.h"

#include <gralloc_priv.h>
#include <android-base/unique_fd.h>
#include <log/log.h>
#include <private/dvr/native_buffer.h>
#include <sync/sync.h>

namespace android {
namespace dvr {

namespace {

sp<GraphicBuffer> GetBufferFromHandle(const native_handle_t* handle) {
  // TODO(dnicoara): Fix this once gralloc1 is available.
  private_handle_t* private_handle = private_handle_t::dynamicCast(handle);
  sp<GraphicBuffer> buffer = new GraphicBuffer(
      private_handle->width, private_handle->height, private_handle->format, 1,
      GraphicBuffer::USAGE_HW_COMPOSER | GraphicBuffer::USAGE_HW_TEXTURE |
      GraphicBuffer::USAGE_HW_2D | GraphicBuffer::USAGE_HW_RENDER,
      private_handle->width, native_handle_clone(handle), true);
  if (GraphicBufferMapper::get().registerBuffer(buffer.get()) != OK) {
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

HwcCallback::HwcCallback(IVrComposerView* composer_view, Client* client)
    : composer_view_(composer_view),
      client_(client) {
  composer_view_->registerCallback(this);
}

HwcCallback::~HwcCallback() {
  composer_view_->registerCallback(nullptr);
}

Return<void> HwcCallback::onNewFrame(
    const hidl_vec<IVrComposerCallback::Layer>& frame) {

  std::vector<HwcLayer> hwc_frame(frame.size());
  for (size_t i = 0; i < frame.size(); ++i) {
    int fence = frame[i].fence.getNativeHandle()->numFds ?
        dup(frame[i].fence.getNativeHandle()->data[0]) : -1;

    hwc_frame[i] = HwcLayer{
      .fence = new Fence(fence),
      .buffer = GetBufferFromHandle(frame[i].buffer.getNativeHandle()),
      .crop = frame[i].crop,
      .display_frame = frame[i].display_frame,
      .blending = static_cast<int32_t>(frame[i].blend_mode),
      .appid = frame[i].app_id,
      .type = static_cast<HwcLayer::LayerType>(frame[i].type),
      .alpha = frame[i].alpha,
    };
  }

  std::lock_guard<std::mutex> guard(mutex_);
  if (client_)
    client_->OnFrame(std::make_unique<Frame>(std::move(hwc_frame)));

  return Void();
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
