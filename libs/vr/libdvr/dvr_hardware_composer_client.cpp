#include "include/dvr/dvr_hardware_composer_client.h"

#include <android/dvr/IVrComposer.h>
#include <android/dvr/BnVrComposerCallback.h>
#include <android/hardware_buffer.h>
#include <binder/IServiceManager.h>
#include <private/android/AHardwareBufferHelpers.h>

#include <memory>

struct DvrHwcFrame {
  android::dvr::ComposerView::Frame frame;
};

namespace {

class HwcCallback : public android::dvr::BnVrComposerCallback {
 public:
  explicit HwcCallback(DvrHwcOnFrameCallback callback,
                       void* client_state);
  ~HwcCallback() override;

  std::unique_ptr<DvrHwcFrame> DequeueFrame();

 private:
  // android::dvr::BnVrComposerCallback:
  android::binder::Status onNewFrame(
      const android::dvr::ParcelableComposerFrame& frame,
      android::dvr::ParcelableUniqueFd* fence) override;

  DvrHwcOnFrameCallback callback_;
  void* client_state_;

  HwcCallback(const HwcCallback&) = delete;
  void operator=(const HwcCallback&) = delete;
};

HwcCallback::HwcCallback(DvrHwcOnFrameCallback callback, void* client_state)
    : callback_(callback), client_state_(client_state) {}

HwcCallback::~HwcCallback() {}

android::binder::Status HwcCallback::onNewFrame(
    const android::dvr::ParcelableComposerFrame& frame,
    android::dvr::ParcelableUniqueFd* fence) {
  std::unique_ptr<DvrHwcFrame> dvr_frame(new DvrHwcFrame());
  dvr_frame->frame = frame.frame();

  fence->set_fence(android::base::unique_fd(callback_(client_state_,
                                                      dvr_frame.release())));
  return android::binder::Status::ok();
}

}  // namespace

struct DvrHwcClient {
  android::sp<android::dvr::IVrComposer> composer;
  android::sp<HwcCallback> callback;
};

DvrHwcClient* dvrHwcClientCreate(DvrHwcOnFrameCallback callback, void* data) {
  std::unique_ptr<DvrHwcClient> client(new DvrHwcClient());

  android::sp<android::IServiceManager> sm(android::defaultServiceManager());
  client->composer = android::interface_cast<android::dvr::IVrComposer>(
      sm->getService(android::dvr::IVrComposer::SERVICE_NAME()));
  if (!client->composer.get())
    return nullptr;

  client->callback = new HwcCallback(callback, data);
  android::binder::Status status = client->composer->registerObserver(
      client->callback);
  if (!status.isOk())
    return nullptr;

  return client.release();
}

void dvrHwcClientDestroy(DvrHwcClient* client) {
  delete client;
}

void dvrHwcFrameDestroy(DvrHwcFrame* frame) {
  delete frame;
}

Display dvrHwcFrameGetDisplayId(DvrHwcFrame* frame) {
  return frame->frame.display_id;
}

int32_t dvrHwcFrameGetDisplayWidth(DvrHwcFrame* frame) {
  return frame->frame.display_width;
}

int32_t dvrHwcFrameGetDisplayHeight(DvrHwcFrame* frame) {
  return frame->frame.display_height;
}

bool dvrHwcFrameGetDisplayRemoved(DvrHwcFrame* frame) {
  return frame->frame.removed;
}

size_t dvrHwcFrameGetLayerCount(DvrHwcFrame* frame) {
  return frame->frame.layers.size();
}

Layer dvrHwcFrameGetLayerId(DvrHwcFrame* frame, size_t layer_index) {
  return frame->frame.layers[layer_index].id;
}

AHardwareBuffer* dvrHwcFrameGetLayerBuffer(DvrHwcFrame* frame,
                                           size_t layer_index) {
  AHardwareBuffer* buffer = android::AHardwareBuffer_from_GraphicBuffer(
      frame->frame.layers[layer_index].buffer.get());
  AHardwareBuffer_acquire(buffer);
  return buffer;
}

int dvrHwcFrameGetLayerFence(DvrHwcFrame* frame, size_t layer_index) {
  return frame->frame.layers[layer_index].fence->dup();
}

Recti dvrHwcFrameGetLayerDisplayFrame(DvrHwcFrame* frame, size_t layer_index) {
  return Recti{
    frame->frame.layers[layer_index].display_frame.left,
    frame->frame.layers[layer_index].display_frame.top,
    frame->frame.layers[layer_index].display_frame.right,
    frame->frame.layers[layer_index].display_frame.bottom,
  };
}

Rectf dvrHwcFrameGetLayerCrop(DvrHwcFrame* frame, size_t layer_index) {
  return Rectf{
    frame->frame.layers[layer_index].crop.left,
    frame->frame.layers[layer_index].crop.top,
    frame->frame.layers[layer_index].crop.right,
    frame->frame.layers[layer_index].crop.bottom,
  };
}

BlendMode dvrHwcFrameGetLayerBlendMode(DvrHwcFrame* frame, size_t layer_index) {
  return static_cast<BlendMode>(frame->frame.layers[layer_index].blend_mode);
}

float dvrHwcFrameGetLayerAlpha(DvrHwcFrame* frame, size_t layer_index) {
  return frame->frame.layers[layer_index].alpha;
}

uint32_t dvrHwcFrameGetLayerType(DvrHwcFrame* frame, size_t layer_index) {
  return frame->frame.layers[layer_index].type;
}

uint32_t dvrHwcFrameGetLayerApplicationId(DvrHwcFrame* frame,
                                          size_t layer_index) {
  return frame->frame.layers[layer_index].app_id;
}
