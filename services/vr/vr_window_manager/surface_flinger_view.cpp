#include "surface_flinger_view.h"

#include <android/dvr/IVrComposer.h>
#include <binder/IServiceManager.h>
#include <private/dvr/native_buffer.h>

#include "hwc_callback.h"
#include "texture.h"

namespace android {
namespace dvr {

SurfaceFlingerView::SurfaceFlingerView() {}

SurfaceFlingerView::~SurfaceFlingerView() {}

bool SurfaceFlingerView::Initialize(HwcCallback::Client *client) {
  sp<IServiceManager> sm(defaultServiceManager());
  vr_composer_ = interface_cast<IVrComposer>(
      sm->getService(IVrComposer::SERVICE_NAME()));

  String8 service_name(IVrComposer::SERVICE_NAME().string());
  if (!vr_composer_.get()) {
    ALOGE("Faild to connect to %s", service_name.c_str());
    return false;
  }

  composer_callback_ = new HwcCallback(client);
  binder::Status status = vr_composer_->registerObserver(composer_callback_);
  if (!status.isOk()) {
    ALOGE("Failed to register observer with %s", service_name.c_str());
    return false;
  }

  return true;
}

bool SurfaceFlingerView::GetTextures(const HwcCallback::Frame& frame,
                                     std::vector<TextureLayer>* texture_layers,
                                     TextureLayer* ime_layer,
                                     bool debug, bool skip_first_layer) const {
  auto& layers = frame.layers();
  texture_layers->clear();

  size_t start = 0;
  // Skip the second layer if it is from the VR app.
  if (!debug && skip_first_layer) {
    start = 2;
  }

  for (size_t i = start; i < layers.size(); ++i) {
    if (!debug && layers[i].should_skip_layer())
      continue;

    std::unique_ptr<Texture> texture(new Texture());
    if (!texture->Initialize(layers[i].buffer->getNativeBuffer())) {
      ALOGE("Failed to create texture");
      texture_layers->clear();
      return false;
    }

    TextureLayer texture_layer = {
        std::move(texture), layers[i].crop, layers[i].display_frame,
        layers[i].blending, layers[i].alpha,
    };
    if (debug && layers[i].type == HwcCallback::HwcLayer::kInputMethod) {
      *ime_layer = std::move(texture_layer);
    } else {
      texture_layers->emplace_back(std::move(texture_layer));
    }
  }

  return true;
}

}  // namespace dvr
}  // namespace android
