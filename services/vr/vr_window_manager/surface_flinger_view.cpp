#include "surface_flinger_view.h"

#include <binder/IServiceManager.h>
#include <impl/vr_composer_view.h>
#include <private/dvr/native_buffer.h>

#include "hwc_callback.h"
#include "texture.h"

namespace android {
namespace dvr {

SurfaceFlingerView::SurfaceFlingerView() {}

SurfaceFlingerView::~SurfaceFlingerView() {}

bool SurfaceFlingerView::Initialize(HwcCallback::Client *client) {
  const char instance[] = "DaydreamDisplay";
  composer_service_ = IVrComposerView::getService(instance);
  if (composer_service_ == nullptr) {
    ALOGE("Failed to initialize composer service");
    return false;
  }

  if (!composer_service_->isRemote()) {
    ALOGE("Composer service is not remote");
    return false;
  }

  // TODO(dnicoara): Query this from the composer service.
  width_ = 1920;
  height_ = 1080;

  composer_observer_.reset(new HwcCallback(composer_service_.get(), client));
  return true;
}

bool SurfaceFlingerView::GetTextures(const HwcCallback::Frame& frame,
                                     std::vector<TextureLayer>* texture_layers,
                                     TextureLayer* ime_layer,
                                     bool debug) const {
  auto& layers = frame.layers();
  texture_layers->clear();

  size_t start = 0;
  // Skip the second layer if it is from the VR app.
  if (!debug) {
    start = 1;
    if (layers[0].appid && layers[0].appid == layers[1].appid)
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
