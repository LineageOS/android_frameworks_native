#include "surface_flinger_view.h"

#include <impl/vr_composer_view.h>
#include <private/dvr/display_client.h>
#include <private/dvr/native_buffer.h>

#include "hwc_callback.h"
#include "texture.h"

namespace android {
namespace dvr {

SurfaceFlingerView::SurfaceFlingerView() {}

SurfaceFlingerView::~SurfaceFlingerView() {}

bool SurfaceFlingerView::Initialize(HwcCallback::Client *client) {
  const char vr_hwcomposer_name[] = "vr";
  vr_hwcomposer_ = HIDL_FETCH_IComposer(vr_hwcomposer_name);
  if (!vr_hwcomposer_.get()) {
    ALOGE("Failed to get vr_hwcomposer");
    return false;
  }

  if (vr_hwcomposer_->isRemote()) {
    ALOGE("vr_hwcomposer service is remote");
    return false;
  }

  const android::status_t vr_hwcomposer_status =
      vr_hwcomposer_->registerAsService(vr_hwcomposer_name);
  if (vr_hwcomposer_status != OK) {
    ALOGE("Failed to register vr_hwcomposer service");
    return false;
  }

  vr_composer_view_ =
      std::make_unique<VrComposerView>(std::make_unique<HwcCallback>(client));
  vr_composer_view_->Initialize(GetComposerViewFromIComposer(
      vr_hwcomposer_.get()));

  int error = 0;
  auto display_client = DisplayClient::Create(&error);
  SystemDisplayMetrics metrics;

  if (error) {
    ALOGE("Could not connect to display service : %s(%d)", strerror(error), error);
  } else {
    error = display_client->GetDisplayMetrics(&metrics);

    if (error) {
      ALOGE("Could not get display metrics from display service : %s(%d)", strerror(error), error);
    }
  }

  if (error) {
    metrics.display_native_height = 1920;
    metrics.display_native_width = 1080;
    ALOGI("Setting display metrics to default : width=%d height=%d", metrics.display_native_height, metrics.display_native_width);
  }

  // TODO(alexst): Refactor ShellView to account for orientation and change this back.
  width_ = metrics.display_native_height;
  height_ = metrics.display_native_width;
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
