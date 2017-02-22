#ifndef APPLICATIONS_EXPERIMENTS_SURFACE_FLINGER_DEMO_SURFACE_FLINGER_VIEW_H_
#define APPLICATIONS_EXPERIMENTS_SURFACE_FLINGER_DEMO_SURFACE_FLINGER_VIEW_H_

#include <memory>

#include <impl/vr_composer_view.h>

#include "hwc_callback.h"

namespace android {
namespace dvr {

class IDisplay;
class Texture;

struct TextureLayer {
  std::unique_ptr<Texture> texture;
  Rectf crop;
  Recti display_frame;
  int32_t blending;
  float alpha;
};

class SurfaceFlingerView {
 public:
  SurfaceFlingerView();
  ~SurfaceFlingerView();

  int width() const { return width_; }
  int height() const { return height_; }

  bool Initialize(HwcCallback::Client *client);

  bool GetTextures(const HwcCallback::Frame& layers,
                   std::vector<TextureLayer>* texture_layers,
                   TextureLayer* ime_layer, bool debug,
                   bool skip_first_layer) const;

 private:
  sp<IComposer> vr_hwcomposer_;
  std::unique_ptr<VrComposerView> vr_composer_view_;
  int width_ = 0;
  int height_ = 0;

  SurfaceFlingerView(const SurfaceFlingerView&) = delete;
  void operator=(const SurfaceFlingerView&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // APPLICATIONS_EXPERIMENTS_SURFACE_FLINGER_DEMO_SURFACE_FLINGER_VIEW_H_
