#ifndef APPLICATIONS_EXPERIMENTS_SURFACE_FLINGER_DEMO_SURFACE_FLINGER_VIEW_H_
#define APPLICATIONS_EXPERIMENTS_SURFACE_FLINGER_DEMO_SURFACE_FLINGER_VIEW_H_

#include <memory>

#include "hwc_callback.h"

namespace android {
namespace dvr {

class IDisplay;
class IVrComposer;
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

  bool Initialize(HwcCallback::Client *client);

  bool GetTextures(const HwcCallback::Frame& layers,
                   std::vector<TextureLayer>* texture_layers,
                   TextureLayer* ime_layer, bool debug,
                   bool skip_first_layer) const;

 private:
  sp<IVrComposer> vr_composer_;
  sp<HwcCallback> composer_callback_;

  SurfaceFlingerView(const SurfaceFlingerView&) = delete;
  void operator=(const SurfaceFlingerView&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // APPLICATIONS_EXPERIMENTS_SURFACE_FLINGER_DEMO_SURFACE_FLINGER_VIEW_H_
