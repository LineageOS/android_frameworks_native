#ifndef APPLICATIONS_EXPERIMENTS_SURFACE_FLINGER_DEMO_SURFACE_FLINGER_VIEW_H_
#define APPLICATIONS_EXPERIMENTS_SURFACE_FLINGER_DEMO_SURFACE_FLINGER_VIEW_H_

#include <utils/StrongPointer.h>

#include <memory>

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

  void ReleaseFrame();

 private:
  sp<IVrComposerView> composer_service_;
  std::unique_ptr<HwcCallback> composer_observer_;

  int width_ = 0;
  int height_ = 0;

  SurfaceFlingerView(const SurfaceFlingerView&) = delete;
  void operator=(const SurfaceFlingerView&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // APPLICATIONS_EXPERIMENTS_SURFACE_FLINGER_DEMO_SURFACE_FLINGER_VIEW_H_
