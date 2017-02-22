#ifndef VR_WINDOW_MANAGER_COMPOSER_IMPL_VR_COMPOSER_VIEW_H_
#define VR_WINDOW_MANAGER_COMPOSER_IMPL_VR_COMPOSER_VIEW_H_

#include <memory>

#include "vr_hwc.h"

namespace android {
namespace dvr {

class VrComposerView : public ComposerView::Observer {
 public:
  class Callback {
   public:
    virtual ~Callback() = default;
    virtual base::unique_fd OnNewFrame(const ComposerView::Frame& frame) = 0;
  };

  VrComposerView(std::unique_ptr<Callback> callback);
  ~VrComposerView() override;

  void Initialize(ComposerView* composer_view);

  // ComposerView::Observer
  base::unique_fd OnNewFrame(const ComposerView::Frame& frame) override;

 private:
  ComposerView* composer_view_;
  std::unique_ptr<Callback> callback_;
  std::mutex mutex_;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_COMPOSER_IMPL_VR_COMPOSER_VIEW_H_
