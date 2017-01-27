#ifndef VR_WINDOW_MANAGER_COMPOSER_IMPL_VR_COMPOSER_VIEW_H_
#define VR_WINDOW_MANAGER_COMPOSER_IMPL_VR_COMPOSER_VIEW_H_

#include <android/dvr/composer/1.0/IVrComposerCallback.h>
#include <android/dvr/composer/1.0/IVrComposerView.h>

#include "vr_hwc.h"

namespace android {
namespace dvr {

using composer::V1_0::IVrComposerView;
using composer::V1_0::IVrComposerCallback;

class VrComposerView : public IVrComposerView, public ComposerView::Observer {
 public:
  VrComposerView();
  ~VrComposerView() override;

  void Initialize(ComposerView* composer_view);

  // IVrComposerView
  Return<void> registerCallback(const sp<IVrComposerCallback>& callback)
      override;
  Return<void> releaseFrame() override;

  // ComposerView::Observer
  void OnNewFrame(const ComposerView::Frame& frame) override;

 private:
  ComposerView* composer_view_;
  sp<IVrComposerCallback> callback_;
};

VrComposerView* GetVrComposerViewFromIVrComposerView(IVrComposerView* view);

IVrComposerView* HIDL_FETCH_IVrComposerView(const char* name);

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_COMPOSER_IMPL_VR_COMPOSER_VIEW_H_
