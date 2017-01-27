#include "vr_composer_view.h"

namespace android {
namespace dvr {

VrComposerView::VrComposerView() : composer_view_(nullptr) {}

VrComposerView::~VrComposerView() {
  composer_view_->UnregisterObserver(this);
}

void VrComposerView::Initialize(ComposerView* composer_view) {
  composer_view_ = composer_view;
  composer_view_->RegisterObserver(this);
}

Return<void> VrComposerView::registerCallback(
    const sp<IVrComposerCallback>& callback) {
  callback_ = callback;
  return Void();
}

Return<void> VrComposerView::releaseFrame() {
  composer_view_->ReleaseFrame();
  return Void();
}

void VrComposerView::OnNewFrame(const ComposerView::Frame& frame) {
  if (!callback_.get()) {
    releaseFrame();
    return;
  }

  std::vector<IVrComposerCallback::Layer> layers;
  std::vector<native_handle_t*> fences;
  for (size_t i = 0; i < frame.size(); ++i) {
    native_handle_t* fence;
    if (frame[i].fence->isValid()) {
      fence = native_handle_create(1, 0);
      fence->data[0] = frame[i].fence->dup();
    } else {
      fence = native_handle_create(0, 0);
    }
    fences.push_back(fence);

    layers.push_back(IVrComposerCallback::Layer{
      .buffer = hidl_handle(frame[i].buffer->getNativeBuffer()->handle),
      .fence = hidl_handle(fence),
      .display_frame = frame[i].display_frame,
      .crop = frame[i].crop,
      .blend_mode= frame[i].blend_mode,
      .alpha = frame[i].alpha,
      .type = frame[i].type,
      .app_id = frame[i].app_id,
    });
  }

  auto status =
      callback_->onNewFrame(hidl_vec<IVrComposerCallback::Layer>(layers));
  if (!status.isOk()) {
    ALOGE("Failed to send onNewFrame: %s", status.description().c_str());
    releaseFrame();
  }

  for (size_t i = 0; i < fences.size(); ++i) {
    native_handle_close(fences[i]);
    native_handle_delete(fences[i]);
  }
}

VrComposerView* GetVrComposerViewFromIVrComposerView(IVrComposerView* view) {
  return static_cast<VrComposerView*>(view);
}

IVrComposerView* HIDL_FETCH_IVrComposerView(const char* name) {
  return new VrComposerView();
}

}  // namespace dvr
}  // namespace android
