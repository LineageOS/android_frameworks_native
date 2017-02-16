#include "vr_composer_view.h"

namespace android {
namespace dvr {

VrComposerView::VrComposerView(
    std::unique_ptr<VrComposerView::Callback> callback)
    : composer_view_(nullptr), callback_(std::move(callback)) {}

VrComposerView::~VrComposerView() {
  composer_view_->UnregisterObserver(this);
}

void VrComposerView::Initialize(ComposerView* composer_view) {
  composer_view_ = composer_view;
  composer_view_->RegisterObserver(this);
}

void VrComposerView::ReleaseFrame() {
  LOG_ALWAYS_FATAL_IF(!composer_view_, "VrComposerView not initialized");
  composer_view_->ReleaseFrame();
}

void VrComposerView::OnNewFrame(const ComposerView::Frame& frame) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!callback_.get()) {
    ReleaseFrame();
    return;
  }

  callback_->OnNewFrame(frame);
}

}  // namespace dvr
}  // namespace android
