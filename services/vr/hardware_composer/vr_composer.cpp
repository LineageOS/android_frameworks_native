#include "vr_composer.h"

namespace android {
namespace dvr {

VrComposer::VrComposer() {}

VrComposer::~VrComposer() {}

binder::Status VrComposer::registerObserver(
    const sp<IVrComposerCallback>& callback) {
  std::lock_guard<std::mutex> guard(mutex_);

  if (callback_.get()) {
    ALOGE("Failed to register callback, already registered");
    return binder::Status::fromStatusT(ALREADY_EXISTS);
  }

  callback_ = callback;
  IInterface::asBinder(callback_)->linkToDeath(this);
  return binder::Status::ok();
}

base::unique_fd VrComposer::OnNewFrame(const ComposerView::Frame& frame) {
  std::lock_guard<std::mutex> guard(mutex_);

  if (!callback_.get())
    return base::unique_fd();

  ParcelableComposerFrame parcelable_frame(frame);
  ParcelableUniqueFd fence;
  binder::Status ret = callback_->onNewFrame(parcelable_frame, &fence);
  if (!ret.isOk())
    ALOGE("Failed to send new frame: %s", ret.toString8().string());

  return fence.fence();
}

void VrComposer::binderDied(const wp<IBinder>& /* who */) {
  std::lock_guard<std::mutex> guard(mutex_);

  callback_ = nullptr;
}

}  // namespace dvr
}  // namespace android
