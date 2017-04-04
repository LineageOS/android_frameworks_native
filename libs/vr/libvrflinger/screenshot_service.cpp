#include "screenshot_service.h"

#include <utils/Trace.h>

#include <pdx/default_transport/service_endpoint.h>
#include <private/android_filesystem_config.h>
#include <private/dvr/display_types.h>
#include <private/dvr/trusted_uids.h>

using android::pdx::Message;
using android::pdx::MessageInfo;
using android::pdx::default_transport::Endpoint;
using android::pdx::rpc::DispatchRemoteMethod;
using android::pdx::rpc::RemoteMethodError;
using android::pdx::rpc::RemoteMethodReturn;

namespace android {
namespace dvr {

ScreenshotService::~ScreenshotService() { instance_ = nullptr; }

pdx::Status<void> ScreenshotService::HandleMessage(pdx::Message& message) {
  switch (message.GetOp()) {
    case DisplayScreenshotRPC::GetFormat::Opcode:
      DispatchRemoteMethod<DisplayScreenshotRPC::GetFormat>(
          *this, &ScreenshotService::OnGetFormat, message);
      return {};

    case DisplayScreenshotRPC::TakeScreenshot::Opcode:
      DispatchRemoteMethod<DisplayScreenshotRPC::TakeScreenshot>(
          *this, &ScreenshotService::OnTakeScreenshot, message);
      return {};

    default:
      return Service::HandleMessage(message);
  }
}

int ScreenshotService::OnGetFormat(pdx::Message&) {
  return HAL_PIXEL_FORMAT_RGB_888;
}

ScreenshotData ScreenshotService::OnTakeScreenshot(pdx::Message& message,
                                                   int layer_index) {
  // Also allow AID_SHELL to support vrscreencap commands.
  if (message.GetEffectiveUserId() != AID_SHELL &&
      !IsTrustedUid(message.GetEffectiveUserId())) {
    REPLY_ERROR_RETURN(message, EACCES, {});
  }

  AddWaiter(std::move(message), layer_index);
  return {};
}

void ScreenshotService::AddWaiter(pdx::Message&& message, int layer_index) {
  std::lock_guard<std::mutex> lock(mutex_);
  waiters_.emplace_back(std::move(message), layer_index);
}

void ScreenshotService::TakeIfNeeded(
    std::array<Layer*, HardwareComposer::kMaxHardwareLayers>& hw_layers,
    Compositor& compositor) {
  std::lock_guard<std::mutex> lock(mutex_);

  // Send the buffer contents to all of our waiting clients.
  for (auto& waiter : waiters_) {
    if (waiter.IsDone())
      continue;

    if (waiter.layer_index() == 0) {
      ALOGE(
          "ScreenshotService::TakeIfNeeded: Capturing the composited display "
          "output is not yet supported.");

      waiter.Error(EINVAL);
      continue;
    }

    if (waiter.layer_index() > 0) {
      // Check for hardware layer screenshot requests.
      // Hardware layers are requested with positive indices starting at 1.
      const size_t layer_index = static_cast<size_t>(waiter.layer_index() - 1);

      if (layer_index >= hw_layers.size()) {
        waiter.Error(EINVAL);
        continue;
      }

      auto buffer = hw_layers[layer_index]->GetBuffer();
      if (!buffer) {
        waiter.Error(ENOBUFS);
        continue;
      }

      auto data = compositor.ReadBufferPixels(buffer);
      if (data.empty()) {
        waiter.Error(ENOBUFS);
        continue;
      }

      Take(&waiter, data.data(), buffer->width(), buffer->height(),
           buffer->width());
    } else {
      // Check for compositor input layer screenshot requests.
      // Prewarp surfaces are requested with negative indices starting at -1.
      const size_t layer_index = static_cast<size_t>(-waiter.layer_index() - 1);

      if (layer_index >= compositor.GetLayerCount()) {
        waiter.Error(EINVAL);
        continue;
      }

      int width = 0;
      int height = 0;
      auto data = compositor.ReadLayerPixels(layer_index, &width, &height);
      if (data.empty()) {
        waiter.Error(ENOBUFS);
        continue;
      }

      Take(&waiter, data.data(), width, height, width);
    }
  }

  // Reply with error to requests that did not match up with a source layer.
  for (auto& waiter : waiters_) {
    if (!waiter.IsDone())
      waiter.Error(EAGAIN);
  }
  waiters_.clear();
}

void ScreenshotWaiter::Reply(const ScreenshotData& screenshot) {
  ALOGI("Returning screenshot: size=%zu recv_size=%zu",
        screenshot.buffer.size(), message_.GetReceiveLength());
  RemoteMethodReturn<DisplayScreenshotRPC::TakeScreenshot>(message_,
                                                           screenshot);
}

void ScreenshotWaiter::Error(int error) { RemoteMethodError(message_, error); }

void ScreenshotService::Take(ScreenshotWaiter* waiter, const void* rgba_data,
                             int32_t width, int32_t height, int buffer_stride) {
  ATRACE_NAME(__PRETTY_FUNCTION__);

  bool is_portrait = height > width;
  if (is_portrait) {
    std::swap(width, height);
  }
  int response_stride = width;

  // Convert from RGBA to RGB and if in portrait, rotates to landscape; store
  // the result in the response buffer.
  ScreenshotData screenshot{width, height,
                            std::vector<uint8_t>(width * height * 3)};

  const auto rgba_bytes = static_cast<const uint8_t*>(rgba_data);
  for (int j = 0; j < height; ++j) {
    for (int i = 0; i < width; ++i) {
      // If the screenshot is in portrait mode, rotate into landscape mode.
      const int response_index = is_portrait
                                     ? (height - j - 1) * response_stride + i
                                     : j * response_stride + i;
      const int buffer_index =
          is_portrait ? i * buffer_stride + j : j * buffer_stride + i;
      screenshot.buffer[response_index * 3 + 0] =
          rgba_bytes[buffer_index * 4 + 0];
      screenshot.buffer[response_index * 3 + 1] =
          rgba_bytes[buffer_index * 4 + 1];
      screenshot.buffer[response_index * 3 + 2] =
          rgba_bytes[buffer_index * 4 + 2];
    }
  }

  waiter->Reply(screenshot);
}

ScreenshotService::ScreenshotService()
    : BASE("ScreenshotService",
           Endpoint::Create(DisplayScreenshotRPC::kClientPath)) {
  instance_ = this;
}

ScreenshotService* ScreenshotService::GetInstance() { return instance_; }

ScreenshotService* ScreenshotService::instance_ = nullptr;

}  // namespace dvr
}  // namespace android
