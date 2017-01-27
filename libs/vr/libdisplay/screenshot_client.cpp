#include "include/private/dvr/screenshot_client.h"

#include <cutils/log.h>

#include <mutex>

#include <pdx/default_transport/client_channel_factory.h>
#include <private/dvr/display_rpc.h>

using android::pdx::Transaction;
using android::pdx::rpc::ClientPayload;
using android::pdx::rpc::MessageBuffer;
using android::pdx::rpc::ReplyBuffer;

namespace android {
namespace dvr {

namespace {
// Maximum supported pixels for screenshot capture. If the actual target buffer
// is more than this, an error will be reported.
constexpr int kMaxScreenshotPixels = 6000 * 4000;
}  // namespace

int ScreenshotClient::Take(std::vector<uint8_t>* out_image, int index,
                           int* return_width, int* return_height) {
  if (format_ != HAL_PIXEL_FORMAT_RGB_888) {
    ALOGE("ScreenshotClient::Take: Unsupported layout format: format=%d",
          format_);
    return -ENOSYS;
  }

  // TODO(eieio): Make a cleaner way to ensure enough capacity for send or
  // receive buffers. This method assumes TLS buffers that will maintain
  // capacity across calls within the same thread.
  MessageBuffer<ReplyBuffer>::Reserve(kMaxScreenshotPixels * 3);
  auto status = InvokeRemoteMethod<DisplayScreenshotRPC::TakeScreenshot>(index);
  if (!status) {
    ALOGE("ScreenshotClient::Take: Failed to take screenshot: %s",
          status.GetErrorMessage().c_str());
    return -status.error();
  }

  *return_width = status.get().width;
  *return_height = status.get().height;
  *out_image = std::move(status.take().buffer);
  return 0;
}

ScreenshotClient::ScreenshotClient()
    : BASE(pdx::default_transport::ClientChannelFactory::Create(
          DisplayScreenshotRPC::kClientPath)) {
  auto status = InvokeRemoteMethod<DisplayScreenshotRPC::GetFormat>();
  if (!status) {
    ALOGE(
        "ScreenshotClient::ScreenshotClient: Failed to retrieve screenshot "
        "layout: %s",
        status.GetErrorMessage().c_str());

    Close(status.error());
  } else {
    format_ = status.get();
  }
}

}  // namespace dvr
}  // namespace android
