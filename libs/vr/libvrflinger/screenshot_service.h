#ifndef ANDROID_DVR_SERVICES_DISPLAYD_SCREENSHOT_SERVICE_H_
#define ANDROID_DVR_SERVICES_DISPLAYD_SCREENSHOT_SERVICE_H_

#include <pdx/rpc/pointer_wrapper.h>
#include <pdx/service.h>
#include <private/dvr/ion_buffer.h>

#include <mutex>
#include <vector>

#include "hardware_composer.h"

namespace android {
namespace dvr {

class ScreenshotWaiter {
 public:
  explicit ScreenshotWaiter(pdx::Message&& message, int layer_index)
      : message_(std::move(message)), layer_index_(layer_index) {}
  ScreenshotWaiter(ScreenshotWaiter&&) = default;

  void Reply(const ScreenshotData& screenshot);
  void Error(int error);

  bool IsDone() const { return message_.replied(); }
  int layer_index() const { return layer_index_; }

 private:
  pdx::Message message_;
  int layer_index_;

  ScreenshotWaiter(const ScreenshotWaiter&) = delete;
  void operator=(const ScreenshotWaiter&) = delete;
};

// The screenshot service allows clients to obtain screenshots from displayd.
class ScreenshotService : public pdx::ServiceBase<ScreenshotService> {
 public:
  ~ScreenshotService();

  int HandleMessage(pdx::Message& message) override;

  // Returns true if there is a pending screenshot request.
  bool IsScreenshotRequestPending() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !waiters_.empty();
  }

  // If any clients are currently waiting for a screenshot, read back the
  // contents of requested layers and send the resulting
  // image to the clients.
  void TakeIfNeeded(
      std::array<Layer*, HardwareComposer::kMaxHardwareLayers>& hw_layers,
      Compositor& compositor);

  static ScreenshotService* GetInstance();

 private:
  friend BASE;

  ScreenshotService();

  void AddWaiter(pdx::Message&& message, int layer_index);

  ScreenshotData OnTakeScreenshot(pdx::Message& message, int index);
  int OnGetFormat(pdx::Message& message);

  // Copy the given screenshot data into the message reply.
  void Take(ScreenshotWaiter* waiter, const void* rgba_data, int32_t width,
            int32_t height, int buffer_stride);

  static ScreenshotService* instance_;

  // Protects access to subsequent member variables.
  mutable std::mutex mutex_;
  std::vector<ScreenshotWaiter> waiters_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SERVICES_DISPLAYD_SCREENSHOT_SERVICE_H_
