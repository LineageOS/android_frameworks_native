#ifndef ANDROID_DVR_SCREENSHOT_CLIENT_H_
#define ANDROID_DVR_SCREENSHOT_CLIENT_H_

#include <memory>
#include <vector>

#include <pdx/client.h>
#include <private/dvr/display_rpc.h>
#include <system/graphics.h>

namespace android {
namespace dvr {

// Represents a connection to the screenshot service, which allows capturing an
// upcoming frame as it is being rendered to the display.
class ScreenshotClient : public pdx::ClientBase<ScreenshotClient> {
 public:
  int format() const { return format_; }

  // Attempts to take a screenshot. If successful, sets *data to the contents
  // of the screenshot and returns zero. Otherwise, returns a negative error
  // code.
  // |index| is used to match the requested buffer with various buffer layers.
  int Take(std::vector<uint8_t>* data, int index, int* return_width,
           int* return_height);

 private:
  friend BASE;

  ScreenshotClient();

  // Layout information for screenshots.
  int format_;

  ScreenshotClient(const ScreenshotClient&) = delete;
  void operator=(const ScreenshotClient&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SCREENSHOT_CLIENT_H_
