// screencap is a tool for taking screenshots using the screenshot service.

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <private/dvr/image_io.h>
#include <private/dvr/screenshot_client.h>

namespace {

// Attempt to take a screenshot and save it to |filename|.
// Returns zero on success, or a non-zero exit code otherwise.
int TakeScreenshot(const std::string& app_name, const std::string& filename,
                   int index) {
  auto error_out = [app_name]() -> std::ostream& {
    return std::cerr << app_name << ": ";
  };

  auto info_out = [app_name]() -> std::ostream& {
    return std::cout << app_name << ": ";
  };

  auto client = android::dvr::ScreenshotClient::Create();

  if (client->format() != HAL_PIXEL_FORMAT_RGB_888) {
    error_out() << "The screenshot format for this device is not supported."
                << std::endl;
    return 1;
  }

  std::vector<uint8_t> image;
  int width = 0;
  int height = 0;
  if (client->Take(&image, index, &width, &height) != 0) {
    error_out() << "Failed to take screenshot." << std::endl;
    return 1;
  }

  info_out() << "Got " << width << "x" << height << " screenshot." << std::endl;

  if (!image_io_write_rgb888(filename.c_str(), width, height, image.data())) {
    error_out() << "Failed to write image to output file " << filename
                << std::endl;
    return 1;
  }

  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  // Parse arguments
  if (argc != 2 && argc != 3) {
    std::cerr
        << "Usage: " << argv[0]
        << " filename.[" DVR_IMAGE_IO_SUPPORTED_WRITE
           "] [INDEX]\n"
           "INDEX: specify 1..n to grab hw_composer layers by index.\n"
           "       specify -n to grab pre-warp layers (-1 is base layer).\n"
           "       the default is 1 (the base hw_composer layer).\n"
           "       an invalid index will result in an error.\n";
    return 1;
  }
  const std::string filename(argv[1]);
  int index = 1;
  if (argc > 2)
    index = atoi(argv[2]);

  // Perform the actual screenshot.
  return TakeScreenshot(argv[0], filename, index);
}
