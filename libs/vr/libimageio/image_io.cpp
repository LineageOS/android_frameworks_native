#define LOG_TAG "ImageIo"

#include <private/dvr/image_io.h>

#include <algorithm>
#include <memory>
#include <string>

#include <private/dvr/image_io_base.h>
#include <private/dvr/image_io_logging.h>
#include <private/dvr/image_io_png.h>
#include <private/dvr/image_io_ppm.h>

namespace {

// Returns true if |str| ends with |suffix|.
bool EndsWith(const std::string& str, const std::string& suffix) {
  if (str.length() < suffix.length())
    return false;

  return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}

// Returns lower case copy of the input string.
std::string ToLower(std::string str) {
  std::transform(str.begin(), str.end(), str.begin(),
                 [](char x) { return std::tolower(x); });
  return str;
}

}  // namespace

std::unique_ptr<ImageIoReader> ImageIoReader::Create(const char* filename) {
  std::unique_ptr<ImageIoReader> reader;
  std::string filename_lower = ToLower(filename);

  if (EndsWith(filename_lower, ".ppm"))
    reader.reset(new ImageIoPpmReader(filename));

  if (!reader) {
    ALOGE("Unknown/unsupported image file format.");
    return nullptr;
  }

  return reader;
}

std::unique_ptr<ImageIoWriter> ImageIoWriter::Create(const char* filename,
                                                     int width, int height,
                                                     const uint8_t* image) {
  std::unique_ptr<ImageIoWriter> writer;
  std::string filename_lower = ToLower(filename);

  if (EndsWith(filename_lower, ".ppm"))
    writer.reset(new ImageIoPpmWriter(filename, width, height, image));
  else if (EndsWith(filename_lower, ".png"))
    writer.reset(new ImageIoPngWriter(filename, width, height, image));

  if (!writer) {
    ALOGE("Unknown/unsupported image file format.");
    return nullptr;
  }

  return writer;
}

extern "C" {

bool image_io_write_rgb888(const char* filename, int width, int height,
                           const uint8_t* image) {
  auto writer = ImageIoWriter::Create(filename, width, height, image);
  if (!writer)
    return false;
  return writer->WriteRgb888();
}

bool image_io_read_rgb888(const char* filename, int* width, int* height,
                          uint8_t** image) {
  auto reader = ImageIoReader::Create(filename);
  if (!reader)
    return false;
  if (!reader->ReadRgb888())
    return false;
  *width = reader->width();
  *height = reader->height();
  *image = reader->ReleaseImage();
  return true;
}

void image_io_release_buffer(uint8_t* image) { delete[] image; }

}  // extern "C"
