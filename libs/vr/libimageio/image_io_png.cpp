#define LOG_TAG "ImageIo"

#include <private/dvr/image_io_png.h>

#include <fstream>
#include <string>
#include <vector>

#include <private/dvr/image_io_logging.h>

#include "png.h"

namespace {

void WriteChunkCallback(png_structp out_ptr, png_bytep chunk_ptr,
                        png_size_t chunk_size) {
  auto* writer = static_cast<ImageIoPngWriter*>(png_get_io_ptr(out_ptr));
  const char* chunk = reinterpret_cast<const char*>(chunk_ptr);
  writer->WriteChunk(chunk, chunk_size);
}

}  // namespace

ImageIoPngWriter::ImageIoPngWriter(const char* filename, int width, int height,
                                   const uint8_t* image)
    : ImageIoWriter(filename, width, height, image),
      out_(filename_),
      write_failed_(false) {}

bool ImageIoPngWriter::WriteChunk(const char* chunk, int chunk_size) {
  out_.write(chunk, chunk_size);
  if (!out_) {
    if (write_failed_) {
      // Error was already logged once.
      return false;
    }

    ALOGE("Failed to write .png image to %s.", filename_.c_str());
    write_failed_ = true;
    return false;
  }
  return true;
}

// Writes RGB888 image to png file.
// Refactored from Chromium:
// WebKit/Source/platform/image-encoders/skia/PNGImageEncoder.cpp
bool ImageIoPngWriter::WriteRgb888() {
  if (width_ <= 0 || height_ <= 0) {
    ALOGE("Invalid width or height.");
    return false;
  }

  if (!out_) {
    ALOGE("Failed to open output file %s.", filename_.c_str());
    return false;
  }

  png_struct* png = png_create_write_struct(PNG_LIBPNG_VER_STRING, 0, 0, 0);
  png_info* info = png_create_info_struct(png);
  if (!png || !info || setjmp(png_jmpbuf(png))) {
    png_destroy_write_struct(png ? &png : 0, info ? &info : 0);
    return false;
  }

  png_set_compression_level(png, 3);
  png_set_filter(png, PNG_FILTER_TYPE_BASE, PNG_FILTER_SUB);

  png_set_write_fn(png, this, WriteChunkCallback, 0);
  png_set_IHDR(png, info, width_, height_, 8, PNG_COLOR_TYPE_RGB, 0, 0, 0);
  png_write_info(png, info);

  unsigned char* pixels =
      reinterpret_cast<unsigned char*>(const_cast<uint8_t*>(image_));
  const size_t stride = width_ * 3;
  for (int y = 0; y < height_; ++y) {
    png_write_row(png, pixels);
    if (write_failed_)
      return false;
    pixels += stride;
  }

  png_write_end(png, info);
  png_destroy_write_struct(&png, &info);

  return !write_failed_;
}
