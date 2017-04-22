#ifndef LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_PPM_H_
#define LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_PPM_H_

#include <private/dvr/image_io_base.h>

class ImageIoPpmReader : public ImageIoReader {
 public:
  bool ReadRgb888() override;

 private:
  explicit ImageIoPpmReader(const char* filename) : ImageIoReader(filename) {}

  friend class ImageIoReader;
};

class ImageIoPpmWriter : public ImageIoWriter {
 public:
  bool WriteRgb888() override;

 private:
  ImageIoPpmWriter(const char* filename, int width, int height,
                   const uint8_t* image)
      : ImageIoWriter(filename, width, height, image) {}

  friend class ImageIoWriter;
};

#endif  // LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_PPM_H_
