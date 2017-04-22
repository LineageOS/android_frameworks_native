#ifndef LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_PNG_H_
#define LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_PNG_H_

#include <fstream>

#include <private/dvr/image_io_base.h>

class ImageIoPngWriter : public ImageIoWriter {
 public:
  bool WriteRgb888() override;

  bool WriteChunk(const char* chunk, int chunk_size);

 private:
  ImageIoPngWriter(const char* filename, int width, int height,
                   const uint8_t* image);

  std::ofstream out_;
  bool write_failed_;

  friend class ImageIoWriter;
};

#endif  // LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_PNG_H_
