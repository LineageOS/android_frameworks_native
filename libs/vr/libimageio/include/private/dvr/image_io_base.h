#ifndef LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_BASE_H_
#define LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_BASE_H_

#include <memory>
#include <string>

class ImageIoReader {
 public:
  virtual ~ImageIoReader() {}

  static std::unique_ptr<ImageIoReader> Create(const char* filename);

  virtual bool ReadRgb888() = 0;

  int width() const { return width_; }

  int height() const { return height_; }

  uint8_t* ReleaseImage() { return image_.release(); }

 protected:
  int width_;
  int height_;
  std::unique_ptr<uint8_t[]> image_;
  const std::string filename_;

  explicit ImageIoReader(const char* filename)
      : width_(0), height_(0), filename_(filename) {}

  ImageIoReader() = delete;
};

class ImageIoWriter {
 public:
  virtual ~ImageIoWriter() {}

  static std::unique_ptr<ImageIoWriter> Create(const char* filename, int width,
                                               int height,
                                               const uint8_t* image);

  virtual bool WriteRgb888() = 0;

 protected:
  const int width_;
  const int height_;
  const uint8_t* image_;
  const std::string filename_;

  ImageIoWriter(const char* filename, int width, int height,
                const uint8_t* image)
      : width_(width), height_(height), image_(image), filename_(filename) {}

  ImageIoWriter() = delete;
};

#endif  // LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_BASE_H_
