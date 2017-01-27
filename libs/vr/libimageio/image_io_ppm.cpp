#define LOG_TAG "ImageIo"

#include <private/dvr/image_io_ppm.h>

#include <cwctype>
#include <fstream>
#include <string>

#include <private/dvr/image_io_logging.h>

bool ImageIoPpmWriter::WriteRgb888() {
  std::ofstream out(filename_);
  if (!out) {
    ALOGE("Failed to open output file %s.", filename_.c_str());
    return false;
  }

  // Write a PPM header. See http://netpbm.sourceforge.net/doc/ppm.html for
  // the format specification.
  constexpr int maximum_intensity = 255;
  out << "P6\n"
      << width_ << "\n"
      << height_ << "\n"
      << maximum_intensity << "\n";

  // Write out the image itself.
  out.write(reinterpret_cast<const char*>(image_), 3 * width_ * height_);

  if (!out) {
    ALOGE("Failed to write .ppm image to %s.", filename_.c_str());
    return false;
  }
  return true;
}

bool ImageIoPpmReader::ReadRgb888() {
  std::ifstream in(filename_);
  if (!in) {
    ALOGE("Failed to open input file %s.", filename_.c_str());
    return false;
  }

  // Read PPM header. See http://netpbm.sourceforge.net/doc/ppm.html for
  // the format specification.
  char magic_number[2];
  in.read(magic_number, 2);
  if (magic_number[0] != 'P' || magic_number[1] != '6') {
    ALOGE("Failed to read PPM, not a P6 file %s.", filename_.c_str());
    return false;
  }

  int maximum_intensity = 0;

  in >> width_;
  in >> height_;
  in >> maximum_intensity;

  char delimiter;
  in.read(&delimiter, 1);

  if (!iswspace(delimiter) || width_ <= 0 || height_ <= 0 ||
      maximum_intensity <= 0) {
    ALOGE("Failed to parse PPM header for %s.", filename_.c_str());
    return false;
  }

  if (maximum_intensity != 255) {
    ALOGE("Failed to read PPM, only 8-bit depth supported %s.",
          filename_.c_str());
    return false;
  }

  // Read RGB data.
  const int data_begin = in.tellg();
  in.seekg(0, in.end);
  const int data_end = in.tellg();
  in.seekg(data_begin, in.beg);

  const int data_size = data_end - data_begin;
  if (data_size != 3 * width_ * height_) {
    ALOGE("Failed to read PPM, unexpected data size %s.", filename_.c_str());
    return false;
  }

  image_.reset(new uint8_t[data_size]);
  char* data = reinterpret_cast<char*>(image_.get());

  const auto it_data_begin = std::istreambuf_iterator<char>(in);
  const auto it_data_end = std::istreambuf_iterator<char>();
  std::copy(it_data_begin, it_data_end, data);

  return true;
}
