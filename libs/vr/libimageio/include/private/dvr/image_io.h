#ifndef DVR_IMAGE_IO_H_
#define DVR_IMAGE_IO_H_

#include <stdbool.h>
#include <stdint.h>

// Supported filetypes.
#define DVR_IMAGE_IO_SUPPORTED_WRITE "png, ppm"
#define DVR_IMAGE_IO_SUPPORTED_READ "ppm"

#ifdef __cplusplus
extern "C" {
#endif

// Writes an RGB888 image to file. Intended file type is autodetected
// based on the extension. Currently supported formats: PNG, PPM.
bool image_io_write_rgb888(const char* filename, int width, int height,
                           const uint8_t* image);

// Reads an RGB888 image from file. Image buffer needs to be released with
// image_io_release_image. Currently supported formats: PPM.
bool image_io_read_rgb888(const char* filename, int* width, int* height,
                          uint8_t** image);

// Releases image buffer allocated within the library.
void image_io_release_buffer(uint8_t* image);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // DVR_IMAGE_IO_H_
