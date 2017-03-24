#ifndef LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_LOGGING_H_
#define LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_LOGGING_H_

// This header acts as log/log.h if LOG_TO_STDERR is not defined.
// If LOG_TO_STDERR is defined, then android logging macros (such as ALOGE)
// would log to stderr. This is useful if the code is also being used/tested on
// a desktop.

#ifdef LOG_TO_STDERR
#include <stdarg.h>
#include <cstdio>

#ifndef LOG_TAG
#define LOG_TAG " "
#endif  // LOG_TAG

inline void LogToStderr(const char* severity, const char* fmt, ...) {
  fprintf(stderr, "%s %s: ", LOG_TAG, severity);
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  fprintf(stderr, "\n");
  fflush(stderr);
}

#define ALOGE(fmt, ...) LogToStderr("ERROR", fmt, ##__VA_ARGS__)

#define ALOGW(fmt, ...) LogToStderr("WARNING", fmt, ##__VA_ARGS__)

#define ALOGI(fmt, ...) LogToStderr("INFO", fmt, ##__VA_ARGS__)

#define ALOGV(fmt, ...) LogToStderr("VERBOSE", fmt, ##__VA_ARGS__)

#else  // LOG_TO_STDERR
#include <log/log.h>
#endif  // LOG_TO_STDERR

#endif  // LIB_LIBIMAGEIO_PRIVATE_DVR_IMAGE_IO_LOGGING_H_
