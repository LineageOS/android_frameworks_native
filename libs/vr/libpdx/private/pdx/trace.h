#ifndef ANDROID_PDX_TRACE_H_
#define ANDROID_PDX_TRACE_H_

// Tracing utilities for libpdx. Tracing in the service framework is enabled
// under these conditions:
//    1. ATRACE_TAG is defined, AND
//    2. ATRACE_TAG does not equal ATRACE_TAG_NEVER, AND
//    3. PDX_TRACE_ENABLED is defined, AND
//    4. PDX_TRACE_ENABLED is equal to logical true.
//
// If any of these conditions are not met tracing is completely removed from the
// library and headers.

// If ATRACE_TAG is not defined, default to never.
#ifndef ATRACE_TAG
#define ATRACE_TAG ATRACE_TAG_NEVER
#endif

// Include tracing functions after the trace tag is defined.
#include <utils/Trace.h>

// If PDX_TRACE_ENABLED is not defined, default to off.
#ifndef PDX_TRACE_ENABLED
#define PDX_TRACE_ENABLED 0
#endif

#if (ATRACE_TAG) != (ATRACE_TAG_NEVER) && (PDX_TRACE_ENABLED)
#define PDX_TRACE_NAME ATRACE_NAME
#else
#define PDX_TRACE_NAME(name) \
  do {                       \
  } while (0)
#endif

#endif  // ANDROID_PDX_TRACE_H_
