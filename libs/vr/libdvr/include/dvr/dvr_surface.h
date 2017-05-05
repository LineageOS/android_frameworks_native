#ifndef ANDROID_DVR_SURFACE_H_
#define ANDROID_DVR_SURFACE_H_

#include <dvr/dvr_buffer.h>
#include <dvr/dvr_buffer_queue.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DvrSurface DvrSurface;
typedef struct DvrSurfaceParameter DvrSurfaceParameter;

// Get a pointer to the global pose buffer.
int dvrGetNamedBuffer(const char* name, DvrBuffer** out_buffer);

int dvrSurfaceCreate(int width, int height, int format, uint64_t usage0,
                     uint64_t usage1, int flags, DvrSurface** out_surface);

// TODO(eieio, jwcai) Change this once we have multiple buffer queue support.
int dvrSurfaceGetWriteBufferQueue(DvrSurface* surface,
                                  DvrWriteBufferQueue** out_writer);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_SURFACE_H_
