#ifndef ANDROID_DVR_SURFACE_H_
#define ANDROID_DVR_SURFACE_H_

#include <dvr/dvr_buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

// Get a pointer to the global pose buffer.
int dvrGetPoseBuffer(DvrReadBuffer** pose_buffer);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_SURFACE_H_
