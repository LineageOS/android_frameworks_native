#ifndef ANDROID_DVR_POSE_CLIENT_INTERNAL_H_
#define ANDROID_DVR_POSE_CLIENT_INTERNAL_H_

#include <stdint.h>

#include <dvr/pose_client.h>
#include <pdx/file_handle.h>
#include <private/dvr/sensor_constants.h>

#ifdef __cplusplus
extern "C" {
#endif

// Sensord head pose ring buffer.
typedef struct __attribute__((packed, aligned(16))) DvrPoseRingBuffer {
  // Ring buffer always at the beginning of the structure, as consumers may
  // not have access to this parent structure definition.
  DvrPoseAsync ring[kPoseAsyncBufferTotalCount];
  // Current vsync_count (where sensord is writing poses from).
  uint32_t vsync_count;
} DvrPoseMetadata;

// Called by displayd to give vsync count info to the pose service.
// |display_timestamp| Display timestamp is in the middle of scanout.
// |display_period_ns| Nanos between vsyncs.
// |right_eye_photon_offset_ns| Nanos to shift the prediction timestamp for
//    the right eye head pose (relative to the left eye prediction).
int privateDvrPoseNotifyVsync(DvrPose* client, uint32_t vsync_count,
                              int64_t display_timestamp,
                              int64_t display_period_ns,
                              int64_t right_eye_photon_offset_ns);

// Get file descriptor for access to the shared memory pose buffer. This can be
// used with GL extensions that support shared memory buffer objects. The caller
// takes ownership of the returned fd and must close it or pass on ownership.
int privateDvrPoseGetRingBufferFd(DvrPose* client,
                                  android::pdx::LocalHandle* fd);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_POSE_CLIENT_INTERNAL_H_
