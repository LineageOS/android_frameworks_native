#ifndef ANDROID_DVR_POSE_CLIENT_H_
#define ANDROID_DVR_POSE_CLIENT_H_

#ifdef __ARM_NEON
#include <arm_neon.h>
#else
#ifndef __FLOAT32X4T_86
#define __FLOAT32X4T_86
typedef float float32x4_t __attribute__ ((__vector_size__ (16)));
typedef struct float32x4x4_t { float32x4_t val[4]; };
#endif
#endif

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DvrPose DvrPose;

// Represents the current state provided by the pose service, containing a
// rotation and translation.
typedef struct __attribute__((packed, aligned(8))) DvrPoseState {
  // A quaternion representing the rotation of the HMD in Start Space.
  struct __attribute__((packed)) {
    float x, y, z, w;
  } head_from_start_rotation;
  // The position of the HMD in Start Space.
  struct __attribute__((packed)) {
    float x, y, z;
  } head_from_start_translation;
  // Time in nanoseconds for the current pose.
  uint64_t timestamp_ns;
  // The rotational velocity of the HMD.
  struct __attribute__((packed)) {
    float x, y, z;
  } sensor_from_start_rotation_velocity;
} DvrPoseState;

enum {
  DVR_POSE_FLAG_VALID = (1UL << 0),       // This pose is valid.
  DVR_POSE_FLAG_HEAD = (1UL << 1),        // This pose is the head.
  DVR_POSE_FLAG_CONTROLLER = (1UL << 2),  // This pose is a controller.
};

// Represents an estimated pose, accessed asynchronously through a shared ring
// buffer. No assumptions should be made about the data in padding space.
// The size of this struct is 128 bytes.
typedef struct __attribute__((packed, aligned(16))) DvrPoseAsync {
  // Left eye head-from-start orientation quaternion x,y,z,w.
  float32x4_t orientation;
  // Left eye head-from-start translation x,y,z,pad in meters.
  float32x4_t translation;
  // Right eye head-from-start orientation quaternion x,y,z,w.
  float32x4_t right_orientation;
  // Right eye head-from-start translation x,y,z,pad in meters.
  float32x4_t right_translation;
  // Start-space angular velocity x,y,z,pad in radians per second.
  float32x4_t angular_velocity;
  // Start-space positional velocity x,y,z,pad in meters per second.
  float32x4_t velocity;
  // Timestamp of when this pose is predicted for, typically halfway through
  // scanout.
  int64_t timestamp_ns;
  // Bitmask of DVR_POSE_FLAG_* constants that apply to this pose.
  //
  // If DVR_POSE_FLAG_VALID is not set, the pose is indeterminate.
  uint64_t flags;
  // Reserved padding to 128 bytes.
  uint8_t pad[16];
} DvrPoseAsync;

// Returned by the async pose ring buffer access API.
typedef struct DvrPoseRingBufferInfo {
  // Read-only pointer to the pose ring buffer. The current pose is in this
  // buffer at element buffer[current_frame & (buffer_size - 1)]. The next
  // frame's forecasted pose is at element
  // ((current_frame + 1) & (buffer_size - 1)). And so on. The poses are
  // predicted for when 50% of the corresponding frame's pixel data is visible
  // to the user.
  // The last value returned by dvrPresent is the count for the next frame,
  // which is the earliest that the application could display something if they
  // were to render promptly. (TODO(jbates) move this comment to dvrPresent).
  volatile const DvrPoseAsync* buffer;
  // Minimum number of accurate forecasted poses including the current frame's
  // pose. This is the number of poses that are udpated by the pose service.
  // If the application reads past this count, they will get a stale prediction
  // from a previous frame. Guaranteed to be at least 2.
  uint32_t min_future_count;
  // Number of elements in buffer. At least 8 and greater than min_future_count.
  // Guaranteed to be a power of two. The total size of the buffer in bytes is:
  //   total_count * sizeof(DvrPoseAsync)
  uint32_t total_count;
} DvrPoseRingBufferInfo;

typedef enum DvrPoseMode {
  DVR_POSE_MODE_6DOF = 0,
  DVR_POSE_MODE_3DOF,
  DVR_POSE_MODE_MOCK_FROZEN,
  DVR_POSE_MODE_MOCK_HEAD_TURN_SLOW,
  DVR_POSE_MODE_MOCK_HEAD_TURN_FAST,
  DVR_POSE_MODE_MOCK_ROTATE_SLOW,
  DVR_POSE_MODE_MOCK_ROTATE_MEDIUM,
  DVR_POSE_MODE_MOCK_ROTATE_FAST,
  DVR_POSE_MODE_MOCK_CIRCLE_STRAFE,

  // Always last.
  DVR_POSE_MODE_COUNT,
} DvrPoseMode;

typedef enum DvrControllerId {
  DVR_CONTROLLER_0 = 0,
  DVR_CONTROLLER_1 = 1,
} DvrControllerId;

// Creates a new pose client.
//
// @return Pointer to the created pose client, nullptr on failure.
DvrPose* dvrPoseCreate();

// Destroys a pose client.
//
// @param client Pointer to the pose client to be destroyed.
void dvrPoseDestroy(DvrPose* client);

// Gets the pose for the given vsync count.
//
// @param client Pointer to the pose client.
// @param vsync_count Vsync that this pose should be forward-predicted to.
//     Typically this is the count returned by dvrGetNextVsyncCount.
// @param out_pose Struct to store pose state.
// @return Zero on success, negative error code on failure.
int dvrPoseGet(DvrPose* client, uint32_t vsync_count, DvrPoseAsync* out_pose);

// Gets the current vsync count.
uint32_t dvrPoseGetVsyncCount(DvrPose* client);

// Gets the pose for the given controller at the given vsync count.
//
// @param client Pointer to the pose client.
// @param controller_id The controller id.
// @param vsync_count Vsync that this pose should be forward-predicted to.
//     Typically this is the count returned by dvrGetNextVsyncCount.
// @param out_pose Struct to store pose state.
// @return Zero on success, negative error code on failure.
int dvrPoseGetController(DvrPose* client, int32_t controller_id,
                         uint32_t vsync_count, DvrPoseAsync* out_pose);

// Enables/disables logging for the controller fusion.
//
// @param client Pointer to the pose client.
// @param enable True starts logging, False stops.
// @return Zero on success, negative error code on failure.
int dvrPoseLogController(DvrPose* client, bool enable);

// DEPRECATED
// Polls current pose state.
//
// @param client Pointer to the pose client.
// @param state Struct to store polled state.
// @return Zero on success, negative error code on failure.
int dvrPosePoll(DvrPose* client, DvrPoseState* state);

// Freezes the pose to the provided state.
//
// Future poll operations will return this state until a different state is
// frozen or dvrPoseSetMode() is called with a different mode. The timestamp is
// not frozen.
//
// @param client Pointer to the pose client.
// @param frozen_state State pose to be frozen to.
// @return Zero on success, negative error code on failure.
int dvrPoseFreeze(DvrPose* client, const DvrPoseState* frozen_state);

// Sets the pose service mode.
//
// @param mode The requested pose mode.
// @return Zero on success, negative error code on failure.
int dvrPoseSetMode(DvrPose* client, DvrPoseMode mode);

// Gets the pose service mode.
//
// @param mode Return value for the current pose mode.
// @return Zero on success, negative error code on failure.
int dvrPoseGetMode(DvrPose* client, DvrPoseMode* mode);

// Get access to the shared memory pose ring buffer.
// A future pose at vsync <current> + <offset> is accessed at index:
//   index = (<current> + <offset>) % out_buffer_size
// Where <current> was the last value returned by dvrPresent and
// <offset> is less than or equal to |out_min_future_count|.
// |out_buffer| will be set to a pointer to the buffer.
// |out_fd| will be set to the gralloc buffer file descriptor, which is
//   required for binding this buffer for GPU use.
// Returns 0 on success.
int dvrPoseGetRingBuffer(DvrPose* client, DvrPoseRingBufferInfo* out_info);


#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_POSE_CLIENT_H_
