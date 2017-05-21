#ifndef ANDROID_DVR_PUBLIC_POSE_H_
#define ANDROID_DVR_PUBLIC_POSE_H_

#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

#ifdef __ARM_NEON
#include <arm_neon.h>
#else
#ifndef __FLOAT32X4T_86
#define __FLOAT32X4T_86
typedef float float32x4_t __attribute__((__vector_size__(16)));
#endif
#endif

// Represents an estimated pose, accessed asynchronously through a shared ring
// buffer. No assumptions should be made about the data in padding space.
// The size of this struct is 128 bytes.
typedef struct __attribute__((packed, aligned(16))) DvrPoseAsync {
  // Left eye head-from-start orientation quaternion x,y,z,w.
  float32x4_t orientation;
  // Left eye head-from-start position x,y,z,pad in meters.
  float32x4_t position;
  // Right eye head-from-start orientation quaternion x,y,z,w.
  float32x4_t right_orientation;
  // Right eye head-from-start position x,y,z,pad in meters.
  float32x4_t right_position;
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

enum {
  DVR_POSE_FLAG_VALID = (1UL << 0),       // This pose is valid.
  DVR_POSE_FLAG_HEAD = (1UL << 1),        // This pose is the head.
  DVR_POSE_FLAG_CONTROLLER = (1UL << 2),  // This pose is a controller.
};

// Represents a sensor pose sample.
typedef struct __attribute__((packed, aligned(16))) DvrPose {
  // Head-from-start orientation quaternion x,y,z,w.
  float32x4_t orientation;

  // The angular velocity where the x,y,z is the rotation axis and the
  // magnitude is the radians / second in the same coordinate frame as
  // orientation.
  float32x4_t angular_velocity;

  // Head-from-start position x,y,z,pad in meters.
  float32x4_t position;

  // In meters / second in the same coordinate frame as position.
  float32x4_t velocity;

  // In meters / second ^ 2 in the same coordinate frame as position.
  float32x4_t acceleration;

  // Timestamp for the measurement in nanoseconds.
  int64_t timestamp_ns;

  // Padding to 96 bytes so the size is a multiple of 16.
  uint8_t padding[8];
} DvrPose;

__END_DECLS

#endif  // ANDROID_DVR_PUBLIC_POSE_H_
