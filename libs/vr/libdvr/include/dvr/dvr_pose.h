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
  // If DVR_POSE_FLAG_INVALID is set, the pose is indeterminate.
  uint64_t flags;
  // Reserved padding to 128 bytes.
  uint8_t pad[16];
} DvrPoseAsync;

enum {
  DVR_POSE_FLAG_INVALID = (1ULL << 0),       // This pose is invalid.
  DVR_POSE_FLAG_INITIALIZING = (1ULL << 1),  // The pose delivered during
                                             // initialization and it may not be
                                             // correct.
  DVR_POSE_FLAG_3DOF =
      (1ULL << 2),  // This pose is derived from 3Dof sensors. If
                    // this is not set, pose is derived using
                    // 3Dof and 6Dof sensors.
  DVR_POSE_FLAG_FLOOR_HEIGHT_INVALID =
      (1ULL << 3),  // If set the floor height is invalid.

  // Bits that indicate the tracking system state.
  DVR_POSE_FLAG_SERVICE_EXCEPTION = (1ULL << 32),
  DVR_POSE_FLAG_FISHEYE_OVER_EXPOSED = (1ULL << 33),
  DVR_POSE_FLAG_FISHEYE_UNDER_EXPOSED = (1ULL << 34),
  DVR_POSE_FLAG_COLOR_OVER_EXPOSED = (1ULL << 35),
  DVR_POSE_FLAG_COLOR_UNDER_EXPOSED = (1ULL << 36),
  DVR_POSE_FLAG_TOO_FEW_FEATURES_TRACKED = (1ULL << 37)
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

  // The combination of flags above.
  uint64_t flags;

  // The current floor height. May be updated at a lower cadence than pose.
  float floor_height;

  // Padding to 112 bytes so the size is a multiple of 16.
  uint8_t padding[12];
} DvrPose;

__END_DECLS

#endif  // ANDROID_DVR_PUBLIC_POSE_H_
