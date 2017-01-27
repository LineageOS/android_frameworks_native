#ifndef ANDROID_DVR_RAW_POSE_H_
#define ANDROID_DVR_RAW_POSE_H_

#include <atomic>

namespace android {
namespace dvr {

// POD raw data of a head pose with a count field for read consistency checking.
// Warning: The layout of this struct and RawPosePair are specific to match the
// corresponding buffer type in the shader in late_latch.cpp.
struct RawPose {
  void Reset(uint32_t new_count) volatile {
    qx = qy = qz = 0.0f;
    qw = 1.0f;
    px = py = pz = 0.0f;
    count = new_count;
  }

  float qx, qy, qz, qw;
  float px, py, pz;
  std::atomic<uint32_t> count;
};

// RawPosePair is used for lock-free writing at about 1khz by the CPU/DSP
// and reading by the GPU. At creation time, pose1 is given count = 1 and
// pose2 is given count = 2.
//
// The lock-free write pattern is:
// - write to pose with least count.
// - memory write barrier.
// - write count = count + 2.
//
// For reads, there is an important assumption about the GPU: it generally
// processes things contiguously, without arbitrary preemptions that save and
// restore full cache states. In other words, if the GPU is preempted and then
// later resumed, any data that was read from memory before the preemption will
// be re-read from memory after resume. This allows the following read trick to
// work:
// - read the full RawPosePair into a shader.
// - select the pose with the newest count.
//
// The older pose may be partially written by the async stores from CPU/DSP, but
// because of the memory barrier and GPU characteristics, the highest count pose
// should always be a fully consistent RawPose.
struct RawPosePair {
  RawPose pose1;
  RawPose pose2;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_RAW_POSE_H_
