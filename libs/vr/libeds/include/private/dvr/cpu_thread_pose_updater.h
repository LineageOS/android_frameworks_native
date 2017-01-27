#ifndef ANDROID_DVR_CPU_THREAD_POSE_UPDATER_H_
#define ANDROID_DVR_CPU_THREAD_POSE_UPDATER_H_

#include <atomic>
#include <thread>

#include <private/dvr/lucid_pose_tracker.h>
#include <private/dvr/raw_pose.h>

namespace android {
namespace dvr {

// Temporary version of pose updater that uses a CPU thread to update
// the pose buffer. Note that this thread starts and runs indefinitely
class CpuThreadPoseUpdater {
 public:
  CpuThreadPoseUpdater();
  ~CpuThreadPoseUpdater();

  // Start the thread to update the given buffer with the given number of
  // microseconds between updates.
  void Start(volatile RawPosePair* mapped_pose_buffer, int period_us);

  void StopAndJoin();

 private:
  void UpdateThread();

  volatile RawPosePair* mapped_pose_buffer_;

  // Pose update thread.
  std::thread update_thread_;

  volatile bool stop_request_;

  // Update period in microseconds.
  int update_period_us_;

  // Current pose count, used to avoid writing to the same buffer that is being
  // read by the GPU.
  uint32_t count_;
  LucidPoseTracker pose_tracker_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_CPU_THREAD_POSE_UPDATER_H_
