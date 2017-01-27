#ifndef ANDROID_DVR_LUCID_POSE_TRACKER_H_
#define ANDROID_DVR_LUCID_POSE_TRACKER_H_

#include <memory>

#include <dvr/pose_client.h>

#include <private/dvr/types.h>

namespace android {
namespace dvr {

// Provides pose tracking via the system pose service.
class LucidPoseTracker {
 public:
  // When set, the pose service is ignored and the given pose is always returned
  // by GetPose. As long as this is called before any LucidPoseTracker is
  // used, the pose service will not be created.
  // Threading: this is not thread safe.
  static void SetPoseOverride(const Posef& pose);

  // Reset prior override pose.
  static void ClearPoseOverride();

  LucidPoseTracker();
  ~LucidPoseTracker();

  // Currently GetPose() will ignore timestamp_ns and always return the most
  // recent orientation.
  // TODO(stefanus): support prediction.
  Posef GetPose(uint64_t timestamp_ns);

 private:
  static bool is_override_pose_;
  static Posef override_pose_;

  DvrPose* pose_client_;

  // The most recent pose.
  Posef latest_pose_;

  // The time stamp corresponding to when latest_pose_ was last updated.
  uint64_t latest_timestamp_ns_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_LUCID_POSE_TRACKER_H_
