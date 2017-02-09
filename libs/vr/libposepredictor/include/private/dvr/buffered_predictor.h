#ifndef ANDROID_DVR_BUFFERED_PREDICTOR_H_
#define ANDROID_DVR_BUFFERED_PREDICTOR_H_

#include <vector>

#include "pose_predictor.h"

namespace android {
namespace dvr {

// Keeps the previous n poses around in a ring buffer.
// The orientations are also unrolled so that a . b > 0 for two subsequent
// quaternions a and b.
class BufferedPredictor : public PosePredictor {
 public:
  BufferedPredictor(size_t buffer_size);
  ~BufferedPredictor() = default;

 protected:
  // Add a pose sample into the buffer.
  void BufferSample(const Sample& sample);

  // Grab a previous sample.
  // index = 0: last sample
  // index = 1: the one before that
  // ...
  const Sample& PrevSample(size_t index) const;

  // Where we keep the last n poses.
  std::vector<Sample> buffer_;

  // Where the last valid pose is in the buffer.
  size_t current_pose_index_ = 0;

  // The number of poses we have added.
  size_t num_poses_added_ = 0;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFERED_PREDICTOR_H_
