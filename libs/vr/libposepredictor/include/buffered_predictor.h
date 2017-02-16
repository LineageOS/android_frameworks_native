#ifndef POSEPREDICTOR_BUFFERED_PREDICTOR_H_
#define POSEPREDICTOR_BUFFERED_PREDICTOR_H_

#include <vector>

#include "predictor.h"

namespace posepredictor {

// Keeps the previous n poses around in a ring buffer.
// The orientations are also unrolled so that a . b > 0 for two subsequent
// quaternions a and b.
class BufferedPredictor : public Predictor {
 public:
  BufferedPredictor(size_t buffer_size);
  ~BufferedPredictor() = default;

 protected:
  // Add a pose sample into the buffer.
  void BufferSample(const Pose& sample);

  // Grab a previous sample.
  // index = 0: last sample
  // index = 1: the one before that
  // ...
  const Pose& PrevSample(size_t index) const;

  // Where we keep the last n poses.
  std::vector<Pose> buffer_;

  // Where the last valid pose is in the buffer.
  size_t current_pose_index_ = 0;

  // The number of poses we have added.
  size_t num_poses_added_ = 0;
};

}  // namespace posepredictor

#endif  // POSEPREDICTOR_BUFFERED_PREDICTOR_H_
