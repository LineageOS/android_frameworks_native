#include <buffered_predictor.h>

namespace posepredictor {

BufferedPredictor::BufferedPredictor(size_t buffer_size) {
  buffer_.resize(buffer_size);
}

void BufferedPredictor::BufferSample(const Pose& sample) {
  const auto& prev_sample = buffer_[current_pose_index_];

  // If we are updating a sample (the same time stamp), do not advance the
  // counter.
  if (sample.time_ns != prev_sample.time_ns) {
    current_pose_index_ = (current_pose_index_ + 1) % buffer_.size();
  }

  buffer_[current_pose_index_] = sample;

  // Make sure the subsequent orientations are the closest in quaternion space.
  if (PrevSample(1).orientation.coeffs().dot(sample.orientation.coeffs()) < 0) {
    // Flip the quaternion to be closest to the previous sample.
    buffer_[current_pose_index_].orientation =
        quat(-sample.orientation.w(), -sample.orientation.x(),
             -sample.orientation.y(), -sample.orientation.z());
  }

  ++num_poses_added_;
}

const Pose& BufferedPredictor::PrevSample(size_t index) const {
  // We must not request a pose too far in the past.
  assert(index < buffer_.size());
  return buffer_[(current_pose_index_ - index + buffer_.size()) %
                 buffer_.size()];
}

}  // namespace posepredictor
