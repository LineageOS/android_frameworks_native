#ifndef ANDROID_DVR_POSE_PREDICTOR_H_
#define ANDROID_DVR_POSE_PREDICTOR_H_

#include <dvr/pose_client.h>
#include <predictor.h>

// Some shim functions for connecting dvr to pose predictor.

namespace android {
namespace dvr {

// Feed a pose to the predictor.
void AddPredictorPose(posepredictor::Predictor* predictor,
                      const posepredictor::vec3& start_t_head,
                      const posepredictor::quat& start_q_head,
                      int64_t pose_timestamp, DvrPoseAsync* out);

// Make a prediction for left and right eyes.
void PredictPose(const posepredictor::Predictor* predictor, int64_t left_ns,
                 int64_t right_ns, DvrPoseAsync* out);

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_POSE_PREDICTOR_H_
