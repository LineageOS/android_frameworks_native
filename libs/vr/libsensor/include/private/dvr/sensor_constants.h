#ifndef ANDROID_DVR_SENSOR_CONSTANTS_H_
#define ANDROID_DVR_SENSOR_CONSTANTS_H_

namespace android {
namespace dvr {

// Number of elements in the async pose buffer.
// Must be power of two.
// Macro so that shader code can easily include this value.
#define kPoseAsyncBufferTotalCount 8

// Mask for accessing the current ring buffer array element:
// index = vsync_count & kPoseAsyncBufferIndexMask
constexpr uint32_t kPoseAsyncBufferIndexMask = kPoseAsyncBufferTotalCount - 1;

// Number of pose frames including the current frame that are kept updated with
// pose forecast data. The other poses are left their last known estimates.
constexpr uint32_t kPoseAsyncBufferMinFutureCount = 4;

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SENSOR_CONSTANTS_H_
