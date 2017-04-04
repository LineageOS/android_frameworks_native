#ifndef ANDROID_DVR_DEVICE_METRICS_H_
#define ANDROID_DVR_DEVICE_METRICS_H_

#include <private/dvr/display_metrics.h>
#include <private/dvr/head_mount_metrics.h>
#include <private/dvr/types.h>

namespace android {
namespace dvr {

HeadMountMetrics CreateHeadMountMetrics();
HeadMountMetrics CreateHeadMountMetrics(const FieldOfView& l_fov,
                                        const FieldOfView& r_fov);
HeadMountMetrics CreateUndistortedHeadMountMetrics();
HeadMountMetrics CreateUndistortedHeadMountMetrics(const FieldOfView& l_fov,
                                                   const FieldOfView& r_fov);
DisplayMetrics CreateDisplayMetrics(vec2i screen_size);

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_DEVICE_METRICS_H_
