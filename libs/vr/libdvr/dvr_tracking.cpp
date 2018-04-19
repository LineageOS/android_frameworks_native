#include "include/dvr/dvr_tracking.h"

#include <utils/Errors.h>
#include <utils/Log.h>

#if !DVR_TRACKING_IMPLEMENTED

extern "C" {

// This file provides the stub implementation of dvrTrackingXXX APIs. On
// platforms that implement these APIs, set -DDVR_TRACKING_IMPLEMENTED=1 in the
// build file.
int dvrTrackingCameraCreate(DvrTrackingCamera**) {
  ALOGE("dvrTrackingCameraCreate is not implemented.");
  return -ENOSYS;
}

int dvrTrackingCameraStart(DvrTrackingCamera*, DvrWriteBufferQueue*) {
  ALOGE("dvrTrackingCameraCreate is not implemented.");
  return -ENOSYS;
}

int dvrTrackingCameraStop(DvrTrackingCamera*) {
  ALOGE("dvrTrackingCameraCreate is not implemented.");
  return -ENOSYS;
}

}  // extern "C"

#endif  // DVR_TRACKING_IMPLEMENTED
