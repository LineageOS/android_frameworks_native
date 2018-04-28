#ifndef ANDROID_DVR_TRACKING_H_
#define ANDROID_DVR_TRACKING_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

typedef struct DvrTrackingCamera DvrTrackingCamera;
typedef struct DvrWriteBufferQueue DvrWriteBufferQueue;

// Creates a DvrTrackingCamera session.
//
// On creation, the session is not in operating mode. Client code must call
// dvrTrackingCameraStart to bootstrap the underlying camera stack.
//
// There is no plan to expose camera configuration through this API. All camera
// parameters are determined by the system optimized for better tracking
// results. See b/78662281 for detailed deprecation plan of this API and the
// Stage 2 of VR tracking data source refactoring.
//
// @param out_camera The pointer of a DvrTrackingCamera will be filled here if
//     the method call succeeds.
// @return Zero on success, or negative error code.
int dvrTrackingCameraCreate(DvrTrackingCamera** out_camera);

// Starts the DvrTrackingCamera.
//
// On successful return, all DvrReadBufferQueue's associated with the given
// write_queue will start to receive buffers from the camera stack. Note that
// clients of this API should not assume the buffer dimension, format, and/or
// usage of the outcoming buffers, as they are governed by the underlying camera
// logic. Also note that it's the client's responsibility to consume buffers
// from DvrReadBufferQueue on time and return them back to the producer;
// otherwise the camera stack might be blocked.
//
// @param camera The DvrTrackingCamera of interest.
// @param write_queue A DvrWriteBufferQueue that the camera stack can use to
//     populate the buffer into. The queue must be empty and the camera stack
//     will request buffer allocation with proper buffer dimension, format, and
//     usage.
// @return Zero on success, or negative error code.
int dvrTrackingCameraStart(DvrTrackingCamera* camera,
                           DvrWriteBufferQueue* write_queue);

// Stops the DvrTrackingCamera.
//
// On successful return, the DvrWriteBufferQueue set during
// dvrTrackingCameraStart will stop getting new buffers from the camera stack.
//
// @param camera The DvrTrackingCamera of interest.
// @return Zero on success, or negative error code.
int dvrTrackingCameraStop(DvrTrackingCamera* camera);

__END_DECLS

#endif  // ANDROID_DVR_TRACKING_H_
