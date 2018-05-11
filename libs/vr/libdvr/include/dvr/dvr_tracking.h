#ifndef ANDROID_DVR_TRACKING_H_
#define ANDROID_DVR_TRACKING_H_

#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

// Represents a sensor event.
typedef struct DvrTrackingSensorEvent {
  // The sensor type.
  int32_t sensor;

  // Event type.
  int32_t type;

  // This is the timestamp recorded from the device. Taken in the middle
  // of the integration interval and adjusted for any low pass filtering.
  int64_t timestamp_ns;

  // The event data.
  float x;
  float y;
  float z;
} DvrTrackingSensorEvent;

typedef struct DvrTrackingSensors DvrTrackingSensors;
typedef struct DvrTrackingCamera DvrTrackingCamera;
typedef struct DvrWriteBufferQueue DvrWriteBufferQueue;

// The callback for DvrTrackingSensors session that will deliver the events.
// This callback is passed to dvrTrackingSensorsStart.
typedef void (*DvrTrackingSensorEventCallback)(void* context,
                                               DvrTrackingSensorEvent* event);

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

// Destroys a DvrTrackingCamera handle.
//
// @param camera The DvrTrackingCamera of interest.
void dvrTrackingCameraDestroy(DvrTrackingCamera* camera);

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

// Creates a DvrTrackingSensors session.
//
// This will initialize but not start device sensors (gyro / accel). Upon
// successfull creation, the clients can call dvrTrackingSensorsStart to start
// receiving sensor events.
//
// @param out_sensors The pointer of a DvrTrackingSensors will be filled here if
//     the method call succeeds.
// @param mode The sensor mode.
//        mode="ndk": Use the Android NDK.
//        mode="direct": Use direct mode sensors (lower latency).
// @return Zero on success, or negative error code.
int dvrTrackingSensorsCreate(DvrTrackingSensors** out_sensors,
                             const char* mode);

// Destroy a DvrTrackingSensors session.
//
// @param sensors The DvrTrackingSensors struct to destroy.
void dvrTrackingSensorsDestroy(DvrTrackingSensors* sensors);

// Start the tracking.
//
// This will start the device sensors and start pumping the feature and sensor
// events as they arrive.
//
// @param client A tracking client created by dvrTrackingSensorsCreate.
// @param context A client supplied pointer that will be passed to the callback.
// @param callback A callback that will receive the sensor events on an
// arbitrary thread.
// @return Zero on success, or negative error code.
int dvrTrackingSensorsStart(DvrTrackingSensors* sensors,
                            DvrTrackingSensorEventCallback callback,
                            void* context);

// Stop the tracking.
//
// This will stop the device sensors. dvrTrackingSensorsStart can be called to
// restart them again.
//
// @param client A tracking client created by dvrTrackingClientCreate.
// @return Zero on success, or negative error code.
int dvrTrackingSensorsStop(DvrTrackingSensors* sensors);

__END_DECLS

#endif  // ANDROID_DVR_TRACKING_H_
