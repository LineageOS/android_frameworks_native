#ifndef ANDROID_DVR_API_H_
#define ANDROID_DVR_API_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <unistd.h>

#include <dvr/dvr_hardware_composer_defs.h>

__BEGIN_DECLS

typedef struct ANativeWindow ANativeWindow;

typedef struct DvrPoseAsync DvrPoseAsync;

typedef uint64_t DvrSurfaceUpdateFlags;
typedef struct DvrDisplayManager DvrDisplayManager;
typedef struct DvrSurfaceState DvrSurfaceState;
typedef struct DvrPose DvrPose;
typedef struct DvrVSyncClient DvrVSyncClient;
typedef struct DvrVirtualTouchpad DvrVirtualTouchpad;

typedef struct DvrBuffer DvrBuffer;
typedef struct DvrWriteBuffer DvrWriteBuffer;
typedef struct DvrReadBuffer DvrReadBuffer;
typedef struct AHardwareBuffer AHardwareBuffer;

typedef struct DvrReadBufferQueue DvrReadBufferQueue;
typedef struct DvrWriteBufferQueue DvrWriteBufferQueue;

typedef struct DvrSurface DvrSurface;
typedef uint64_t DvrSurfaceAttributeType;
typedef int32_t DvrSurfaceAttributeKey;

typedef struct DvrSurfaceAttributeValue DvrSurfaceAttributeValue;
typedef struct DvrSurfaceAttribute DvrSurfaceAttribute;

struct native_handle;

// dvr_display_manager.h
typedef int (*DvrDisplayManagerCreatePtr)(DvrDisplayManager** client_out);
typedef void (*DvrDisplayManagerDestroyPtr)(DvrDisplayManager* client);
typedef int (*DvrDisplayManagerSetupNamedBufferPtr)(DvrDisplayManager* client,
                                                    const char* name,
                                                    size_t size, uint64_t usage,
                                                    DvrBuffer** buffer_out);
typedef int (*DvrDisplayManagerGetEventFdPtr)(DvrDisplayManager* client);
typedef int (*DvrDisplayManagerTranslateEpollEventMaskPtr)(
    DvrDisplayManager* client, int in_events, int* out_events);
typedef int (*DvrDisplayManagerGetSurfaceStatePtr)(
    DvrDisplayManager* client, DvrSurfaceState* surface_state);
typedef int (*DvrDisplayManagerGetReadBufferQueuePtr)(
    DvrDisplayManager* client, int surface_id, int queue_id,
    DvrReadBufferQueue** queue_out);
typedef int (*DvrSurfaceStateCreatePtr)(DvrSurfaceState** surface_state);
typedef void (*DvrSurfaceStateDestroyPtr)(DvrSurfaceState* surface_state);
typedef int (*DvrSurfaceStateGetSurfaceCountPtr)(DvrSurfaceState* surface_state,
                                                 size_t* count_out);
typedef int (*DvrSurfaceStateGetUpdateFlagsPtr)(
    DvrSurfaceState* surface_state, size_t surface_index,
    DvrSurfaceUpdateFlags* flags_out);
typedef int (*DvrSurfaceStateGetSurfaceIdPtr)(DvrSurfaceState* surface_state,
                                              size_t surface_index,
                                              int* surface_id_out);
typedef int (*DvrSurfaceStateGetProcessIdPtr)(DvrSurfaceState* surface_state,
                                              size_t surface_index,
                                              int* process_id_out);
typedef int (*DvrSurfaceStateGetQueueCountPtr)(DvrSurfaceState* surface_state,
                                               size_t surface_index,
                                               size_t* count_out);
typedef ssize_t (*DvrSurfaceStateGetQueueIdsPtr)(DvrSurfaceState* surface_state,
                                                 size_t surface_index,
                                                 int* queue_ids,
                                                 size_t max_count);
typedef int (*DvrSurfaceStateGetZOrderPtr)(DvrSurfaceState* surface_state,
                                           size_t surface_index,
                                           int* z_order_out);
typedef int (*DvrSurfaceStateGetVisiblePtr)(DvrSurfaceState* surface_state,
                                            size_t surface_index,
                                            bool* visible_out);
typedef int (*DvrSurfaceStateGetAttributeCountPtr)(
    DvrSurfaceState* surface_state, size_t surface_index, size_t* count_out);
typedef ssize_t (*DvrSurfaceStateGetAttributesPtr)(
    DvrSurfaceState* surface_state, size_t surface_index,
    DvrSurfaceAttribute* attributes, size_t max_attribute_count);

// dvr_buffer.h
typedef void (*DvrWriteBufferCreateEmptyPtr)(DvrWriteBuffer** write_buffer_out);
typedef void (*DvrWriteBufferDestroyPtr)(DvrWriteBuffer* write_buffer);
typedef int (*DvrWriteBufferIsValidPtr)(DvrWriteBuffer* write_buffer);
typedef int (*DvrWriteBufferClearPtr)(DvrWriteBuffer* write_buffer);
typedef int (*DvrWriteBufferGetIdPtr)(DvrWriteBuffer* write_buffer);
typedef int (*DvrWriteBufferGetAHardwareBufferPtr)(
    DvrWriteBuffer* write_buffer, AHardwareBuffer** hardware_buffer);
typedef int (*DvrWriteBufferPostPtr)(DvrWriteBuffer* write_buffer,
                                     int ready_fence_fd, const void* meta,
                                     size_t meta_size_bytes);
typedef int (*DvrWriteBufferGainPtr)(DvrWriteBuffer* write_buffer,
                                     int* release_fence_fd);
typedef int (*DvrWriteBufferGainAsyncPtr)(DvrWriteBuffer* write_buffer);
typedef const struct native_handle* (*DvrWriteBufferGetNativeHandlePtr)(
    DvrWriteBuffer* write_buffer);

typedef void (*DvrReadBufferCreateEmptyPtr)(DvrReadBuffer** read_buffer_out);
typedef void (*DvrReadBufferDestroyPtr)(DvrReadBuffer* read_buffer);
typedef int (*DvrReadBufferIsValidPtr)(DvrReadBuffer* read_buffer);
typedef int (*DvrReadBufferClearPtr)(DvrReadBuffer* read_buffer);
typedef int (*DvrReadBufferGetIdPtr)(DvrReadBuffer* read_buffer);
typedef int (*DvrReadBufferGetAHardwareBufferPtr)(
    DvrReadBuffer* read_buffer, AHardwareBuffer** hardware_buffer);
typedef int (*DvrReadBufferAcquirePtr)(DvrReadBuffer* read_buffer,
                                       int* ready_fence_fd, void* meta,
                                       size_t meta_size_bytes);
typedef int (*DvrReadBufferReleasePtr)(DvrReadBuffer* read_buffer,
                                       int release_fence_fd);
typedef int (*DvrReadBufferReleaseAsyncPtr)(DvrReadBuffer* read_buffer);
typedef const struct native_handle* (*DvrReadBufferGetNativeHandlePtr)(
    DvrReadBuffer* read_buffer);

typedef void (*DvrBufferDestroyPtr)(DvrBuffer* buffer);
typedef int (*DvrBufferGetAHardwareBufferPtr)(
    DvrBuffer* buffer, AHardwareBuffer** hardware_buffer);
typedef const struct native_handle* (*DvrBufferGetNativeHandlePtr)(
    DvrBuffer* buffer);

// dvr_buffer_queue.h
typedef void (*DvrWriteBufferQueueDestroyPtr)(DvrWriteBufferQueue* write_queue);
typedef ssize_t (*DvrWriteBufferQueueGetCapacityPtr)(
    DvrWriteBufferQueue* write_queue);
typedef int (*DvrWriteBufferQueueGetIdPtr)(DvrWriteBufferQueue* write_queue);
typedef int (*DvrWriteBufferQueueGetExternalSurfacePtr)(
    DvrWriteBufferQueue* write_queue, ANativeWindow** out_window);
typedef int (*DvrWriteBufferQueueCreateReadQueuePtr)(
    DvrWriteBufferQueue* write_queue, DvrReadBufferQueue** out_read_queue);
typedef int (*DvrWriteBufferQueueDequeuePtr)(DvrWriteBufferQueue* write_queue,
                                             int timeout,
                                             DvrWriteBuffer* out_buffer,
                                             int* out_fence_fd);
typedef void (*DvrReadBufferQueueDestroyPtr)(DvrReadBufferQueue* read_queue);
typedef ssize_t (*DvrReadBufferQueueGetCapacityPtr)(
    DvrReadBufferQueue* read_queue);
typedef int (*DvrReadBufferQueueGetIdPtr)(DvrReadBufferQueue* read_queue);
typedef int (*DvrReadBufferQueueCreateReadQueuePtr)(
    DvrReadBufferQueue* read_queue, DvrReadBufferQueue** out_read_queue);
typedef int (*DvrReadBufferQueueDequeuePtr)(DvrReadBufferQueue* read_queue,
                                            int timeout,
                                            DvrReadBuffer* out_buffer,
                                            int* out_fence_fd, void* out_meta,
                                            size_t meta_size_bytes);

// dvr_surface.h
typedef int (*DvrGetNamedBufferPtr)(const char* name, DvrBuffer** out_buffer);
typedef int (*DvrSurfaceCreatePtr)(const DvrSurfaceAttribute* attributes,
                                   size_t attribute_count,
                                   DvrSurface** surface_out);
typedef void (*DvrSurfaceDestroyPtr)(DvrSurface* surface);
typedef int (*DvrSurfaceGetIdPtr)(DvrSurface* surface);
typedef int (*DvrSurfaceSetAttributesPtr)(DvrSurface* surface,
                                          const DvrSurfaceAttribute* attributes,
                                          size_t attribute_count);
typedef int (*DvrSurfaceCreateWriteBufferQueuePtr)(
    DvrSurface* surface, uint32_t width, uint32_t height, uint32_t format,
    uint32_t layer_count, uint64_t usage, size_t capacity,
    DvrWriteBufferQueue** queue_out);

// vsync_client_api.h
typedef int (*DvrVSyncClientCreatePtr)(DvrVSyncClient** client_out);
typedef void (*DvrVSyncClientDestroyPtr)(DvrVSyncClient* client);
typedef int (*DvrVSyncClientGetSchedInfoPtr)(DvrVSyncClient* client,
                                             int64_t* vsync_period_ns,
                                             int64_t* next_timestamp_ns,
                                             uint32_t* next_vsync_count);

// pose_client.h
typedef DvrPose* (*DvrPoseCreatePtr)(void);
typedef void (*DvrPoseDestroyPtr)(DvrPose* client);
typedef int (*DvrPoseGetPtr)(DvrPose* client, uint32_t vsync_count,
                             DvrPoseAsync* out_pose);
typedef uint32_t (*DvrPoseGetVsyncCountPtr)(DvrPose* client);
typedef int (*DvrPoseGetControllerPtr)(DvrPose* client, int32_t controller_id,
                                       uint32_t vsync_count,
                                       DvrPoseAsync* out_pose);

// virtual_touchpad_client.h
typedef DvrVirtualTouchpad* (*DvrVirtualTouchpadCreatePtr)(void);
typedef void (*DvrVirtualTouchpadDestroyPtr)(DvrVirtualTouchpad* client);
typedef int (*DvrVirtualTouchpadAttachPtr)(DvrVirtualTouchpad* client);
typedef int (*DvrVirtualTouchpadDetachPtr)(DvrVirtualTouchpad* client);
typedef int (*DvrVirtualTouchpadTouchPtr)(DvrVirtualTouchpad* client,
                                          int touchpad, float x, float y,
                                          float pressure);
typedef int (*DvrVirtualTouchpadButtonStatePtr)(DvrVirtualTouchpad* client,
                                                int touchpad, int buttons);

// dvr_hardware_composer_client.h
typedef struct DvrHwcClient DvrHwcClient;
typedef struct DvrHwcFrame DvrHwcFrame;
typedef int (*DvrHwcOnFrameCallback)(void* client_state, DvrHwcFrame* frame);
typedef DvrHwcClient* (*DvrHwcClientCreatePtr)(DvrHwcOnFrameCallback callback,
                                               void* client_state);
typedef void (*DvrHwcClientDestroyPtr)(DvrHwcClient* client);
typedef void (*DvrHwcFrameDestroyPtr)(DvrHwcFrame* frame);
typedef DvrHwcDisplay (*DvrHwcFrameGetDisplayIdPtr)(DvrHwcFrame* frame);
typedef int32_t (*DvrHwcFrameGetDisplayWidthPtr)(DvrHwcFrame* frame);
typedef int32_t (*DvrHwcFrameGetDisplayHeightPtr)(DvrHwcFrame* frame);
typedef bool (*DvrHwcFrameGetDisplayRemovedPtr)(DvrHwcFrame* frame);
typedef size_t (*DvrHwcFrameGetLayerCountPtr)(DvrHwcFrame* frame);
typedef DvrHwcLayer (*DvrHwcFrameGetLayerIdPtr)(DvrHwcFrame* frame,
                                                size_t layer_index);
typedef uint32_t (*DvrHwcFrameGetActiveConfigPtr)(DvrHwcFrame* frame);
typedef uint32_t (*DvrHwcFrameGetColorModePtr)(DvrHwcFrame* frame);
typedef void (*DvrHwcFrameGetColorTransformPtr)(DvrHwcFrame* frame,
                                                float* out_matrix,
                                                int32_t* out_hint);
typedef uint32_t (*DvrHwcFrameGetPowerModePtr)(DvrHwcFrame* frame);
typedef uint32_t (*DvrHwcFrameGetVsyncEnabledPtr)(DvrHwcFrame* frame);
typedef AHardwareBuffer* (*DvrHwcFrameGetLayerBufferPtr)(DvrHwcFrame* frame,
                                                         size_t layer_index);
typedef int (*DvrHwcFrameGetLayerFencePtr)(DvrHwcFrame* frame,
                                           size_t layer_index);
typedef DvrHwcRecti (*DvrHwcFrameGetLayerDisplayFramePtr)(DvrHwcFrame* frame,
                                                          size_t layer_index);
typedef DvrHwcRectf (*DvrHwcFrameGetLayerCropPtr)(DvrHwcFrame* frame,
                                                  size_t layer_index);
typedef DvrHwcBlendMode (*DvrHwcFrameGetLayerBlendModePtr)(DvrHwcFrame* frame,
                                                           size_t layer_index);
typedef float (*DvrHwcFrameGetLayerAlphaPtr)(DvrHwcFrame* frame,
                                             size_t layer_index);
typedef uint32_t (*DvrHwcFrameGetLayerTypePtr)(DvrHwcFrame* frame,
                                               size_t layer_index);
typedef uint32_t (*DvrHwcFrameGetLayerApplicationIdPtr)(DvrHwcFrame* frame,
                                                        size_t layer_index);
typedef uint32_t (*DvrHwcFrameGetLayerZOrderPtr)(DvrHwcFrame* frame,
                                                 size_t layer_index);

typedef void (*DvrHwcFrameGetLayerCursorPtr)(DvrHwcFrame* frame,
                                             size_t layer_index, int32_t* out_x,
                                             int32_t* out_y);

typedef uint32_t (*DvrHwcFrameGetLayerTransformPtr)(DvrHwcFrame* frame,
                                                    size_t layer_index);

typedef uint32_t (*DvrHwcFrameGetLayerDataspacePtr)(DvrHwcFrame* frame,
                                                    size_t layer_index);

typedef uint32_t (*DvrHwcFrameGetLayerColorPtr)(DvrHwcFrame* frame,
                                                size_t layer_index);

typedef uint32_t (*DvrHwcFrameGetLayerNumVisibleRegionsPtr)(DvrHwcFrame* frame,
                                                            size_t layer_index);
typedef DvrHwcRecti (*DvrHwcFrameGetLayerVisibleRegionPtr)(DvrHwcFrame* frame,
                                                           size_t layer_index,
                                                           size_t index);

typedef uint32_t (*DvrHwcFrameGetLayerNumDamagedRegionsPtr)(DvrHwcFrame* frame,
                                                            size_t layer_index);
typedef DvrHwcRecti (*DvrHwcFrameGetLayerDamagedRegionPtr)(DvrHwcFrame* frame,
                                                           size_t layer_index,
                                                           size_t index);

// The buffer metadata that an Android Surface (a.k.a. ANativeWindow)
// will populate. A DvrWriteBufferQueue must be created with this metadata iff
// ANativeWindow access is needed. Please do not remove, modify, or reorder
// existing data members. If new fields need to be added, please take extra care
// to make sure that new data field is padded properly the size of the struct
// stays same.
struct DvrNativeBufferMetadata {
  // Timestamp of the frame.
  int64_t timestamp;

  // Whether the buffer is using auto timestamp.
  int32_t is_auto_timestamp;

  // Must be one of the HAL_DATASPACE_XXX value defined in system/graphics.h
  int32_t dataspace;

  // Crop extracted from an ACrop or android::Crop object.
  int32_t crop_left;
  int32_t crop_top;
  int32_t crop_right;
  int32_t crop_bottom;

  // Must be one of the NATIVE_WINDOW_SCALING_MODE_XXX value defined in
  // system/window.h.
  int32_t scaling_mode;

  // Must be one of the ANATIVEWINDOW_TRANSFORM_XXX value defined in
  // android/native_window.h
  int32_t transform;

  // Reserved bytes for so that the struct is forward compatible.
  int32_t reserved[16];
};

struct DvrApi_v1 {
// Defines an API entry for V1 (no version suffix).
#define DVR_V1_API_ENTRY(name) Dvr##name##Ptr name

// Include file with API entries.
#include "dvr_api_entries.h"

// Undefine macro definitions to play nice with Google3 style rules.
#undef DVR_V1_API_ENTRY
};

int dvrGetApi(void* api, size_t struct_size, int version);

__END_DECLS

#endif  // ANDROID_DVR_API_H_
