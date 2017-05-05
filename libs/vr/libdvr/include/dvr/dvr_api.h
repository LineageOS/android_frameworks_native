#ifndef ANDROID_DVR_API_H_
#define ANDROID_DVR_API_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <dvr/dvr_hardware_composer_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ANativeWindow ANativeWindow;

typedef struct DvrPoseAsync DvrPoseAsync;

typedef struct DvrDisplayManagerClient DvrDisplayManagerClient;
typedef struct DvrDisplayManagerClientSurfaceList
    DvrDisplayManagerClientSurfaceList;
typedef struct DvrDisplayManagerClientSurfaceBuffers
    DvrDisplayManagerClientSurfaceBuffers;
typedef struct DvrPose DvrPose;
typedef struct dvr_vsync_client dvr_vsync_client;
typedef struct DvrVirtualTouchpad DvrVirtualTouchpad;

typedef DvrDisplayManagerClient* (*DvrDisplayManagerClientCreatePtr)(void);
typedef void (*DvrDisplayManagerClientDestroyPtr)(
    DvrDisplayManagerClient* client);

typedef struct DvrWriteBuffer DvrWriteBuffer;
typedef struct DvrReadBuffer DvrReadBuffer;
typedef struct DvrBuffer DvrBuffer;
typedef struct AHardwareBuffer AHardwareBuffer;

typedef struct DvrWriteBufferQueue DvrWriteBufferQueue;
typedef struct DvrReadBufferQueue DvrReadBufferQueue;

typedef struct DvrSurface DvrSurface;

struct native_handle;

// display_manager_client.h
typedef int (*DvrDisplayManagerClientGetSurfaceListPtr)(
    DvrDisplayManagerClient* client,
    DvrDisplayManagerClientSurfaceList** surface_list);
typedef void (*DvrDisplayManagerClientSurfaceListDestroyPtr)(
    DvrDisplayManagerClientSurfaceList* surface_list);
typedef DvrBuffer* (*DvrDisplayManagerSetupNamedBufferPtr)(
    DvrDisplayManagerClient* client, const char* name, size_t size,
    uint64_t usage0, uint64_t usage1);
typedef size_t (*DvrDisplayManagerClientSurfaceListGetSizePtr)(
    DvrDisplayManagerClientSurfaceList* surface_list);
typedef int (*DvrDisplayManagerClientSurfaceListGetSurfaceIdPtr)(
    DvrDisplayManagerClientSurfaceList* surface_list, size_t index);
typedef int (*DvrDisplayManagerClientGetSurfaceBufferListPtr)(
    DvrDisplayManagerClient* client, int surface_id,
    DvrDisplayManagerClientSurfaceBuffers** surface_buffers);
typedef void (*DvrDisplayManagerClientSurfaceBufferListDestroyPtr)(
    DvrDisplayManagerClientSurfaceBuffers* surface_buffers);
typedef size_t (*DvrDisplayManagerClientSurfaceBufferListGetSizePtr)(
    DvrDisplayManagerClientSurfaceBuffers* surface_buffers);
typedef int (*DvrDisplayManagerClientSurfaceBufferListGetFdPtr)(
    DvrDisplayManagerClientSurfaceBuffers* surface_buffers, size_t index);

// dvr_buffer.h
typedef void (*DvrWriteBufferDestroyPtr)(DvrWriteBuffer* client);
typedef int (*DvrWriteBufferGetAHardwareBufferPtr)(
    DvrWriteBuffer* client, AHardwareBuffer** hardware_buffer);
typedef int (*DvrWriteBufferPostPtr)(DvrWriteBuffer* client, int ready_fence_fd,
                                     const void* meta, size_t meta_size_bytes);
typedef int (*DvrWriteBufferGainPtr)(DvrWriteBuffer* client,
                                     int* release_fence_fd);
typedef int (*DvrWriteBufferGainAsyncPtr)(DvrWriteBuffer* client);
typedef const struct native_handle* (*DvrWriteBufferGetNativeHandle)(
    DvrWriteBuffer* write_buffer);

typedef void (*DvrReadBufferDestroyPtr)(DvrReadBuffer* client);
typedef int (*DvrReadBufferGetAHardwareBufferPtr)(
    DvrReadBuffer* client, AHardwareBuffer** hardware_buffer);
typedef int (*DvrReadBufferAcquirePtr)(DvrReadBuffer* client,
                                       int* ready_fence_fd, void* meta,
                                       size_t meta_size_bytes);
typedef int (*DvrReadBufferReleasePtr)(DvrReadBuffer* client,
                                       int release_fence_fd);
typedef int (*DvrReadBufferReleaseAsyncPtr)(DvrReadBuffer* client);
typedef const struct native_handle* (*DvrReadBufferGetNativeHandle)(
    DvrReadBuffer* read_buffer);

typedef void (*DvrBufferDestroy)(DvrBuffer* buffer);
typedef int (*DvrBufferGetAHardwareBuffer)(DvrBuffer* buffer,
                                           AHardwareBuffer** hardware_buffer);
typedef const struct native_handle* (*DvrBufferGetNativeHandle)(
    DvrBuffer* buffer);

// dvr_buffer_queue.h
typedef void (*DvrWriteBufferQueueDestroyPtr)(DvrWriteBufferQueue* write_queue);
typedef size_t (*DvrWriteBufferQueueGetCapacityPtr)(
    DvrWriteBufferQueue* write_queue);
typedef int (*DvrWriteBufferQueueGetExternalSurfacePtr)(
    DvrWriteBufferQueue* write_queue, ANativeWindow** out_window);
typedef int (*DvrWriteBufferQueueCreateReadQueuePtr)(
    DvrWriteBufferQueue* write_queue, DvrReadBufferQueue** out_read_queue);
typedef int (*DvrWriteBufferQueueDequeuePtr)(DvrWriteBufferQueue* write_queue,
                                             int timeout,
                                             DvrWriteBuffer** out_buffer,
                                             int* out_fence_fd);
typedef void (*DvrReadBufferQueueDestroyPtr)(DvrReadBufferQueue* read_queue);
typedef size_t (*DvrReadBufferQueueGetCapacityPtr)(
    DvrReadBufferQueue* read_queue);
typedef int (*DvrReadBufferQueueCreateReadQueuePtr)(
    DvrReadBufferQueue* read_queue, DvrReadBufferQueue** out_read_queue);
typedef int (*DvrReadBufferQueueDequeuePtr)(DvrReadBufferQueue* read_queue,
                                            int timeout,
                                            DvrReadBuffer** out_buffer,
                                            int* out_fence_fd, void* out_meta,
                                            size_t meta_size_bytes);

// dvr_surface.h
typedef int (*DvrGetNamedBufferPtr)(const char* name, DvrBuffer** out_buffer);
typedef int (*DvrSurfaceCreatePtr)(int width, int height, int format,
                                   uint64_t usage0, uint64_t usage1, int flags,
                                   DvrSurface** out_surface);
typedef int (*DvrSurfaceGetWriteBufferQueuePtr)(
    DvrSurface* surface, DvrWriteBufferQueue** out_writer);

// vsync_client_api.h
typedef dvr_vsync_client* (*DvrVSyncClientCreatePtr)();
typedef void (*DvrVSyncClientDestroyPtr)(dvr_vsync_client* client);
typedef int (*DvrVSyncClientGetSchedInfoPtr)(dvr_vsync_client* client,
                                             int64_t* vsync_period_ns,
                                             int64_t* next_timestamp_ns,
                                             uint32_t* next_vsync_count);

// pose_client.h
typedef DvrPose* (*DvrPoseClientCreatePtr)(void);
typedef void (*DvrPoseClientDestroyPtr)(DvrPose* client);
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
// ANativeWindow access is needed. Note that this struct must stay in sync with
// BufferHubQueueCore::NativeBufferMetadata. Please do not remove, modify, or
// reorder existing data members. If new fields need to be added, please take
// extra care to make sure that new data field is padded properly the size of
// the struct stays same.
// TODO(b/37578558) Move |dvr_api.h| into a header library so that this structure
// won't be copied between |dvr_api.h| and |buffer_hub_qeue_core.h|.
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
  // Display manager client
  DvrDisplayManagerClientCreatePtr display_manager_client_create;
  DvrDisplayManagerClientDestroyPtr display_manager_client_destroy;
  DvrDisplayManagerClientGetSurfaceListPtr
      display_manager_client_get_surface_list;
  DvrDisplayManagerClientSurfaceListDestroyPtr
      display_manager_client_surface_list_destroy;
  DvrDisplayManagerSetupNamedBufferPtr display_manager_setup_named_buffer;
  DvrDisplayManagerClientSurfaceListGetSizePtr
      display_manager_client_surface_list_get_size;
  DvrDisplayManagerClientSurfaceListGetSurfaceIdPtr
      display_manager_client_surface_list_get_surface_id;
  DvrDisplayManagerClientGetSurfaceBufferListPtr
      display_manager_client_get_surface_buffer_list;
  DvrDisplayManagerClientSurfaceBufferListDestroyPtr
      display_manager_client_surface_buffer_list_destroy;
  DvrDisplayManagerClientSurfaceBufferListGetSizePtr
      display_manager_client_surface_buffer_list_get_size;
  DvrDisplayManagerClientSurfaceBufferListGetFdPtr
      display_manager_client_surface_buffer_list_get_fd;

  // Write buffer
  DvrWriteBufferDestroyPtr write_buffer_destroy;
  DvrWriteBufferGetAHardwareBufferPtr write_buffer_get_ahardwarebuffer;
  DvrWriteBufferPostPtr write_buffer_post;
  DvrWriteBufferGainPtr write_buffer_gain;
  DvrWriteBufferGainAsyncPtr write_buffer_gain_async;
  DvrWriteBufferGetNativeHandle write_buffer_get_native_handle;

  // Read buffer
  DvrReadBufferDestroyPtr read_buffer_destroy;
  DvrReadBufferGetAHardwareBufferPtr read_buffer_get_ahardwarebuffer;
  DvrReadBufferAcquirePtr read_buffer_acquire;
  DvrReadBufferReleasePtr read_buffer_release;
  DvrReadBufferReleaseAsyncPtr read_buffer_release_async;
  DvrReadBufferGetNativeHandle read_buffer_get_native_handle;

  // Buffer
  DvrBufferDestroy buffer_destroy;
  DvrBufferGetAHardwareBuffer buffer_get_ahardwarebuffer;
  DvrBufferGetNativeHandle buffer_get_native_handle;

  // Write buffer queue
  DvrWriteBufferQueueDestroyPtr write_buffer_queue_destroy;
  DvrWriteBufferQueueGetCapacityPtr write_buffer_queue_get_capacity;
  DvrWriteBufferQueueGetExternalSurfacePtr
      write_buffer_queue_get_external_surface;
  DvrWriteBufferQueueCreateReadQueuePtr write_buffer_queue_create_read_queue;
  DvrWriteBufferQueueDequeuePtr write_buffer_queue_dequeue;

  // Read buffer queue
  DvrReadBufferQueueDestroyPtr read_buffer_queue_destroy;
  DvrReadBufferQueueGetCapacityPtr read_buffer_queue_get_capacity;
  DvrReadBufferQueueCreateReadQueuePtr read_buffer_queue_create_read_queue;
  DvrReadBufferQueueDequeuePtr read_buffer_queue_dequeue;

  // V-Sync client
  DvrVSyncClientCreatePtr vsync_client_create;
  DvrVSyncClientDestroyPtr vsync_client_destroy;
  DvrVSyncClientGetSchedInfoPtr vsync_client_get_sched_info;

  // Display surface
  DvrGetNamedBufferPtr get_named_buffer;
  DvrSurfaceCreatePtr surface_create;
  DvrSurfaceGetWriteBufferQueuePtr surface_get_write_buffer_queue;

  // Pose client
  DvrPoseClientCreatePtr pose_client_create;
  DvrPoseClientDestroyPtr pose_client_destroy;
  DvrPoseGetPtr pose_get;
  DvrPoseGetVsyncCountPtr pose_get_vsync_count;
  DvrPoseGetControllerPtr pose_get_controller;

  // Virtual touchpad client
  DvrVirtualTouchpadCreatePtr virtual_touchpad_create;
  DvrVirtualTouchpadDestroyPtr virtual_touchpad_destroy;
  DvrVirtualTouchpadAttachPtr virtual_touchpad_attach;
  DvrVirtualTouchpadDetachPtr virtual_touchpad_detach;
  DvrVirtualTouchpadTouchPtr virtual_touchpad_touch;
  DvrVirtualTouchpadButtonStatePtr virtual_touchpad_button_state;

  // VR HWComposer client
  DvrHwcClientCreatePtr hwc_client_create;
  DvrHwcClientDestroyPtr hwc_client_destroy;
  DvrHwcFrameDestroyPtr hwc_frame_destroy;
  DvrHwcFrameGetDisplayIdPtr hwc_frame_get_display_id;
  DvrHwcFrameGetDisplayWidthPtr hwc_frame_get_display_width;
  DvrHwcFrameGetDisplayHeightPtr hwc_frame_get_display_height;
  DvrHwcFrameGetDisplayRemovedPtr hwc_frame_get_display_removed;
  DvrHwcFrameGetActiveConfigPtr hwc_frame_get_active_config;
  DvrHwcFrameGetColorModePtr hwc_frame_get_color_mode;
  DvrHwcFrameGetColorTransformPtr hwc_frame_get_color_transform;
  DvrHwcFrameGetPowerModePtr hwc_frame_get_power_mode;
  DvrHwcFrameGetVsyncEnabledPtr hwc_frame_get_vsync_enabled;
  DvrHwcFrameGetLayerCountPtr hwc_frame_get_layer_count;
  DvrHwcFrameGetLayerIdPtr hwc_frame_get_layer_id;
  DvrHwcFrameGetLayerBufferPtr hwc_frame_get_layer_buffer;
  DvrHwcFrameGetLayerFencePtr hwc_frame_get_layer_fence;
  DvrHwcFrameGetLayerDisplayFramePtr hwc_frame_get_layer_display_frame;
  DvrHwcFrameGetLayerCropPtr hwc_frame_get_layer_crop;
  DvrHwcFrameGetLayerBlendModePtr hwc_frame_get_layer_blend_mode;
  DvrHwcFrameGetLayerAlphaPtr hwc_frame_get_layer_alpha;
  DvrHwcFrameGetLayerTypePtr hwc_frame_get_layer_type;
  DvrHwcFrameGetLayerApplicationIdPtr hwc_frame_get_layer_application_id;
  DvrHwcFrameGetLayerZOrderPtr hwc_frame_get_layer_z_order;
  DvrHwcFrameGetLayerCursorPtr hwc_frame_get_layer_cursor;
  DvrHwcFrameGetLayerTransformPtr hwc_frame_get_layer_transform;
  DvrHwcFrameGetLayerDataspacePtr hwc_frame_get_layer_dataspace;
  DvrHwcFrameGetLayerColorPtr hwc_frame_get_layer_color;
  DvrHwcFrameGetLayerNumVisibleRegionsPtr
      hwc_frame_get_layer_num_visible_regions;
  DvrHwcFrameGetLayerVisibleRegionPtr hwc_frame_get_layer_visible_region;
  DvrHwcFrameGetLayerNumDamagedRegionsPtr
      hwc_frame_get_layer_num_damaged_regions;
  DvrHwcFrameGetLayerDamagedRegionPtr hwc_frame_get_layer_damaged_region;
};

int dvrGetApi(void* api, size_t struct_size, int version);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_API_H_
