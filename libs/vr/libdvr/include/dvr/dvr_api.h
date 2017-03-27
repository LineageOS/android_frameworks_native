#ifndef ANDROID_DVR_API_H_
#define ANDROID_DVR_API_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <dvr/dvr_hardware_composer_defs.h>
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

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
typedef struct AHardwareBuffer AHardwareBuffer;

typedef struct DvrWriteBufferQueue DvrWriteBufferQueue;
typedef struct DvrReadBufferQueue DvrReadBufferQueue;

typedef struct DvrSurface DvrSurface;

// display_manager_client.h
typedef int (*DvrDisplayManagerClientGetSurfaceListPtr)(
    DvrDisplayManagerClient* client,
    DvrDisplayManagerClientSurfaceList** surface_list);
typedef void (*DvrDisplayManagerClientSurfaceListDestroyPtr)(
    DvrDisplayManagerClientSurfaceList* surface_list);
typedef DvrWriteBuffer* (*DvrDisplayManagerSetupPoseBufferPtr)(
    DvrDisplayManagerClient* client, size_t extended_region_size,
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
typedef void (*DvrWriteBufferGetBlobFdsPtr)(DvrWriteBuffer* client, int* fds,
                                            size_t* fds_count,
                                            size_t max_fds_count);
typedef int (*DvrWriteBufferGetAHardwareBufferPtr)(
    DvrWriteBuffer* client, AHardwareBuffer** hardware_buffer);
typedef int (*DvrWriteBufferPostPtr)(DvrWriteBuffer* client, int ready_fence_fd,
                                     const void* meta, size_t meta_size_bytes);
typedef int (*DvrWriteBufferGainPtr)(DvrWriteBuffer* client,
                                     int* release_fence_fd);
typedef int (*DvrWriteBufferGainAsyncPtr)(DvrWriteBuffer* client);

typedef void (*DvrReadBufferDestroyPtr)(DvrReadBuffer* client);
typedef void (*DvrReadBufferGetBlobFdsPtr)(DvrReadBuffer* client, int* fds,
                                           size_t* fds_count,
                                           size_t max_fds_count);
typedef int (*DvrReadBufferGetAHardwareBufferPtr)(
    DvrReadBuffer* client, AHardwareBuffer** hardware_buffer);
typedef int (*DvrReadBufferAcquirePtr)(DvrReadBuffer* client,
                                       int* ready_fence_fd, void* meta,
                                       size_t meta_size_bytes);
typedef int (*DvrReadBufferReleasePtr)(DvrReadBuffer* client,
                                       int release_fence_fd);
typedef int (*DvrReadBufferReleaseAsyncPtr)(DvrReadBuffer* client);

// dvr_buffer_queue.h
typedef void (*DvrWriteBufferQueueDestroyPtr)(DvrWriteBufferQueue* write_queue);
typedef size_t (*DvrWriteBufferQueueGetCapacityPtr)(
    DvrWriteBufferQueue* write_queue);
typedef jobject (*DvrWriteBufferQueueGetExternalSurfacePtr)(
    DvrWriteBufferQueue* write_queue, JNIEnv* env);
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
typedef int (*DvrGetPoseBufferPtr)(DvrReadBuffer** pose_buffer);
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
typedef struct AHardwareBuffer AHardwareBuffer;
typedef struct DvrHwcClient DvrHwcClient;
typedef struct DvrHwcFrame DvrHwcFrame;
typedef int(*DvrHwcOnFrameCallback)(void* client_state, DvrHwcFrame* frame);
typedef DvrHwcClient* (*DvrHwcCreateClientPtr)(DvrHwcOnFrameCallback callback,
                                               void* client_state);
typedef void (*DvrHwcClientDestroyPtr)(DvrHwcClient* client);
typedef void (*DvrHwcFrameDestroyPtr)(DvrHwcFrame* frame);
typedef Display (*DvrHwcFrameGetDisplayIdPtr)(DvrHwcFrame* frame);
typedef int32_t (*DvrHwcFrameGetDisplayWidthPtr)(DvrHwcFrame* frame);
typedef int32_t (*DvrHwcFrameGetDisplayHeightPtr)(DvrHwcFrame* frame);
typedef bool (*DvrHwcFrameGetDisplayRemovedPtr)(DvrHwcFrame* frame);
typedef size_t (*DvrHwcFrameGetLayerCountPtr)(DvrHwcFrame* frame);
typedef Layer (*DvrHwcFrameGetLayerIdPtr)(DvrHwcFrame* frame, size_t layer_index);
typedef AHardwareBuffer* (*DvrHwcFrameGetLayerBufferPtr)(DvrHwcFrame* frame,
                                                         size_t layer_index);
typedef int (*DvrHwcFrameGetLayerFencePtr)(DvrHwcFrame* frame,
                                           size_t layer_index);
typedef Recti (*DvrHwcFrameGetLayerDisplayFramePtr)(DvrHwcFrame* frame,
                                                    size_t layer_index);
typedef Rectf (*DvrHwcFrameGetLayerCropPtr)(DvrHwcFrame* frame,
                                            size_t layer_index);
typedef BlendMode (*DvrHwcFrameGetLayerBlendModePtr)(DvrHwcFrame* frame,
                                                     size_t layer_index);
typedef float (*DvrHwcFrameGetLayerAlphaPtr)(DvrHwcFrame* frame,
                                             size_t layer_index);
typedef uint32_t (*DvrHwcFrameGetLayerTypePtr)(DvrHwcFrame* frame,
                                               size_t layer_index);
typedef uint32_t (*DvrHwcFrameGetLayerApplicationIdPtr)(DvrHwcFrame* frame,
                                                        size_t layer_index);

struct DvrApi_v1 {
  // Display manager client
  DvrDisplayManagerClientCreatePtr display_manager_client_create_;
  DvrDisplayManagerClientDestroyPtr display_manager_client_destroy_;
  DvrDisplayManagerClientGetSurfaceListPtr
      display_manager_client_get_surface_list_;
  DvrDisplayManagerClientSurfaceListDestroyPtr
      display_manager_client_surface_list_destroy_;
  DvrDisplayManagerSetupPoseBufferPtr display_manager_setup_pose_buffer_;
  DvrDisplayManagerClientSurfaceListGetSizePtr
      display_manager_client_surface_list_get_size_;
  DvrDisplayManagerClientSurfaceListGetSurfaceIdPtr
      display_manager_client_surface_list_get_surface_id_;
  DvrDisplayManagerClientGetSurfaceBufferListPtr
      display_manager_client_get_surface_buffer_list_;
  DvrDisplayManagerClientSurfaceBufferListDestroyPtr
      display_manager_client_surface_buffer_list_destroy_;
  DvrDisplayManagerClientSurfaceBufferListGetSizePtr
      display_manager_client_surface_buffer_list_get_size_;
  DvrDisplayManagerClientSurfaceBufferListGetFdPtr
      display_manager_client_surface_buffer_list_get_fd_;

  // Write buffer
  DvrWriteBufferDestroyPtr write_buffer_destroy_;
  DvrWriteBufferGetBlobFdsPtr write_buffer_get_blob_fds_;
  DvrWriteBufferGetAHardwareBufferPtr write_buffer_get_AHardwareBuffer_;
  DvrWriteBufferPostPtr write_buffer_post_;
  DvrWriteBufferGainPtr write_buffer_gain_;
  DvrWriteBufferGainAsyncPtr write_buffer_gain_async_;

  // Read buffer
  DvrReadBufferDestroyPtr read_buffer_destroy_;
  DvrReadBufferGetBlobFdsPtr read_buffer_get_blob_fds_;
  DvrReadBufferGetAHardwareBufferPtr read_buffer_get_AHardwareBuffer_;
  DvrReadBufferAcquirePtr read_buffer_acquire_;
  DvrReadBufferReleasePtr read_buffer_release_;
  DvrReadBufferReleaseAsyncPtr read_buffer_release_async_;

  // Write buffer queue
  DvrWriteBufferQueueDestroyPtr write_buffer_queue_destroy_;
  DvrWriteBufferQueueGetCapacityPtr write_buffer_queue_get_capacity_;
  DvrWriteBufferQueueGetExternalSurfacePtr
      write_buffer_queue_get_external_surface_;
  DvrWriteBufferQueueCreateReadQueuePtr write_buffer_queue_create_read_queue_;
  DvrWriteBufferQueueDequeuePtr write_buffer_queue_dequeue_;

  // Read buffer queue
  DvrReadBufferQueueDestroyPtr read_buffer_queue_destroy_;
  DvrReadBufferQueueGetCapacityPtr read_buffer_queue_get_capacity_;
  DvrReadBufferQueueCreateReadQueuePtr read_buffer_queue_create_read_queue_;
  DvrReadBufferQueueDequeuePtr read_buffer_queue_dequeue;

  // V-Sync client
  DvrVSyncClientCreatePtr vsync_client_create_;
  DvrVSyncClientDestroyPtr vsync_client_destroy_;
  DvrVSyncClientGetSchedInfoPtr vsync_client_get_sched_info_;

  // Display surface
  DvrGetPoseBufferPtr get_pose_buffer_;
  DvrSurfaceCreatePtr surface_create_;
  DvrSurfaceGetWriteBufferQueuePtr surface_get_write_buffer_queue_;

  // Pose client
  DvrPoseClientCreatePtr pose_client_create_;
  DvrPoseClientDestroyPtr pose_client_destroy_;
  DvrPoseGetPtr pose_get_;
  DvrPoseGetVsyncCountPtr pose_get_vsync_count_;
  DvrPoseGetControllerPtr pose_get_controller_;

  // Virtual touchpad client
  DvrVirtualTouchpadCreatePtr virtual_touchpad_create_;
  DvrVirtualTouchpadDestroyPtr virtual_touchpad_destroy_;
  DvrVirtualTouchpadAttachPtr virtual_touchpad_attach_;
  DvrVirtualTouchpadDetachPtr virtual_touchpad_detach_;
  DvrVirtualTouchpadTouchPtr virtual_touchpad_touch_;
  DvrVirtualTouchpadButtonStatePtr virtual_touchpad_button_state_;

  // VR HWComposer client
  DvrHwcCreateClientPtr hwc_create_client_;
  DvrHwcClientDestroyPtr hwc_client_destroy_;
  DvrHwcFrameDestroyPtr hwc_frame_destroy_;
  DvrHwcFrameGetDisplayIdPtr hwc_frame_get_display_id_;
  DvrHwcFrameGetDisplayWidthPtr hwc_frame_get_display_width_;
  DvrHwcFrameGetDisplayHeightPtr hwc_frame_get_display_height_;
  DvrHwcFrameGetDisplayRemovedPtr hwc_frame_get_display_removed_;
  DvrHwcFrameGetLayerCountPtr hwc_frame_get_layer_count_;
  DvrHwcFrameGetLayerIdPtr hwc_frame_get_layer_id_;
  DvrHwcFrameGetLayerBufferPtr hwc_frame_get_layer_buffer_;
  DvrHwcFrameGetLayerFencePtr hwc_frame_get_layer_fence_;
  DvrHwcFrameGetLayerDisplayFramePtr hwc_frame_get_layer_display_frame_;
  DvrHwcFrameGetLayerCropPtr hwc_frame_get_layer_crop_;
  DvrHwcFrameGetLayerBlendModePtr hwc_frame_get_layer_blend_mode_;
  DvrHwcFrameGetLayerAlphaPtr hwc_frame_get_layer_alpha_;
  DvrHwcFrameGetLayerTypePtr hwc_frame_get_layer_type_;
  DvrHwcFrameGetLayerApplicationIdPtr hwc_frame_get_layer_application_id_;
};

int dvrGetApi(void* api, size_t struct_size, int version);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_API_H_
