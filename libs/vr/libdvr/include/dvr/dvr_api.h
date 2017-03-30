#ifndef ANDROID_DVR_API_H_
#define ANDROID_DVR_API_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

struct DvrApi_v1 {
  // Display manager client
  DvrDisplayManagerClientCreatePtr display_manager_client_create;
  DvrDisplayManagerClientDestroyPtr display_manager_client_destroy;
  DvrDisplayManagerClientGetSurfaceListPtr
      display_manager_client_get_surface_list;
  DvrDisplayManagerClientSurfaceListDestroyPtr
      display_manager_client_surface_list_destroy;
  DvrDisplayManagerSetupPoseBufferPtr display_manager_setup_pose_buffer;
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
  DvrWriteBufferGetBlobFdsPtr write_buffer_get_blob_fds;
  DvrWriteBufferGetAHardwareBufferPtr write_buffer_get_ahardwarebuffer;
  DvrWriteBufferPostPtr write_buffer_post;
  DvrWriteBufferGainPtr write_buffer_gain;
  DvrWriteBufferGainAsyncPtr write_buffer_gain_async;

  // Read buffer
  DvrReadBufferDestroyPtr read_buffer_destroy;
  DvrReadBufferGetBlobFdsPtr read_buffer_get_blob_fds;
  DvrReadBufferGetAHardwareBufferPtr read_buffer_get_ahardwarebuffer;
  DvrReadBufferAcquirePtr read_buffer_acquire;
  DvrReadBufferReleasePtr read_buffer_release;
  DvrReadBufferReleaseAsyncPtr read_buffer_release_async;

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
  DvrGetPoseBufferPtr get_pose_buffer;
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
};

int dvrGetApi(void* api, size_t struct_size, int version);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_API_H_
