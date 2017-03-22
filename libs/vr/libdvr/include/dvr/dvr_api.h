#ifndef ANDROID_DVR_API_H_
#define ANDROID_DVR_API_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

typedef DvrDisplayManagerClient* (*DisplayManagerClientCreatePtr)(void);
typedef void (*DisplayManagerClientDestroyPtr)(DvrDisplayManagerClient* client);

typedef struct DvrWriteBuffer DvrWriteBuffer;
typedef struct DvrReadBuffer DvrReadBuffer;
typedef struct AHardwareBuffer AHardwareBuffer;

// display_manager_client.h
typedef int (*DisplayManagerClientGetSurfaceListPtr)(
    DvrDisplayManagerClient* client,
    DvrDisplayManagerClientSurfaceList** surface_list);
typedef void (*DisplayManagerClientSurfaceListDestroyPtr)(
    DvrDisplayManagerClientSurfaceList* surface_list);
typedef DvrWriteBuffer* (*DisplayManagerSetupPoseBufferPtr)(
    DvrDisplayManagerClient* client, size_t extended_region_size,
    uint64_t usage0, uint64_t usage1);
typedef size_t (*DisplayManagerClientSurfaceListGetSizePtr)(
    DvrDisplayManagerClientSurfaceList* surface_list);
typedef int (*DisplayManagerClientSurfaceListGetSurfaceIdPtr)(
    DvrDisplayManagerClientSurfaceList* surface_list, size_t index);
typedef int (*DisplayManagerClientGetSurfaceBufferListPtr)(
    DvrDisplayManagerClient* client, int surface_id,
    DvrDisplayManagerClientSurfaceBuffers** surface_buffers);
typedef void (*DisplayManagerClientSurfaceBufferListDestroyPtr)(
    DvrDisplayManagerClientSurfaceBuffers* surface_buffers);
typedef size_t (*DisplayManagerClientSurfaceBufferListGetSizePtr)(
    DvrDisplayManagerClientSurfaceBuffers* surface_buffers);
typedef int (*DisplayManagerClientSurfaceBufferListGetFdPtr)(
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

// dvr_surface.h
typedef int (*DvrGetPoseBufferPtr)(DvrReadBuffer** pose_buffer);

// vsync_client_api.h
typedef dvr_vsync_client* (*VSyncClientCreatePtr)();
typedef void (*VSyncClientDestroyPtr)(dvr_vsync_client* client);
typedef int (*VSyncClientGetSchedInfoPtr)(dvr_vsync_client* client,
                                          int64_t* vsync_period_ns,
                                          int64_t* next_timestamp_ns,
                                          uint32_t* next_vsync_count);

// pose_client.h
typedef DvrPose* (*PoseClientCreatePtr)(void);
typedef void (*PoseClientDestroyPtr)(DvrPose* client);
typedef int (*PoseGetPtr)(DvrPose* client, uint32_t vsync_count,
                          DvrPoseAsync* out_pose);
typedef uint32_t (*PoseGetVsyncCountPtr)(DvrPose* client);
typedef int (*PoseGetControllerPtr)(DvrPose* client, int32_t controller_id,
                                    uint32_t vsync_count,
                                    DvrPoseAsync* out_pose);

// virtual_touchpad_client.h
typedef DvrVirtualTouchpad* (*VirtualTouchpadCreatePtr)(void);
typedef void (*VirtualTouchpadDestroyPtr)(DvrVirtualTouchpad* client);
typedef int (*VirtualTouchpadAttachPtr)(DvrVirtualTouchpad* client);
typedef int (*VirtualTouchpadDetachPtr)(DvrVirtualTouchpad* client);
typedef int (*VirtualTouchpadTouchPtr)(DvrVirtualTouchpad* client, int touchpad,
                                       float x, float y, float pressure);
typedef int (*VirtualTouchpadButtonStatePtr)(DvrVirtualTouchpad* client,
                                             int touchpad, int buttons);

struct DvrApi_v1 {
  // Display manager client
  DisplayManagerClientCreatePtr display_manager_client_create_;
  DisplayManagerClientDestroyPtr display_manager_client_destroy_;
  DisplayManagerClientGetSurfaceListPtr
      display_manager_client_get_surface_list_;
  DisplayManagerClientSurfaceListDestroyPtr
      display_manager_client_surface_list_destroy_;
  DisplayManagerSetupPoseBufferPtr display_manager_setup_pose_buffer_;
  DisplayManagerClientSurfaceListGetSizePtr
      display_manager_client_surface_list_get_size_;
  DisplayManagerClientSurfaceListGetSurfaceIdPtr
      display_manager_client_surface_list_get_surface_id_;
  DisplayManagerClientGetSurfaceBufferListPtr
      display_manager_client_get_surface_buffer_list_;
  DisplayManagerClientSurfaceBufferListDestroyPtr
      display_manager_client_surface_buffer_list_destroy_;
  DisplayManagerClientSurfaceBufferListGetSizePtr
      display_manager_client_surface_buffer_list_get_size_;
  DisplayManagerClientSurfaceBufferListGetFdPtr
      display_manager_client_surface_buffer_list_get_fd_;

  // Write buffer
  DvrWriteBufferDestroyPtr write_buffer_destroy_;
  DvrWriteBufferGetBlobFdsPtr write_buffer_get_blob_fds_;
  DvrWriteBufferGetAHardwareBufferPtr write_buffer_get_AHardwareBuffer_;
  DvrWriteBufferPostPtr write_buffer_post_;
  DvrWriteBufferGainPtr write_buffer_gain_;
  DvrWriteBufferGainAsyncPtr write_buffer_gain_async_;

  // Read buffer
  DvrReadBufferGetBlobFdsPtr read_buffer_get_blob_fds_;
  DvrReadBufferGetAHardwareBufferPtr read_buffer_get_AHardwareBuffer_;
  DvrReadBufferAcquirePtr read_buffer_acquire_;
  DvrReadBufferReleasePtr read_buffer_release_;
  DvrReadBufferReleaseAsyncPtr read_buffer_release_async_;

  // V-Sync client
  VSyncClientCreatePtr vsync_client_create_;
  VSyncClientDestroyPtr vsync_client_destroy_;
  VSyncClientGetSchedInfoPtr vsync_client_get_sched_info_;

  // Display surface
  DvrGetPoseBufferPtr get_pose_buffer_;

  // Pose client
  PoseClientCreatePtr pose_client_create_;
  PoseClientDestroyPtr pose_client_destroy_;
  PoseGetPtr pose_get_;
  PoseGetVsyncCountPtr pose_get_vsync_count_;
  PoseGetControllerPtr pose_get_controller_;

  // Virtual touchpad client
  VirtualTouchpadCreatePtr virtual_touchpad_create_;
  VirtualTouchpadDestroyPtr virtual_touchpad_destroy_;
  VirtualTouchpadAttachPtr virtual_touchpad_attach_;
  VirtualTouchpadDetachPtr virtual_touchpad_detach_;
  VirtualTouchpadTouchPtr virtual_touchpad_touch_;
  VirtualTouchpadButtonStatePtr virtual_touchpad_button_state_;
};

int dvrGetApi(void* api, size_t struct_size, int version);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_API_H_
