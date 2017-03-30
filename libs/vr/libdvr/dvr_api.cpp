#include "include/dvr/dvr_api.h"

#include <errno.h>

// Headers from libdvr
#include <dvr/display_manager_client.h>
#include <dvr/dvr_buffer.h>
#include <dvr/dvr_buffer_queue.h>
#include <dvr/dvr_surface.h>
#include <dvr/vsync_client_api.h>

// Headers not yet moved into libdvr.
// TODO(jwcai) Move these once their callers are moved into Google3.
#include <dvr/pose_client.h>
#include <dvr/virtual_touchpad_client.h>

extern "C" {

DVR_EXPORT int dvrGetApi(void* api, size_t struct_size, int version) {
  if (version == 1) {
    if (struct_size != sizeof(DvrApi_v1)) {
      return -EINVAL;
    }
    DvrApi_v1* dvr_api = static_cast<DvrApi_v1*>(api);

    // display_manager_client.h
    dvr_api->display_manager_client_create = dvrDisplayManagerClientCreate;
    dvr_api->display_manager_client_destroy = dvrDisplayManagerClientDestroy;
    dvr_api->display_manager_client_get_surface_list =
        dvrDisplayManagerClientGetSurfaceList;
    dvr_api->display_manager_client_surface_list_destroy =
        dvrDisplayManagerClientSurfaceListDestroy;
    dvr_api->display_manager_setup_pose_buffer =
        dvrDisplayManagerSetupPoseBuffer;
    dvr_api->display_manager_client_surface_list_get_size =
        dvrDisplayManagerClientSurfaceListGetSize;
    dvr_api->display_manager_client_surface_list_get_surface_id =
        dvrDisplayManagerClientSurfaceListGetSurfaceId;
    dvr_api->display_manager_client_get_surface_buffer_list =
        dvrDisplayManagerClientGetSurfaceBuffers;
    dvr_api->display_manager_client_surface_buffer_list_destroy =
        dvrDisplayManagerClientSurfaceBuffersDestroy;
    dvr_api->display_manager_client_surface_buffer_list_get_size =
        dvrDisplayManagerClientSurfaceBuffersGetSize;
    dvr_api->display_manager_client_surface_buffer_list_get_fd =
        dvrDisplayManagerClientSurfaceBuffersGetFd;

    // dvr_buffer.h
    dvr_api->write_buffer_destroy = dvrWriteBufferDestroy;
    dvr_api->write_buffer_get_blob_fds = dvrWriteBufferGetBlobFds;
    dvr_api->write_buffer_get_ahardwarebuffer =
        dvrWriteBufferGetAHardwareBuffer;
    dvr_api->write_buffer_post = dvrWriteBufferPost;
    dvr_api->write_buffer_gain = dvrWriteBufferGain;
    dvr_api->write_buffer_gain_async = dvrWriteBufferGainAsync;

    dvr_api->read_buffer_destroy = dvrReadBufferDestroy;
    dvr_api->read_buffer_get_blob_fds = dvrReadBufferGetBlobFds;
    dvr_api->read_buffer_get_ahardwarebuffer = dvrReadBufferGetAHardwareBuffer;
    dvr_api->read_buffer_acquire = dvrReadBufferAcquire;
    dvr_api->read_buffer_release = dvrReadBufferRelease;
    dvr_api->read_buffer_release_async = dvrReadBufferReleaseAsync;

    // dvr_buffer_queue.h
    dvr_api->write_buffer_queue_destroy = dvrWriteBufferQueueDestroy;
    dvr_api->write_buffer_queue_get_capacity = dvrWriteBufferQueueGetCapacity;
    dvr_api->write_buffer_queue_get_external_surface =
        dvrWriteBufferQueueGetExternalSurface;
    dvr_api->write_buffer_queue_create_read_queue =
        dvrWriteBufferQueueCreateReadQueue;
    dvr_api->write_buffer_queue_dequeue = dvrWriteBufferQueueDequeue;
    dvr_api->read_buffer_queue_destroy = dvrReadBufferQueueDestroy;
    dvr_api->read_buffer_queue_get_capacity = dvrReadBufferQueueGetCapacity;
    dvr_api->read_buffer_queue_create_read_queue =
        dvrReadBufferQueueCreateReadQueue;
    dvr_api->read_buffer_queue_dequeue = dvrReadBufferQueueDequeue;

    // dvr_surface.h
    dvr_api->get_pose_buffer = dvrGetPoseBuffer;
    dvr_api->surface_create = dvrSurfaceCreate;
    dvr_api->surface_get_write_buffer_queue = dvrSurfaceGetWriteBufferQueue;

    // vsync_client_api.h
    dvr_api->vsync_client_create = dvr_vsync_client_create;
    dvr_api->vsync_client_destroy = dvr_vsync_client_destroy;
    dvr_api->vsync_client_get_sched_info = dvr_vsync_client_get_sched_info;

    // pose_client.h
    dvr_api->pose_client_create = dvrPoseCreate;
    dvr_api->pose_client_destroy = dvrPoseDestroy;
    dvr_api->pose_get = dvrPoseGet;
    dvr_api->pose_get_vsync_count = dvrPoseGetVsyncCount;
    dvr_api->pose_get_controller = dvrPoseGetController;

    // virtual_touchpad_client.h
    dvr_api->virtual_touchpad_create = dvrVirtualTouchpadCreate;
    dvr_api->virtual_touchpad_destroy = dvrVirtualTouchpadDestroy;
    dvr_api->virtual_touchpad_attach = dvrVirtualTouchpadAttach;
    dvr_api->virtual_touchpad_detach = dvrVirtualTouchpadDetach;
    dvr_api->virtual_touchpad_touch = dvrVirtualTouchpadTouch;
    dvr_api->virtual_touchpad_button_state = dvrVirtualTouchpadButtonState;

    return 0;
  }
  return -EINVAL;
}

}  // extern "C"
