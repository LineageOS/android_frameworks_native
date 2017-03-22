#include "include/dvr/dvr_api.h"

#include <errno.h>

// Headers from libdvr
#include <dvr/display_manager_client.h>
#include <dvr/dvr_buffer.h>
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
    dvr_api->display_manager_client_create_ = dvrDisplayManagerClientCreate;
    dvr_api->display_manager_client_destroy_ = dvrDisplayManagerClientDestroy;
    dvr_api->display_manager_client_get_surface_list_ =
        dvrDisplayManagerClientGetSurfaceList;
    dvr_api->display_manager_client_surface_list_destroy_ =
        dvrDisplayManagerClientSurfaceListDestroy;
    dvr_api->display_manager_setup_pose_buffer_ =
        dvrDisplayManagerSetupPoseBuffer;
    dvr_api->display_manager_client_surface_list_get_size_ =
        dvrDisplayManagerClientSurfaceListGetSize;
    dvr_api->display_manager_client_surface_list_get_surface_id_ =
        dvrDisplayManagerClientSurfaceListGetSurfaceId;
    dvr_api->display_manager_client_get_surface_buffer_list_ =
        dvrDisplayManagerClientGetSurfaceBuffers;
    dvr_api->display_manager_client_surface_buffer_list_destroy_ =
        dvrDisplayManagerClientSurfaceBuffersDestroy;
    dvr_api->display_manager_client_surface_buffer_list_get_size_ =
        dvrDisplayManagerClientSurfaceBuffersGetSize;
    dvr_api->display_manager_client_surface_buffer_list_get_fd_ =
        dvrDisplayManagerClientSurfaceBuffersGetFd;

    // dvr_buffer.h
    dvr_api->write_buffer_destroy_ = dvrWriteBufferDestroy;
    dvr_api->write_buffer_get_blob_fds_ = dvrWriteBufferGetBlobFds;
    dvr_api->write_buffer_get_AHardwareBuffer_ =
        dvrWriteBufferGetAHardwareBuffer;
    dvr_api->write_buffer_post_ = dvrWriteBufferPost;
    dvr_api->write_buffer_gain_ = dvrWriteBufferGain;
    dvr_api->write_buffer_gain_async_ = dvrWriteBufferGainAsync;

    dvr_api->read_buffer_get_blob_fds_ = dvrReadBufferGetBlobFds;
    dvr_api->read_buffer_get_AHardwareBuffer_ = dvrReadBufferGetAHardwareBuffer;
    dvr_api->read_buffer_acquire_ = dvrReadBufferAcquire;
    dvr_api->read_buffer_release_ = dvrReadBufferRelease;
    dvr_api->read_buffer_release_async_ = dvrReadBufferReleaseAsync;

    // dvr_surface.h
    dvr_api->get_pose_buffer_ = dvrGetPoseBuffer;

    // vsync_client_api.h
    dvr_api->vsync_client_create_ = dvr_vsync_client_create;
    dvr_api->vsync_client_destroy_ = dvr_vsync_client_destroy;
    dvr_api->vsync_client_get_sched_info_ = dvr_vsync_client_get_sched_info;

    // pose_client.h
    dvr_api->pose_client_create_ = dvrPoseCreate;
    dvr_api->pose_client_destroy_ = dvrPoseDestroy;
    dvr_api->pose_get_ = dvrPoseGet;
    dvr_api->pose_get_vsync_count_ = dvrPoseGetVsyncCount;
    dvr_api->pose_get_controller_ = dvrPoseGetController;

    // virtual_touchpad_client.h
    dvr_api->virtual_touchpad_create_ = dvrVirtualTouchpadCreate;
    dvr_api->virtual_touchpad_destroy_ = dvrVirtualTouchpadDestroy;
    dvr_api->virtual_touchpad_attach_ = dvrVirtualTouchpadAttach;
    dvr_api->virtual_touchpad_detach_ = dvrVirtualTouchpadDetach;
    dvr_api->virtual_touchpad_touch_ = dvrVirtualTouchpadTouch;
    dvr_api->virtual_touchpad_button_state_ = dvrVirtualTouchpadButtonState;

    return 0;
  }
  return -EINVAL;
}

}  // extern "C"
