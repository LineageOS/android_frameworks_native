#include "include/dvr/dvr_api.h"

#include <errno.h>
#include <utils/Log.h>

// Headers from libdvr
#include <dvr/dvr_buffer.h>
#include <dvr/dvr_buffer_queue.h>
#include <dvr/dvr_display_manager.h>
#include <dvr/dvr_surface.h>
#include <dvr/dvr_vsync.h>

// Headers not yet moved into libdvr.
// TODO(jwcai) Move these once their callers are moved into Google3.
#include <dvr/dvr_hardware_composer_client.h>
#include <dvr/pose_client.h>
#include <dvr/virtual_touchpad_client.h>

extern "C" {

int dvrGetApi(void* api, size_t struct_size, int version) {
  ALOGI("dvrGetApi: api=%p struct_size=%zu version=%d", api, struct_size,
        version);
  if (version == 1) {
    if (struct_size != sizeof(DvrApi_v1)) {
      ALOGE("dvrGetApi: Size mismatch: expected %zu; actual %zu",
            sizeof(DvrApi_v1), struct_size);
      return -EINVAL;
    }
    DvrApi_v1* dvr_api = static_cast<DvrApi_v1*>(api);

// Defines an API entry for V1 (no version suffix).
#define DVR_V1_API_ENTRY(name) dvr_api->name = dvr##name

#include "include/dvr/dvr_api_entries.h"

// Undefine macro definitions to play nice with Google3 style rules.
#undef DVR_V1_API_ENTRY

    return 0;
  }

  ALOGE("dvrGetApi: Unknown API version=%d", version);
  return -EINVAL;
}

}  // extern "C"
