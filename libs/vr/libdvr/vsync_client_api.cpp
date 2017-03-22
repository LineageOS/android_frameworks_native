#include "include/dvr/vsync_client_api.h"

#include <private/dvr/vsync_client.h>

extern "C" {

dvr_vsync_client* dvr_vsync_client_create() {
  auto client = android::dvr::VSyncClient::Create();
  return static_cast<dvr_vsync_client*>(client.release());
}

void dvr_vsync_client_destroy(dvr_vsync_client* client) {
  delete static_cast<android::dvr::VSyncClient*>(client);
}

int dvr_vsync_client_get_sched_info(dvr_vsync_client* client,
                                    int64_t* vsync_period_ns,
                                    int64_t* next_timestamp_ns,
                                    uint32_t* next_vsync_count) {
  return static_cast<android::dvr::VSyncClient*>(client)->GetSchedInfo(
      vsync_period_ns, next_timestamp_ns, next_vsync_count);
}

}  // extern "C"
