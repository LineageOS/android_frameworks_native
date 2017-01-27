#include "include/private/dvr/vsync_client_api.h"

#include <private/dvr/vsync_client.h>

extern "C" {

dvr_vsync_client* dvr_vsync_client_create() {
  auto client = android::dvr::VSyncClient::Create();
  return static_cast<dvr_vsync_client*>(client.release());
}

void dvr_vsync_client_destroy(dvr_vsync_client* client) {
  delete static_cast<android::dvr::VSyncClient*>(client);
}

int dvr_vsync_client_wait(dvr_vsync_client* client, int64_t* timestamp_ns) {
  return static_cast<android::dvr::VSyncClient*>(client)->Wait(timestamp_ns);
}

int dvr_vsync_client_get_fd(dvr_vsync_client* client) {
  return static_cast<android::dvr::VSyncClient*>(client)->GetFd();
}

int dvr_vsync_client_acknowledge(dvr_vsync_client* client) {
  return static_cast<android::dvr::VSyncClient*>(client)->Acknowledge();
}

int dvr_vsync_client_get_last_timestamp(dvr_vsync_client* client,
                                        int64_t* timestamp_ns) {
  return static_cast<android::dvr::VSyncClient*>(client)->GetLastTimestamp(
      timestamp_ns);
}

}  // extern "C"
