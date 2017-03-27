#include "include/dvr/dvr_surface.h"

#include <private/dvr/display_client.h>

using namespace android;

extern "C" {

int dvrGetPoseBuffer(DvrReadBuffer** pose_buffer) {
  auto client = android::dvr::DisplayClient::Create();
  if (!client) {
    ALOGE("Failed to create display client!");
    return -ECOMM;
  }

  *pose_buffer = CreateDvrReadBufferFromBufferConsumer(client->GetPoseBuffer());
  return 0;
}

}  // extern "C"
