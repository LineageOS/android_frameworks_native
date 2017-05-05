#include "include/dvr/dvr_surface.h"

#include <private/dvr/display_client.h>

using namespace android;

struct DvrSurface {
  std::unique_ptr<dvr::DisplaySurfaceClient> display_surface_;
};

extern "C" {

int dvrSurfaceCreate(int width, int height, int format, uint64_t usage0,
                     uint64_t usage1, int flags, DvrSurface** out_surface) {
  if (out_surface == nullptr) {
    ALOGE("dvrSurfaceCreate: invalid inputs: out_surface=%p.", out_surface);
    return -EINVAL;
  }

  int error;
  auto client = dvr::DisplayClient::Create(&error);
  if (!client) {
    ALOGE("Failed to create display client!");
    return error;
  }

  // TODO(hendrikw): When we move to gralloc1, pass both usage0 and usage1 down.
  std::unique_ptr<dvr::DisplaySurfaceClient> surface =
      client->CreateDisplaySurface(
          width, height, static_cast<int>(usage0 | usage1), format, flags);

  DvrSurface* dvr_surface = new DvrSurface;
  dvr_surface->display_surface_ = std::move(surface);
  *out_surface = dvr_surface;
  return 0;
}

int dvrSurfaceGetWriteBufferQueue(DvrSurface* surface,
                                  DvrWriteBufferQueue** out_writer) {
  if (surface == nullptr || out_writer == nullptr) {
    ALOGE(
        "dvrSurfaceGetWriteBufferQueue: Invalid inputs: surface=%p, "
        "out_writer=%p.",
        surface, out_writer);
    return -EINVAL;
  }
  DvrWriteBufferQueue* buffer_writer = new DvrWriteBufferQueue;
  buffer_writer->producer_queue_ =
      surface->display_surface_->GetProducerQueue();
  if (buffer_writer->producer_queue_ == nullptr) {
    ALOGE(
        "dvrSurfaceGetWriteBufferQueue: Failed to get producer queue from "
        "display surface.");
    return -ENOMEM;
  }

  *out_writer = buffer_writer;
  return 0;
}

int dvrGetNamedBuffer(const char* name, DvrBuffer** out_buffer) {
  auto client = android::dvr::DisplayClient::Create();
  if (!client) {
    ALOGE("dvrGetNamedBuffer: Failed to create display client!");
    return -ECOMM;
  }

  if (out_buffer == nullptr || name == nullptr) {
    ALOGE("dvrGetNamedBuffer: Invalid inputs: name=%p, out_buffer=%p.", name,
          out_buffer);
    return -EINVAL;
  }

  auto named_buffer = client->GetNamedBuffer(name);
  if (!named_buffer) {
    ALOGE("dvrGetNamedBuffer: Failed to find named buffer: %s.", name);
    return -EINVAL;
  }
  *out_buffer = CreateDvrBufferFromIonBuffer(std::move(named_buffer));
  return 0;
}

}  // extern "C"
