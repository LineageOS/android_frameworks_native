#include "include/dvr/dvr_surface.h"

#include <inttypes.h>

#include <private/dvr/display_client.h>

#include "dvr_internal.h"

using android::dvr::display::DisplayClient;
using android::dvr::display::Surface;
using android::dvr::display::SurfaceAttributes;
using android::dvr::display::SurfaceAttributeValue;
using android::dvr::CreateDvrReadBufferFromBufferConsumer;
using android::dvr::CreateDvrWriteBufferQueueFromProducerQueue;

namespace {

bool ConvertSurfaceAttributes(const DvrSurfaceAttribute* attributes,
                              size_t attribute_count,
                              SurfaceAttributes* surface_attributes,
                              size_t* error_index) {
  for (size_t i = 0; i < attribute_count; i++) {
    SurfaceAttributeValue value;
    switch (attributes[i].value.type) {
      case DVR_SURFACE_ATTRIBUTE_TYPE_INT32:
        value = attributes[i].value.int32_value;
        break;
      case DVR_SURFACE_ATTRIBUTE_TYPE_INT64:
        value = attributes[i].value.int64_value;
        break;
      case DVR_SURFACE_ATTRIBUTE_TYPE_BOOL:
        value = attributes[i].value.bool_value;
        break;
      case DVR_SURFACE_ATTRIBUTE_TYPE_FLOAT:
        value = attributes[i].value.float_value;
        break;
      case DVR_SURFACE_ATTRIBUTE_TYPE_FLOAT2:
        value = attributes[i].value.float2_value;
        break;
      case DVR_SURFACE_ATTRIBUTE_TYPE_FLOAT3:
        value = attributes[i].value.float3_value;
        break;
      case DVR_SURFACE_ATTRIBUTE_TYPE_FLOAT4:
        value = attributes[i].value.float4_value;
        break;
      case DVR_SURFACE_ATTRIBUTE_TYPE_FLOAT8:
        value = attributes[i].value.float8_value;
        break;
      case DVR_SURFACE_ATTRIBUTE_TYPE_FLOAT16:
        value = attributes[i].value.float16_value;
        break;
      default:
        *error_index = i;
        return false;
    }

    surface_attributes->emplace(attributes[i].key, value);
  }

  return true;
}

}  // anonymous namespace

extern "C" {

struct DvrSurface {
  std::unique_ptr<Surface> surface;
};

int dvrSurfaceCreate(const DvrSurfaceAttribute* attributes,
                     size_t attribute_count, DvrSurface** out_surface) {
  if (out_surface == nullptr) {
    ALOGE("dvrSurfaceCreate: Invalid inputs: out_surface=%p.", out_surface);
    return -EINVAL;
  }

  size_t error_index;
  SurfaceAttributes surface_attributes;
  if (!ConvertSurfaceAttributes(attributes, attribute_count,
                                &surface_attributes, &error_index)) {
    ALOGE("dvrSurfaceCreate: Invalid surface attribute type: %" PRIu64,
          attributes[error_index].value.type);
    return -EINVAL;
  }

  auto status = Surface::CreateSurface(surface_attributes);
  if (!status) {
    ALOGE("dvrSurfaceCreate:: Failed to create display surface: %s",
          status.GetErrorMessage().c_str());
    return -status.error();
  }

  *out_surface = new DvrSurface{status.take()};
  return 0;
}

void dvrSurfaceDestroy(DvrSurface* surface) { delete surface; }

int dvrSurfaceGetId(DvrSurface* surface) {
  return surface->surface->surface_id();
}

int dvrSurfaceSetAttributes(DvrSurface* surface,
                            const DvrSurfaceAttribute* attributes,
                            size_t attribute_count) {
  if (surface == nullptr || attributes == nullptr) {
    ALOGE(
        "dvrSurfaceSetAttributes: Invalid inputs: surface=%p attributes=%p "
        "attribute_count=%zu",
        surface, attributes, attribute_count);
    return -EINVAL;
  }

  size_t error_index;
  SurfaceAttributes surface_attributes;
  if (!ConvertSurfaceAttributes(attributes, attribute_count,
                                &surface_attributes, &error_index)) {
    ALOGE("dvrSurfaceSetAttributes: Invalid surface attribute type: %" PRIu64,
          attributes[error_index].value.type);
    return -EINVAL;
  }

  auto status = surface->surface->SetAttributes(surface_attributes);
  if (!status) {
    ALOGE("dvrSurfaceSetAttributes: Failed to set attributes: %s",
          status.GetErrorMessage().c_str());
    return -status.error();
  }

  return 0;
}

int dvrSurfaceCreateWriteBufferQueue(DvrSurface* surface, uint32_t width,
                                     uint32_t height, uint32_t format,
                                     uint32_t layer_count, uint64_t usage,
                                     size_t capacity,
                                     DvrWriteBufferQueue** out_writer) {
  if (surface == nullptr || out_writer == nullptr) {
    ALOGE(
        "dvrSurfaceCreateWriteBufferQueue: Invalid inputs: surface=%p, "
        "out_writer=%p.",
        surface, out_writer);
    return -EINVAL;
  }

  auto status = surface->surface->CreateQueue(width, height, layer_count,
                                              format, usage, capacity);
  if (!status) {
    ALOGE("dvrSurfaceCreateWriteBufferQueue: Failed to create queue: %s",
          status.GetErrorMessage().c_str());
    return -status.error();
  }

  *out_writer = CreateDvrWriteBufferQueueFromProducerQueue(status.take());
  return 0;
}

int dvrGetNamedBuffer(const char* name, DvrBuffer** out_buffer) {
  auto client = DisplayClient::Create();
  if (!client) {
    ALOGE("dvrGetNamedBuffer: Failed to create display client!");
    return -ECOMM;
  }

  if (out_buffer == nullptr || name == nullptr) {
    ALOGE("dvrGetNamedBuffer: Invalid inputs: name=%p, out_buffer=%p.", name,
          out_buffer);
    return -EINVAL;
  }

  auto status = client->GetNamedBuffer(name);
  if (!status) {
    ALOGE("dvrGetNamedBuffer: Failed to find named buffer name=%s: %s", name,
          status.GetErrorMessage().c_str());
    return -status.error();
  }
  *out_buffer = CreateDvrBufferFromIonBuffer(status.take());
  return 0;
}

}  // extern "C"
