#include "include/dvr/display_manager_client.h"

#include <dvr/dvr_buffer.h>
#include <grallocusage/GrallocUsageConversion.h>
#include <private/android/AHardwareBufferHelpers.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/display_manager_client_impl.h>

using android::dvr::DisplaySurfaceAttributeEnum;

extern "C" {

struct DvrDisplayManagerClient {
  DvrDisplayManagerClient()
      : client(android::dvr::DisplayManagerClient::Create()) {}
  ~DvrDisplayManagerClient() {}

  std::unique_ptr<android::dvr::DisplayManagerClient> client;
};

struct DvrDisplayManagerClientSurfaceList {
  DvrDisplayManagerClientSurfaceList(
      std::vector<android::dvr::DisplaySurfaceInfo> surface_list)
      : list(std::move(surface_list)) {}
  ~DvrDisplayManagerClientSurfaceList() {}

  std::vector<android::dvr::DisplaySurfaceInfo> list;
};

struct DvrDisplayManagerClientSurfaceBuffers {
  DvrDisplayManagerClientSurfaceBuffers(
      std::vector<std::unique_ptr<android::dvr::BufferConsumer>> buffer_list)
      : list(std::move(buffer_list)) {}
  ~DvrDisplayManagerClientSurfaceBuffers() {}

  std::vector<std::unique_ptr<android::dvr::BufferConsumer>> list;
};

DvrDisplayManagerClient* dvrDisplayManagerClientCreate() {
  return new DvrDisplayManagerClient();
}

void dvrDisplayManagerClientDestroy(DvrDisplayManagerClient* client) {
  delete client;
}

DvrBuffer* dvrDisplayManagerSetupNamedBuffer(DvrDisplayManagerClient* client,
                                             const char* name, size_t size,
                                             uint64_t hardware_buffer_usage,
                                             uint64_t unused) {
  uint64_t producer_usage = 0;
  uint64_t consumer_usage = 0;

  // Note: AHardwareBuffer no longer uses usage0/usage1
  uint64_t gralloc_usage =
      android::AHardwareBuffer_convertToGrallocUsageBits(hardware_buffer_usage);

  // Note: split producer/consumer usage is deprecated, grallocV2 uses single
  // 64-bits usage
  // And, currently, 64-bits gralloc usage flags can safely be truncated to
  // 32-bits
  android_convertGralloc0To1Usage((uint32_t)gralloc_usage, &producer_usage,
                                  &consumer_usage);

  auto ion_buffer = client->client->SetupNamedBuffer(name, size, producer_usage,
                                                     consumer_usage);
  if (ion_buffer) {
    return CreateDvrBufferFromIonBuffer(std::move(ion_buffer));
  }
  return nullptr;
}

int dvrDisplayManagerClientGetEventFd(DvrDisplayManagerClient* client) {
  return client->client->event_fd();
}

int dvrDisplayManagerClientTranslateEpollEventMask(
    DvrDisplayManagerClient* client, int in_events, int* out_events) {
  auto result = client->client->GetChannel()->GetEventMask(in_events);

  if (!result) {
    return -EIO;
  }

  *out_events = result.get();

  return 0;
}

int dvrDisplayManagerClientGetSurfaceList(
    DvrDisplayManagerClient* client,
    DvrDisplayManagerClientSurfaceList** surface_list) {
  std::vector<android::dvr::DisplaySurfaceInfo> list;
  int ret = client->client->GetSurfaceList(&list);
  if (ret < 0)
    return ret;

  *surface_list = new DvrDisplayManagerClientSurfaceList(std::move(list));
  return ret;
}

void dvrDisplayManagerClientSurfaceListDestroy(
    DvrDisplayManagerClientSurfaceList* surface_list) {
  delete surface_list;
}

size_t dvrDisplayManagerClientSurfaceListGetSize(
    DvrDisplayManagerClientSurfaceList* surface_list) {
  return surface_list->list.size();
}

int dvrDisplayManagerClientSurfaceListGetSurfaceId(
    DvrDisplayManagerClientSurfaceList* surface_list, size_t index) {
  return surface_list->list[index].surface_id;
}

int dvrDisplayManagerClientSurfaceListGetClientZOrder(
    DvrDisplayManagerClientSurfaceList* surface_list, size_t index) {
  return surface_list->list[index].ClientZOrder();
}

bool dvrDisplayManagerClientSurfaceListGetClientIsVisible(
    DvrDisplayManagerClientSurfaceList* surface_list, size_t index) {
  return surface_list->list[index].IsClientVisible();
}

int dvrDisplayManagerClientGetSurfaceBuffers(
    DvrDisplayManagerClient* /* client */, int /* surface_id */,
    DvrDisplayManagerClientSurfaceBuffers** /* surface_buffers */) {
  // TODO(jwcai, hendrikw) Remove this after we replacing
  // dvrDisplayManagerClientGetSurfaceBuffers is dvr_api.
  return -1;
}

void dvrDisplayManagerClientSurfaceBuffersDestroy(
    DvrDisplayManagerClientSurfaceBuffers* surface_buffers) {
  delete surface_buffers;
}

size_t dvrDisplayManagerClientSurfaceBuffersGetSize(
    DvrDisplayManagerClientSurfaceBuffers* surface_buffers) {
  return surface_buffers->list.size();
}

int dvrDisplayManagerClientSurfaceBuffersGetFd(
    DvrDisplayManagerClientSurfaceBuffers* surface_buffers, size_t index) {
  return surface_buffers->list[index]->event_fd();
}

}  // extern "C"
