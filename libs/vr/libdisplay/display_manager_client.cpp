#include "include/private/dvr/display_manager_client.h"

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
    DvrDisplayManagerClient* client, int surface_id,
    DvrDisplayManagerClientSurfaceBuffers** surface_buffers) {
  std::vector<std::unique_ptr<android::dvr::BufferConsumer>> buffer_list;
  int ret = client->client->GetSurfaceBuffers(surface_id, &buffer_list);
  if (ret < 0)
    return ret;

  *surface_buffers =
      new DvrDisplayManagerClientSurfaceBuffers(std::move(buffer_list));
  return ret;
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
