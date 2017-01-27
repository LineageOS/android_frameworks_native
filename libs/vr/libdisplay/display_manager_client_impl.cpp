#include "include/private/dvr/display_manager_client_impl.h"

#include <pdx/default_transport/client_channel_factory.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/display_rpc.h>
#include <utils/Log.h>

using android::pdx::LocalChannelHandle;
using android::pdx::Transaction;

namespace android {
namespace dvr {

DisplayManagerClient::DisplayManagerClient()
    : BASE(pdx::default_transport::ClientChannelFactory::Create(
          DisplayManagerRPC::kClientPath)) {}

DisplayManagerClient::~DisplayManagerClient() {}

int DisplayManagerClient::GetSurfaceList(
    std::vector<DisplaySurfaceInfo>* surface_list) {
  auto status = InvokeRemoteMethod<DisplayManagerRPC::GetSurfaceList>();
  if (!status) {
    ALOGE(
        "DisplayManagerClient::GetSurfaceList: Failed to get surface info: %s",
        status.GetErrorMessage().c_str());
    return -status.error();
  }

  *surface_list = status.take();
  return 0;
}

int DisplayManagerClient::GetSurfaceBuffers(
    int surface_id, std::vector<std::unique_ptr<BufferConsumer>>* consumers) {
  auto status =
      InvokeRemoteMethod<DisplayManagerRPC::GetSurfaceBuffers>(surface_id);
  if (!status) {
    ALOGE(
        "DisplayManagerClient::GetSurfaceBuffers: Failed to get buffers for "
        "surface_id=%d: %s",
        surface_id, status.GetErrorMessage().c_str());
    return -status.error();
  }

  std::vector<std::unique_ptr<BufferConsumer>> consumer_buffers;
  std::vector<LocalChannelHandle> channel_handles = status.take();
  for (auto&& handle : channel_handles) {
    consumer_buffers.push_back(BufferConsumer::Import(std::move(handle)));
  }

  *consumers = std::move(consumer_buffers);
  return 0;
}

}  // namespace dvr
}  // namespace android
