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

std::unique_ptr<BufferProducer> DisplayManagerClient::SetupPoseBuffer(
    size_t extended_region_size, int usage) {
  auto status = InvokeRemoteMethod<DisplayManagerRPC::SetupPoseBuffer>(
      extended_region_size, usage);
  if (!status) {
    ALOGE(
        "DisplayManagerClient::SetupPoseBuffer: Failed to create the pose "
        "buffer %s",
        status.GetErrorMessage().c_str());
    return {};
  }

  return BufferProducer::Import(std::move(status));
}

}  // namespace dvr
}  // namespace android
