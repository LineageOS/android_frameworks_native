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

}  // namespace dvr
}  // namespace android
