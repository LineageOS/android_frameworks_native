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

std::unique_ptr<IonBuffer> DisplayManagerClient::SetupNamedBuffer(
    const std::string& name, size_t size, uint64_t producer_usage,
    uint64_t consumer_usage) {
  auto status = InvokeRemoteMethod<DisplayManagerRPC::SetupNamedBuffer>(
      name, size, producer_usage, consumer_usage);
  if (!status) {
    ALOGE(
        "DisplayManagerClient::SetupNamedBuffer: Failed to create the named "
        "buffer: name=%s, error=%s",
        name.c_str(), status.GetErrorMessage().c_str());
    return {};
  }

  auto ion_buffer = std::make_unique<IonBuffer>();
  status.take().Import(ion_buffer.get());
  return ion_buffer;
}

}  // namespace dvr
}  // namespace android
