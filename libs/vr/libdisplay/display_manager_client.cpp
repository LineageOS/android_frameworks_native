#include "include/private/dvr/display_manager_client.h"

#include <pdx/default_transport/client_channel_factory.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/buffer_hub_queue_client.h>
#include <private/dvr/display_protocol.h>
#include <utils/Log.h>

using android::pdx::ErrorStatus;
using android::pdx::LocalChannelHandle;
using android::pdx::Transaction;

namespace android {
namespace dvr {
namespace display {

DisplayManagerClient::DisplayManagerClient()
    : BASE(pdx::default_transport::ClientChannelFactory::Create(
          DisplayManagerProtocol::kClientPath)) {}

DisplayManagerClient::~DisplayManagerClient() {}

pdx::Status<std::vector<display::SurfaceState>>
DisplayManagerClient::GetSurfaceState() {
  auto status = InvokeRemoteMethod<DisplayManagerProtocol::GetSurfaceState>();
  if (!status) {
    ALOGE(
        "DisplayManagerClient::GetSurfaceState: Failed to get surface info: %s",
        status.GetErrorMessage().c_str());
  }

  return status;
}

pdx::Status<std::unique_ptr<IonBuffer>> DisplayManagerClient::SetupNamedBuffer(
    const std::string& name, size_t size, uint64_t usage) {
  auto status = InvokeRemoteMethod<DisplayManagerProtocol::SetupNamedBuffer>(
      name, size, usage);
  if (!status) {
    ALOGE(
        "DisplayManagerClient::SetupPoseBuffer: Failed to create the named "
        "buffer %s",
        status.GetErrorMessage().c_str());
    return status.error_status();
  }

  auto ion_buffer = std::make_unique<IonBuffer>();
  auto native_buffer_handle = status.take();
  const int ret = native_buffer_handle.Import(ion_buffer.get());
  if (ret < 0) {
    ALOGE(
        "DisplayClient::GetNamedBuffer: Failed to import named buffer: "
        "name=%s; error=%s",
        name.c_str(), strerror(-ret));
    return ErrorStatus(-ret);
  }

  return {std::move(ion_buffer)};
}

pdx::Status<std::unique_ptr<ConsumerQueue>>
DisplayManagerClient::GetSurfaceQueue(int surface_id, int queue_id) {
  auto status = InvokeRemoteMethod<DisplayManagerProtocol::GetSurfaceQueue>(
      surface_id, queue_id);
  if (!status) {
    ALOGE(
        "DisplayManagerClient::GetSurfaceQueue: Failed to get queue for "
        "surface_id=%d queue_id=%d: %s",
        surface_id, queue_id, status.GetErrorMessage().c_str());
    return status.error_status();
  }

  return {ConsumerQueue::Import(status.take())};
}

}  // namespace display
}  // namespace dvr
}  // namespace android
