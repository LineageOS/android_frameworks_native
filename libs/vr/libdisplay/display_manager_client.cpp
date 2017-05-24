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

pdx::Status<std::unique_ptr<IonBuffer>> DisplayManagerClient::SetupGlobalBuffer(
    DvrGlobalBufferKey key, size_t size, uint64_t usage) {
  auto status = InvokeRemoteMethod<DisplayManagerProtocol::SetupGlobalBuffer>(
      key, size, usage);
  if (!status) {
    ALOGE(
        "DisplayManagerClient::SetupGlobalBuffer: Failed to create the global "
        "buffer %s",
        status.GetErrorMessage().c_str());
    return status.error_status();
  }

  auto ion_buffer = std::make_unique<IonBuffer>();
  auto native_buffer_handle = status.take();
  const int ret = native_buffer_handle.Import(ion_buffer.get());
  if (ret < 0) {
    ALOGE(
        "DisplayManagerClient::GetGlobalBuffer: Failed to import global "
        "buffer: key=%d; error=%s",
        key, strerror(-ret));
    return ErrorStatus(-ret);
  }

  return {std::move(ion_buffer)};
}

pdx::Status<void> DisplayManagerClient::DeleteGlobalBuffer(
    DvrGlobalBufferKey key) {
  auto status =
      InvokeRemoteMethod<DisplayManagerProtocol::DeleteGlobalBuffer>(key);
  if (!status) {
    ALOGE("DisplayManagerClient::DeleteGlobalBuffer Failed: %s",
          status.GetErrorMessage().c_str());
  }

  return status;
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
