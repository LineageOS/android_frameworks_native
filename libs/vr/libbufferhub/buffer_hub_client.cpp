#include <mutex>

#include <log/log.h>
#include <pdx/default_transport/client_channel.h>
#include <pdx/default_transport/client_channel_factory.h>
#include <private/dvr/buffer_hub_client.h>
#include <utils/Trace.h>

using android::pdx::LocalChannelHandle;
using android::pdx::default_transport::ClientChannel;
using android::pdx::default_transport::ClientChannelFactory;

namespace android {
namespace dvr {

BufferHubClient::BufferHubClient()
    : Client(ClientChannelFactory::Create(BufferHubRPC::kClientPath)) {}

BufferHubClient::BufferHubClient(LocalChannelHandle channel_handle)
    : Client(ClientChannel::Create(std::move(channel_handle))) {}

bool BufferHubClient::IsValid() const {
  return IsConnected() && GetChannelHandle().valid();
}

LocalChannelHandle BufferHubClient::TakeChannelHandle() {
  if (IsConnected()) {
    return std::move(GetChannelHandle());
  } else {
    return {};
  }
}

}  // namespace dvr
}  // namespace android
