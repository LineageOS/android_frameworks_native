#ifndef ANDROID_DVR_BUFFER_HUB_CLIENT_H_
#define ANDROID_DVR_BUFFER_HUB_CLIENT_H_

#include <pdx/channel_handle.h>
#include <pdx/client.h>
#include <private/dvr/consumer_buffer.h>
#include <private/dvr/producer_buffer.h>

namespace android {
namespace dvr {

class BufferHubClient : public pdx::Client {
 public:
  BufferHubClient();
  explicit BufferHubClient(pdx::LocalChannelHandle channel_handle);

  bool IsValid() const;
  pdx::LocalChannelHandle TakeChannelHandle();

  using pdx::Client::Close;
  using pdx::Client::GetChannel;
  using pdx::Client::InvokeRemoteMethod;
  using pdx::Client::IsConnected;
  using pdx::Client::event_fd;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFER_HUB_CLIENT_H_
