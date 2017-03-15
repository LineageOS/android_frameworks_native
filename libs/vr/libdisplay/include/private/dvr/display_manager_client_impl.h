#ifndef ANDROID_DVR_DISPLAY_MANAGER_CLIENT_IMPL_H_
#define ANDROID_DVR_DISPLAY_MANAGER_CLIENT_IMPL_H_

#include <vector>

#include <pdx/client.h>
#include <private/dvr/display_rpc.h>

namespace android {
namespace dvr {

class BufferConsumer;

class DisplayManagerClient : public pdx::ClientBase<DisplayManagerClient> {
 public:
  ~DisplayManagerClient() override;

  int GetSurfaceList(std::vector<DisplaySurfaceInfo>* surface_list);

  using Client::event_fd;
  using Client::GetChannel;

 private:
  friend BASE;

  DisplayManagerClient();

  DisplayManagerClient(const DisplayManagerClient&) = delete;
  void operator=(const DisplayManagerClient&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_DISPLAY_MANAGER_CLIENT_IMPL_H_
