#ifndef ANDROID_DVR_DISPLAY_MANAGER_CLIENT_IMPL_H_
#define ANDROID_DVR_DISPLAY_MANAGER_CLIENT_IMPL_H_

#include <vector>

#include <pdx/client.h>
#include <private/dvr/display_rpc.h>

namespace android {
namespace dvr {

class BufferProducer;

class DisplayManagerClient : public pdx::ClientBase<DisplayManagerClient> {
 public:
  ~DisplayManagerClient() override;

  int GetSurfaceList(std::vector<DisplaySurfaceInfo>* surface_list);

  std::unique_ptr<BufferProducer> SetupPoseBuffer(size_t extended_region_size,
                                                  int usage);

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
