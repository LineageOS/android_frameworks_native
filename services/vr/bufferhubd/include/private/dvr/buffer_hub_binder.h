#ifndef ANDROID_DVR_BUFFER_HUB_BINDER_H
#define ANDROID_DVR_BUFFER_HUB_BINDER_H

#include <vector>

#include <binder/BinderService.h>
#include <private/dvr/IBufferHub.h>
#include <private/dvr/buffer_client.h>
#include <private/dvr/buffer_hub.h>

namespace android {
namespace dvr {

class BufferHubBinderService : public BinderService<BufferHubBinderService>,
                               public BnBufferHub {
 public:
  static status_t start(const std::shared_ptr<BufferHubService>& pdx_service);
  static const char* getServiceName() { return "bufferhubd"; }
  // Dump bufferhub related information to given fd (usually stdout)
  // usage: adb shell dumpsys bufferhubd
  virtual status_t dump(int fd, const Vector<String16>& args) override;

  // Helper function to get the BpReference to this service
  static sp<IBufferHub> getServiceProxy();

  // Binder IPC functions
  sp<IBufferClient> createBuffer(uint32_t width, uint32_t height,
                                 uint32_t layer_count, uint32_t format,
                                 uint64_t usage,
                                 uint64_t user_metadata_size) override;

 private:
  std::shared_ptr<BufferHubService> pdx_service_;

  std::vector<sp<BufferClient>> client_list_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFER_HUB_BINDER_H
