#ifndef ANDROID_DVR_BUFFER_HUB_BINDER_H
#define ANDROID_DVR_BUFFER_HUB_BINDER_H

#include <random>
#include <unordered_map>
#include <vector>

#include <binder/BinderService.h>
#include <private/dvr/IBufferHub.h>
#include <private/dvr/buffer_client.h>
#include <private/dvr/buffer_hub.h>
#include <private/dvr/buffer_node.h>

namespace android {
namespace dvr {

class BufferHubBinderService : public BinderService<BufferHubBinderService>,
                               public BnBufferHub {
 public:
  static status_t start(const std::shared_ptr<BufferHubService>& pdx_service);
  // Dumps bufferhub related information to given fd (usually stdout)
  // usage: adb shell dumpsys bufferhubd
  virtual status_t dump(int fd, const Vector<String16>& args) override;

  // Marks a BufferNode to be duplicated.
  // TODO(b/116681016): add importToken(int64_t)
  status_t registerToken(const std::weak_ptr<BufferNode> node,
                         uint64_t* outToken);

  // Binder IPC functions
  sp<IBufferClient> createBuffer(uint32_t width, uint32_t height,
                                 uint32_t layer_count, uint32_t format,
                                 uint64_t usage,
                                 uint64_t user_metadata_size) override;

  status_t importBuffer(uint64_t token, sp<IBufferClient>* outClient) override;

 private:
  std::shared_ptr<BufferHubService> pdx_service_;

  std::vector<sp<BufferClient>> client_list_;

  // TODO(b/118180214): use a more secure implementation
  std::mt19937_64 token_engine_;
  // The mapping from token to a specific node. This is a many-to-one mapping.
  // One node could be refered by 0 to multiple tokens.
  std::unordered_map<uint64_t, std::weak_ptr<BufferNode>> token_map_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFER_HUB_BINDER_H
