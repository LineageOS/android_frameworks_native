#include <private/dvr/buffer_client.h>
#include <private/dvr/buffer_hub_binder.h>

namespace android {
namespace dvr {

status_t BufferClient::duplicate(uint64_t* outToken) {
  if (!buffer_node_) {
    // Should never happen
    ALOGE("BufferClient::duplicate: node is missing.");
    return UNEXPECTED_NULL;
  }
  return service_->registerToken(std::weak_ptr<BufferNode>(buffer_node_),
                                 outToken);
}

}  // namespace dvr
}  // namespace android