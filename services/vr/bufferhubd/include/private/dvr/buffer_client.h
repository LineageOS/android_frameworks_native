#ifndef ANDROID_DVR_BUFFERCLIENT_H
#define ANDROID_DVR_BUFFERCLIENT_H

#include <private/dvr/IBufferClient.h>
#include <private/dvr/buffer_node.h>

namespace android {
namespace dvr {

// Forward declaration to avoid circular dependency
class BufferHubBinderService;

class BufferClient : public BnBufferClient {
 public:
  // Creates a server-side buffer client from an existing BufferNode. Note that
  // this funciton takes ownership of the shared_ptr.
  explicit BufferClient(std::shared_ptr<BufferNode> node,
                        BufferHubBinderService* service)
      : service_(service), buffer_node_(std::move(node)){};

  // Binder IPC functions
  bool isValid() override {
    return buffer_node_ ? buffer_node_->IsValid() : false;
  };

  status_t duplicate(uint64_t* outToken) override;

 private:
  // Hold a pointer to the service to bypass binder interface, as BufferClient
  // and the service will be in the same process. Also, since service owns
  // Client, if service dead the clients will be destroyed, so this pointer is
  // guaranteed to be valid.
  BufferHubBinderService* service_;

  std::shared_ptr<BufferNode> buffer_node_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_IBUFFERCLIENT_H