#ifndef ANDROID_DVR_BUFFERCLIENT_H
#define ANDROID_DVR_BUFFERCLIENT_H

#include <private/dvr/IBufferClient.h>
#include <private/dvr/buffer_node.h>

namespace android {
namespace dvr {

class BufferClient : public BnBufferClient {
 public:
  // Creates a server-side buffer client from an existing BufferNode. Note that
  // this funciton takes ownership of the shared_ptr.
  explicit BufferClient(std::shared_ptr<BufferNode> node)
      : buffer_node_(std::move(node)){};

  // Binder IPC functions
  bool isValid() override {
    return buffer_node_ ? buffer_node_->IsValid() : false;
  };

 private:
  std::shared_ptr<BufferNode> buffer_node_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_IBUFFERCLIENT_H