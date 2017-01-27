#ifndef ANDROID_PDX_UDS_CLIENT_CHANNEL_H_
#define ANDROID_PDX_UDS_CLIENT_CHANNEL_H_

#include <pdx/client_channel.h>

#include <uds/channel_manager.h>
#include <uds/service_endpoint.h>

namespace android {
namespace pdx {
namespace uds {

class ClientChannel : public pdx::ClientChannel {
 public:
  ~ClientChannel() override;

  static std::unique_ptr<pdx::ClientChannel> Create(
      LocalChannelHandle channel_handle);

  uint32_t GetIpcTag() const override { return Endpoint::kIpcTag; }
  int event_fd() const override { return epoll_fd_.Get(); }
  LocalChannelHandle& GetChannelHandle() override { return channel_handle_; }
  void* AllocateTransactionState() override;
  void FreeTransactionState(void* state) override;

  Status<void> SendImpulse(int opcode, const void* buffer,
                           size_t length) override;

  Status<int> SendWithInt(void* transaction_state, int opcode,
                          const iovec* send_vector, size_t send_count,
                          const iovec* receive_vector,
                          size_t receive_count) override;
  Status<LocalHandle> SendWithFileHandle(void* transaction_state, int opcode,
                                         const iovec* send_vector,
                                         size_t send_count,
                                         const iovec* receive_vector,
                                         size_t receive_count) override;
  Status<LocalChannelHandle> SendWithChannelHandle(
      void* transaction_state, int opcode, const iovec* send_vector,
      size_t send_count, const iovec* receive_vector,
      size_t receive_count) override;

  FileReference PushFileHandle(void* transaction_state,
                               const LocalHandle& handle) override;
  FileReference PushFileHandle(void* transaction_state,
                               const BorrowedHandle& handle) override;
  ChannelReference PushChannelHandle(void* transaction_state,
                                     const LocalChannelHandle& handle) override;
  ChannelReference PushChannelHandle(
      void* transaction_state, const BorrowedChannelHandle& handle) override;
  bool GetFileHandle(void* transaction_state, FileReference ref,
                     LocalHandle* handle) const override;
  bool GetChannelHandle(void* transaction_state, ChannelReference ref,
                        LocalChannelHandle* handle) const override;

 private:
  explicit ClientChannel(LocalChannelHandle channel_handle);

  Status<int> SendAndReceive(void* transaction_state, int opcode,
                             const iovec* send_vector, size_t send_count,
                             const iovec* receive_vector, size_t receive_count);

  LocalChannelHandle channel_handle_;
  LocalHandle epoll_fd_;
};

}  // namespace uds
}  // namespace pdx
}  // namespace android

#endif  // ANDROID_PDX_UDS_CLIENT_CHANNEL_H_
