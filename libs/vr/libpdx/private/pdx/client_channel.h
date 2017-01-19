#ifndef ANDROID_PDX_CLIENT_CHANNEL_H_
#define ANDROID_PDX_CLIENT_CHANNEL_H_

#include <pdx/channel_handle.h>
#include <pdx/file_handle.h>
#include <pdx/status.h>

struct iovec;

namespace android {
namespace pdx {

class ClientChannel {
 public:
  virtual ~ClientChannel() = default;

  // Returns a tag that uniquely identifies a specific underlying IPC transport.
  virtual uint32_t GetIpcTag() const = 0;

  virtual int event_fd() const = 0;
  virtual Status<int> GetEventMask(int events) = 0;

  virtual LocalChannelHandle& GetChannelHandle() = 0;
  virtual void* AllocateTransactionState() = 0;
  virtual void FreeTransactionState(void* state) = 0;

  virtual Status<void> SendImpulse(int opcode, const void* buffer,
                                   size_t length) = 0;

  virtual Status<int> SendWithInt(void* transaction_state, int opcode,
                                  const iovec* send_vector, size_t send_count,
                                  const iovec* receive_vector,
                                  size_t receive_count) = 0;
  virtual Status<LocalHandle> SendWithFileHandle(
      void* transaction_state, int opcode, const iovec* send_vector,
      size_t send_count, const iovec* receive_vector, size_t receive_count) = 0;
  virtual Status<LocalChannelHandle> SendWithChannelHandle(
      void* transaction_state, int opcode, const iovec* send_vector,
      size_t send_count, const iovec* receive_vector, size_t receive_count) = 0;

  virtual FileReference PushFileHandle(void* transaction_state,
                                       const LocalHandle& handle) = 0;
  virtual FileReference PushFileHandle(void* transaction_state,
                                       const BorrowedHandle& handle) = 0;
  virtual ChannelReference PushChannelHandle(
      void* transaction_state, const LocalChannelHandle& handle) = 0;
  virtual ChannelReference PushChannelHandle(
      void* transaction_state, const BorrowedChannelHandle& handle) = 0;
  virtual bool GetFileHandle(void* transaction_state, FileReference ref,
                             LocalHandle* handle) const = 0;
  virtual bool GetChannelHandle(void* transaction_state, ChannelReference ref,
                                LocalChannelHandle* handle) const = 0;
};

}  // namespace pdx
}  // namespace android

#endif  // ANDROID_PDX_CLIENT_CHANNEL_H_
