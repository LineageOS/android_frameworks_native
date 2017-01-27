#include "surface_channel.h"

using android::pdx::BorrowedChannelHandle;
using android::pdx::Message;
using android::pdx::rpc::DispatchRemoteMethod;

namespace android {
namespace dvr {

int SurfaceChannel::HandleMessage(Message& message) {
  switch (message.GetOp()) {
    case DisplayRPC::GetMetadataBuffer::Opcode:
      DispatchRemoteMethod<DisplayRPC::GetMetadataBuffer>(
          *this, &SurfaceChannel::OnGetMetadataBuffer, message);
      break;
  }

  return 0;
}

BorrowedChannelHandle SurfaceChannel::OnGetMetadataBuffer(Message& message) {
  if (EnsureMetadataBuffer()) {
    return metadata_buffer_->GetChannelHandle().Borrow();
  } else {
    REPLY_ERROR_RETURN(message, -ENOMEM, {});
  }
}

bool SurfaceChannel::EnsureMetadataBuffer() {
  if (!metadata_buffer_) {
    metadata_buffer_ =
        BufferProducer::CreateUncachedBlob(metadata_size());
    if (!metadata_buffer_) {
      ALOGE(
          "DisplaySurface::EnsureMetadataBuffer: could not allocate metadata "
          "buffer");
      return false;
    }
  }
  return true;
}

}  // namespace dvr
}  // namespace android
