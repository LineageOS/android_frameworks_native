#include <private/dvr/shared_buffer_helpers.h>

namespace android {
namespace dvr {

CPUMappedBuffer::CPUMappedBuffer(DvrGlobalBufferKey key, CPUUsageMode mode)
    : buffer_key_(key), usage_mode_(mode) {
  TryMapping();
}

CPUMappedBuffer::CPUMappedBuffer(std::unique_ptr<IonBuffer> buffer,
                                 CPUUsageMode mode)
    : owned_buffer_(std::move(buffer)),
      buffer_(owned_buffer_.get()),
      usage_mode_(mode) {
  TryMapping();
}

CPUMappedBuffer::CPUMappedBuffer(IonBuffer* buffer, CPUUsageMode mode)
    : buffer_(buffer), usage_mode_(mode) {
  TryMapping();
}

CPUMappedBuffer::~CPUMappedBuffer() {
  if (IsMapped()) {
    buffer_->Unlock();
  }
}

void CPUMappedBuffer::TryMapping() {
  // Do we have an IonBuffer for this shared memory object?
  if (buffer_ == nullptr) {
    // Create a display client and get the buffer.
    // TODO(okana): We might want to throttle this.
    auto display_client = display::DisplayClient::Create();
    if (display_client) {
      auto get_result = display_client->GetGlobalBuffer(buffer_key_);
      if (get_result.ok()) {
        owned_buffer_ = get_result.take();
        buffer_ = owned_buffer_.get();
      } else {
        ALOGW("Could not get named buffer from pose service : %s(%d)",
              get_result.GetErrorMessage().c_str(), get_result.error());
      }
    } else {
      ALOGE("Unable to create display client for shared buffer access");
    }
  }

  if (buffer_) {
    auto usage = buffer_->usage() & ~GRALLOC_USAGE_SW_READ_MASK &
                 ~GRALLOC_USAGE_SW_WRITE_MASK;

    // Figure out the usage bits.
    switch (usage_mode_) {
      case CPUUsageMode::READ_OFTEN:
        usage |= GRALLOC_USAGE_SW_READ_OFTEN;
        break;
      case CPUUsageMode::READ_RARELY:
        usage |= GRALLOC_USAGE_SW_READ_RARELY;
        break;
      case CPUUsageMode::WRITE_OFTEN:
        usage |= GRALLOC_USAGE_SW_WRITE_OFTEN;
        break;
      case CPUUsageMode::WRITE_RARELY:
        usage |= GRALLOC_USAGE_SW_WRITE_RARELY;
        break;
    }

    int width = static_cast<int>(buffer_->width());
    int height = 1;
    const auto ret = buffer_->Lock(usage, 0, 0, width, height, &address_);

    if (ret < 0 || !address_) {
      ALOGE("Pose failed to map ring buffer: ret:%d, addr:%p", ret, address_);
      buffer_->Unlock();
    } else {
      size_ = width;
    }
  }
}

}  // namespace dvr
}  // namespace android
