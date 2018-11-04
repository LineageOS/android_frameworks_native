#ifndef ANDROID_DVR_BUFFER_HUB_DEFS_H_
#define ANDROID_DVR_BUFFER_HUB_DEFS_H_

#include <dvr/dvr_api.h>
#include <hardware/gralloc.h>
#include <pdx/channel_handle.h>
#include <pdx/file_handle.h>
#include <pdx/rpc/remote_method.h>
#include <pdx/rpc/serializable.h>
#include <private/dvr/native_handle_wrapper.h>

#include <atomic>

namespace android {
namespace dvr {

namespace BufferHubDefs {

static constexpr uint32_t kMetadataFormat = HAL_PIXEL_FORMAT_BLOB;
static constexpr uint32_t kMetadataUsage =
    GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN;

// Single producuer multiple (up to 63) consumers ownership signal.
// 64-bit atomic unsigned int.
//
// MSB           LSB
//  |             |
//  v             v
// [C62|...|C1|C0|P]
// Gain'ed state:     [..|0|0|0] -> Exclusively Writable.
// Post'ed state:     [..|0|0|1]
// Acquired'ed state: [..|X|X|1] -> At least one bit is set in higher 63 bits
// Released'ed state: [..|X|X|0] -> At least one bit is set in higher 63 bits
static constexpr int kMaxNumberOfClients = 64;
static constexpr uint64_t kFirstClientBitMask = 1ULL;
static constexpr uint64_t kConsumerStateMask = ~kFirstClientBitMask;

static inline void ModifyBufferState(std::atomic<uint64_t>* buffer_state,
                                     uint64_t clear_mask, uint64_t set_mask) {
  uint64_t old_state;
  uint64_t new_state;
  do {
    old_state = buffer_state->load(std::memory_order_acquire);
    new_state = (old_state & ~clear_mask) | set_mask;
  } while (!buffer_state->compare_exchange_weak(old_state, new_state));
}

static inline bool IsBufferGained(uint64_t state) { return state == 0; }

static inline bool IsBufferPosted(uint64_t state,
                                  uint64_t consumer_bit = kConsumerStateMask) {
  return (state & kFirstClientBitMask) && !(state & consumer_bit);
}

static inline bool IsBufferAcquired(uint64_t state) {
  return (state & kFirstClientBitMask) && (state & kConsumerStateMask);
}

static inline bool IsBufferReleased(uint64_t state) {
  return !(state & kFirstClientBitMask) && (state & kConsumerStateMask);
}

static inline uint64_t FindNextAvailableClientStateMask(uint64_t bits) {
  return ~bits - (~bits & (~bits - 1));
}

static inline uint64_t FindFirstClearedBit() {
  return FindNextAvailableClientStateMask(kFirstClientBitMask);
}

struct __attribute__((packed, aligned(8))) MetadataHeader {
  // Internal data format, which can be updated as long as the size, padding and
  // field alignment of the struct is consistent within the same ABI. As this
  // part is subject for future updates, it's not stable cross Android version,
  // so don't have it visible from outside of the Android platform (include Apps
  // and vendor HAL).
  std::atomic<uint64_t> buffer_state;
  std::atomic<uint64_t> fence_state;
  std::atomic<uint64_t> active_clients_bit_mask;
  uint64_t queue_index;

  // Public data format, which should be updated with caution. See more details
  // in dvr_api.h
  DvrNativeBufferMetadata metadata;
};

static_assert(sizeof(MetadataHeader) == 136, "Unexpected MetadataHeader size");
static constexpr size_t kMetadataHeaderSize = sizeof(MetadataHeader);

}  // namespace BufferHubDefs

template <typename FileHandleType>
class BufferTraits {
 public:
  BufferTraits() = default;
  BufferTraits(const native_handle_t* buffer_handle,
               const FileHandleType& metadata_handle, int id,
               uint64_t client_state_mask, uint64_t metadata_size,
               uint32_t width, uint32_t height, uint32_t layer_count,
               uint32_t format, uint64_t usage, uint32_t stride,
               const FileHandleType& acquire_fence_fd,
               const FileHandleType& release_fence_fd)
      : id_(id),
        client_state_mask_(client_state_mask),
        metadata_size_(metadata_size),
        width_(width),
        height_(height),
        layer_count_(layer_count),
        format_(format),
        usage_(usage),
        stride_(stride),
        buffer_handle_(buffer_handle),
        metadata_handle_(metadata_handle.Borrow()),
        acquire_fence_fd_(acquire_fence_fd.Borrow()),
        release_fence_fd_(release_fence_fd.Borrow()) {}

  BufferTraits(BufferTraits&& other) = default;
  BufferTraits& operator=(BufferTraits&& other) = default;

  // ID of the buffer client. All BufferHubBuffer clients derived from the same
  // buffer in bufferhubd share the same buffer id.
  int id() const { return id_; }

  // State mask of the buffer client. Each BufferHubBuffer client backed by the
  // same buffer channel has uniqued state bit among its siblings. For a
  // producer buffer the bit must be kFirstClientBitMask; for a consumer the bit
  // must be one of the kConsumerStateMask.
  uint64_t client_state_mask() const { return client_state_mask_; }
  uint64_t metadata_size() const { return metadata_size_; }

  uint32_t width() { return width_; }
  uint32_t height() { return height_; }
  uint32_t layer_count() { return layer_count_; }
  uint32_t format() { return format_; }
  uint64_t usage() { return usage_; }
  uint32_t stride() { return stride_; }

  const NativeHandleWrapper<FileHandleType>& buffer_handle() const {
    return buffer_handle_;
  }

  NativeHandleWrapper<FileHandleType> take_buffer_handle() {
    return std::move(buffer_handle_);
  }
  FileHandleType take_metadata_handle() { return std::move(metadata_handle_); }
  FileHandleType take_acquire_fence() { return std::move(acquire_fence_fd_); }
  FileHandleType take_release_fence() { return std::move(release_fence_fd_); }

 private:
  // BufferHub specific traits.
  int id_ = -1;
  uint64_t client_state_mask_;
  uint64_t metadata_size_;

  // Traits for a GraphicBuffer.
  uint32_t width_;
  uint32_t height_;
  uint32_t layer_count_;
  uint32_t format_;
  uint64_t usage_;
  uint32_t stride_;

  // Native handle for the graphic buffer.
  NativeHandleWrapper<FileHandleType> buffer_handle_;

  // File handle of an ashmem that holds buffer metadata.
  FileHandleType metadata_handle_;

  // Pamameters for shared fences.
  FileHandleType acquire_fence_fd_;
  FileHandleType release_fence_fd_;

  PDX_SERIALIZABLE_MEMBERS(BufferTraits<FileHandleType>, id_,
                           client_state_mask_, metadata_size_, stride_, width_,
                           height_, layer_count_, format_, usage_,
                           buffer_handle_, metadata_handle_, acquire_fence_fd_,
                           release_fence_fd_);

  BufferTraits(const BufferTraits&) = delete;
  void operator=(const BufferTraits&) = delete;
};

struct DetachedBufferRPC {
 private:
  enum {
    kOpDetachedBufferBase = 1000,

    // Allocates a standalone DetachedBuffer not associated with any producer
    // consumer set.
    kOpCreate,

    // Imports the given channel handle to a DetachedBuffer, taking ownership.
    kOpImport,

    // Creates a DetachedBuffer client from an existing one. The new client will
    // share the same underlying gralloc buffer and ashmem region for metadata.
    kOpDuplicate,
  };

  // Aliases.
  using LocalChannelHandle = pdx::LocalChannelHandle;
  using LocalHandle = pdx::LocalHandle;
  using Void = pdx::rpc::Void;

 public:
  PDX_REMOTE_METHOD(Create, kOpCreate,
                    void(uint32_t width, uint32_t height, uint32_t layer_count,
                         uint32_t format, uint64_t usage,
                         size_t user_metadata_size));
  PDX_REMOTE_METHOD(Import, kOpImport, BufferTraits<LocalHandle>(Void));
  PDX_REMOTE_METHOD(Duplicate, kOpDuplicate, LocalChannelHandle(Void));

  PDX_REMOTE_API(API, Create, Import, Duplicate);
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFER_HUB_DEFS_H_
