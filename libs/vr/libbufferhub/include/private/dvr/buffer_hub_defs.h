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

// Single buffer clients (up to 32) ownership signal.
// 64-bit atomic unsigned int.
// Each client takes 2 bits. The first bit locates in the first 32 bits of
// buffer_state; the second bit locates in the last 32 bits of buffer_state.
// Client states:
// Gained state 11. Exclusive write state.
// Posted state 10.
// Acquired state 01. Shared read state.
// Released state 00.
//
//  MSB                        LSB
//   |                          |
//   v                          v
// [C31|...|C1|C0|C31| ... |C1|C0]

// Maximum number of clients a buffer can have.
static constexpr int kMaxNumberOfClients = 32;

// Definition of bit masks.
//  MSB                            LSB
//   | kHighBitsMask | kLowbitsMask |
//   v               v              v
// [b63|   ...   |b32|b31|   ...  |b0]

// The location of lower 32 bits in the 64-bit buffer state.
static constexpr uint64_t kLowbitsMask = (1ULL << kMaxNumberOfClients) - 1ULL;

// The location of higher 32 bits in the 64-bit buffer state.
static constexpr uint64_t kHighBitsMask = ~kLowbitsMask;

// The client bit mask of the first client.
static constexpr uint64_t kFirstClientBitMask =
    (1ULL << kMaxNumberOfClients) + 1ULL;

// Returns true if any of the client is in gained state.
static inline bool AnyClientGained(uint64_t state) {
  uint64_t high_bits = state >> kMaxNumberOfClients;
  uint64_t low_bits = state & kLowbitsMask;
  return high_bits == low_bits && low_bits != 0ULL;
}

// Returns true if the input client is in gained state.
static inline bool IsClientGained(uint64_t state, uint64_t client_bit_mask) {
  return state == client_bit_mask;
}

// Returns true if any of the client is in posted state.
static inline bool AnyClientPosted(uint64_t state) {
  uint64_t high_bits = state >> kMaxNumberOfClients;
  uint64_t low_bits = state & kLowbitsMask;
  uint64_t posted_or_acquired = high_bits ^ low_bits;
  return posted_or_acquired & high_bits;
}

// Returns true if the input client is in posted state.
static inline bool IsClientPosted(uint64_t state, uint64_t client_bit_mask) {
  uint64_t client_bits = state & client_bit_mask;
  if (client_bits == 0ULL)
    return false;
  uint64_t low_bits = client_bits & kLowbitsMask;
  return low_bits == 0ULL;
}

// Return true if any of the client is in acquired state.
static inline bool AnyClientAcquired(uint64_t state) {
  uint64_t high_bits = state >> kMaxNumberOfClients;
  uint64_t low_bits = state & kLowbitsMask;
  uint64_t posted_or_acquired = high_bits ^ low_bits;
  return posted_or_acquired & low_bits;
}

// Return true if the input client is in acquired state.
static inline bool IsClientAcquired(uint64_t state, uint64_t client_bit_mask) {
  uint64_t client_bits = state & client_bit_mask;
  if (client_bits == 0ULL)
    return false;
  uint64_t high_bits = client_bits & kHighBitsMask;
  return high_bits == 0ULL;
}

// Returns true if all clients are in released state.
static inline bool IsBufferReleased(uint64_t state) { return state == 0ULL; }

// Returns true if the input client is in released state.
static inline bool IsClientReleased(uint64_t state, uint64_t client_bit_mask) {
  return (state & client_bit_mask) == 0ULL;
}

// Returns the next available buffer client's client_state_masks.
// @params union_bits. Union of all existing clients' client_state_masks.
static inline uint64_t FindNextAvailableClientStateMask(uint64_t union_bits) {
  uint64_t low_union = union_bits & kLowbitsMask;
  if (low_union == kLowbitsMask)
    return 0ULL;
  uint64_t incremented = low_union + 1ULL;
  uint64_t difference = incremented ^ low_union;
  uint64_t new_low_bit = (difference + 1ULL) >> 1;
  return new_low_bit + (new_low_bit << kMaxNumberOfClients);
}

struct __attribute__((packed, aligned(8))) MetadataHeader {
  // Internal data format, which can be updated as long as the size, padding and
  // field alignment of the struct is consistent within the same ABI. As this
  // part is subject for future updates, it's not stable cross Android version,
  // so don't have it visible from outside of the Android platform (include Apps
  // and vendor HAL).

  // Every client takes up one bit from the higher 32 bits and one bit from the
  // lower 32 bits in buffer_state.
  std::atomic<uint64_t> buffer_state;

  // Every client takes up one bit in fence_state. Only the lower 32 bits are
  // valid. The upper 32 bits are there for easier manipulation, but the value
  // should be ignored.
  std::atomic<uint64_t> fence_state;

  // Every client takes up one bit from the higher 32 bits and one bit from the
  // lower 32 bits in active_clients_bit_mask.
  std::atomic<uint64_t> active_clients_bit_mask;

  // The index of the buffer queue where the buffer belongs to.
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
