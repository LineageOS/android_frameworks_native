#ifndef ANDROID_DVR_BUFFER_HUB_DEFS_H_
#define ANDROID_DVR_BUFFER_HUB_DEFS_H_

#include <dvr/dvr_api.h>
#include <hardware/gralloc.h>

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
// [P|C62|...|C1|C0]
// Gain'ed state:     [0|..|0|0] -> Exclusively Writable.
// Post'ed state:     [1|..|0|0]
// Acquired'ed state: [1|..|X|X] -> At least one bit is set in lower 63 bits
// Released'ed state: [0|..|X|X] -> At least one bit is set in lower 63 bits
static constexpr uint64_t kProducerStateBit = 1ULL << 63;
static constexpr uint64_t kConsumerStateMask = (1ULL << 63) - 1;

static inline void ModifyBufferState(std::atomic<uint64_t>* buffer_state,
                                     uint64_t clear_mask, uint64_t set_mask) {
  uint64_t old_state;
  uint64_t new_state;
  do {
    old_state = buffer_state->load();
    new_state = (old_state & ~clear_mask) | set_mask;
  } while (!buffer_state->compare_exchange_weak(old_state, new_state));
}

static inline bool IsBufferGained(uint64_t state) { return state == 0; }

static inline bool IsBufferPosted(uint64_t state,
                                  uint64_t consumer_bit = kConsumerStateMask) {
  return (state & kProducerStateBit) && !(state & consumer_bit);
}

static inline bool IsBufferAcquired(uint64_t state) {
  return (state & kProducerStateBit) && (state & kConsumerStateMask);
}

static inline bool IsBufferReleased(uint64_t state) {
  return !(state & kProducerStateBit) && (state & kConsumerStateMask);
}

static inline uint64_t FindNextClearedBit(uint64_t bits) {
  return ~bits - (~bits & (~bits - 1));
}

static inline uint64_t FindFirstClearedBit() {
  return FindNextClearedBit(kProducerStateBit);
}

struct __attribute__((packed, aligned(8))) MetadataHeader {
  // Internal data format, which can be updated as long as the size, padding and
  // field alignment of the struct is consistent within the same ABI. As this
  // part is subject for future updates, it's not stable cross Android version,
  // so don't have it visible from outside of the Android platform (include Apps
  // and vendor HAL).
  std::atomic<uint64_t> buffer_state;
  std::atomic<uint64_t> fence_state;
  uint64_t queue_index;

  // Public data format, which should be updated with caution. See more details
  // in dvr_api.h
  DvrNativeBufferMetadata metadata;
};

static_assert(sizeof(MetadataHeader) == 128, "Unexpected MetadataHeader size");
static constexpr size_t kMetadataHeaderSize = sizeof(MetadataHeader);

}  // namespace BufferHubDefs

}  // namespace dvr
}  // namespace android


#endif  // ANDROID_DVR_BUFFER_HUB_DEFS_H_
