#ifndef ANDROID_DVR_SYNC_UTIL_H_
#define ANDROID_DVR_SYNC_UTIL_H_

#include <cstdint>
#include <type_traits>

namespace android {
namespace dvr {

constexpr size_t kFenceInfoBufferSize = 4096;

// This buffer is eventually mapped to a sync_fence_info_data struct (from
// sync.h), whose largest member is a uint32_t. We align to 8 bytes to be extra
// cautious.
using FenceInfoBuffer = std::aligned_storage<kFenceInfoBufferSize, 8>::type;

// Get fence info. Internally this works just like sync_fence_info(), except the
// caller supplies a memory buffer instead of allocating memory.
// On success, returns 0. On error, -1 is returned, and errno is set.
int GetSyncFenceInfo(int fence_fd, FenceInfoBuffer* buffer);

// Returns the timestamp when the fence was first signaled. buffer is used as
// described in GetSyncFenceInfo().
// On success, returns 0. On error, -1 is returned, and errno is set.
int GetFenceSignaledTimestamp(int fence_fd, FenceInfoBuffer* buffer,
                              int64_t* timestamp);

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SYNC_UTIL_H_
