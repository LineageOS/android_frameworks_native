#include "include/private/dvr/sync_util.h"

#include <errno.h>
#include <sys/ioctl.h>

// TODO: http://b/33239638 Move GetSyncFenceInfo() into upstream libsync instead
//   of duplicating functionality and structure definitions from it.
struct sync_fence_info_data {
 uint32_t len;
 char name[32];
 int32_t status;
 uint8_t pt_info[0];
};

struct sync_pt_info {
 uint32_t len;
 char obj_name[32];
 char driver_name[32];
 int32_t status;
 uint64_t timestamp_ns;
 uint8_t driver_data[0];
};

#define SYNC_IOC_MAGIC '>'
#define SYNC_IOC_WAIT _IOW(SYNC_IOC_MAGIC, 0, __s32)
#define SYNC_IOC_MERGE _IOWR(SYNC_IOC_MAGIC, 1, struct sync_merge_data)
#define SYNC_IOC_FENCE_INFO _IOWR(SYNC_IOC_MAGIC, 2, struct sync_fence_info_data)

namespace android {
namespace dvr {

namespace {

// This is copied from sync_pt_info() in libsync/sync.c. It's been cleaned up to
// remove lint warnings.
sync_pt_info* GetSyncPtInfo(sync_fence_info_data* info, sync_pt_info* itr) {
  if (itr == nullptr)
    itr = reinterpret_cast<sync_pt_info*>(info->pt_info);
  else
    itr = reinterpret_cast<sync_pt_info*>(reinterpret_cast<uint8_t*>(itr) +
                                          itr->len);

  if (reinterpret_cast<uint8_t*>(itr) - reinterpret_cast<uint8_t*>(info) >=
      static_cast<int>(info->len))
    return nullptr;

  return itr;
}

}  // namespace

int GetSyncFenceInfo(int fence_fd, FenceInfoBuffer* buffer) {
  // If the implementation of sync_fence_info() in libsync/sync.c changes, this
  // function should be changed to match.
  if (buffer == nullptr) {
    errno = EINVAL;
    return -1;
  }

  sync_fence_info_data* fence_info =
      reinterpret_cast<sync_fence_info_data*>(buffer);
  fence_info->len = kFenceInfoBufferSize;
  return ioctl(fence_fd, SYNC_IOC_FENCE_INFO, fence_info);
}

int GetFenceSignaledTimestamp(int fence_fd, FenceInfoBuffer* buffer,
                              int64_t* timestamp) {
  int result = GetSyncFenceInfo(fence_fd, buffer);
  if (result < 0)
    return result;

  sync_fence_info_data* fence_info =
      reinterpret_cast<sync_fence_info_data*>(buffer);
  struct sync_pt_info* pt_info = nullptr;
  while ((pt_info = GetSyncPtInfo(fence_info, pt_info)) != nullptr) {
    if (pt_info->status == 1) {
      *timestamp = pt_info->timestamp_ns;
      return 0;
    }
  }

  errno = EAGAIN;
  return -1;
}

}  // namespace dvr
}  // namespace android
