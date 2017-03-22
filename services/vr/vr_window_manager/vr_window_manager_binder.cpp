#include "vr_window_manager_binder.h"

#include <inttypes.h>
#include <sys/mman.h>

#include <binder/IPCThreadState.h>
#include <binder/PermissionCache.h>
#include <binder/Status.h>
#include <cutils/log.h>
#include <private/android_filesystem_config.h>
#include <utils/Errors.h>

namespace android {
namespace service {
namespace vr {

namespace {
const String16 kDumpPermission("android.permission.DUMP");
const String16 kSendMeControllerInputPermission(
    "android.permission.RESTRICTED_VR_ACCESS");
}  // anonymous namespace

constexpr size_t AshmemControllerDataProvider::kRegionLength;

status_t AshmemControllerDataProvider::Connect(const int in_fd) {
  if (in_fd < 0) {
    return BAD_VALUE;
  }
  if (fd_.get() >= 0) {
    // The VrCore is dead. Long live the VrCore.
    Disconnect();
  }
  void* const shared_region =
      ::mmap(nullptr, kRegionLength, PROT_READ, MAP_SHARED, in_fd, 0);
  if (shared_region == MAP_FAILED) {
    shared_region_ = nullptr;
    return NO_MEMORY;
  }

  errno = 0;
  const int fd = ::fcntl(in_fd, F_DUPFD_CLOEXEC, 0);
  if (fd < 0) {
    ::munmap(shared_region, kRegionLength);
    return -errno;
  }
  fd_.reset(fd);
  ALOGI("controller connected %d -> %d @ %p", in_fd, fd, shared_region);

  std::lock_guard<std::mutex> guard(mutex_);
  shared_region_ = shared_region;
  return OK;
}

status_t AshmemControllerDataProvider::Disconnect() {
  if (shared_region_ == nullptr || fd_.get() < 0) {
    return INVALID_OPERATION;
  }
  std::lock_guard<std::mutex> guard(mutex_);
  ::munmap(shared_region_, kRegionLength);
  shared_region_ = nullptr;
  fd_.reset();
  ALOGI("controller disconnected");
  return OK;
}

const void* AshmemControllerDataProvider::LockControllerData() {
  mutex_.lock();
  if (!shared_region_) {
    mutex_.unlock();
    return nullptr;
  }
  return shared_region_;
}

void AshmemControllerDataProvider::UnlockControllerData() { mutex_.unlock(); }

void AshmemControllerDataProvider::dumpInternal(String8& result) {
  result.appendFormat("[controller]\nfd = %d\n", fd_.get());
  if (shared_region_) {
    int32_t* p = reinterpret_cast<int32_t*>(shared_region_);
    result.appendFormat("header = ");
    for (int i = 0; i < 8; ++i) {
      result.appendFormat("%c 0x%08" PRIX32, i ? ',' : '[', p[i]);
    }
    result.appendFormat(" ]\n\n");
  }
}

int VrWindowManagerBinder::Initialize() { return 0; }

binder::Status VrWindowManagerBinder::connectController(
    const ::android::base::unique_fd& in_fd) {
  // TODO(kpschoedel): check permission
#if 0
  int32_t pid, uid;
  if (!PermissionCache::checkCallingPermission(kSendMeControllerInputPermission,
                                               &pid, &uid)) {
    ALOGE("permission denied to pid=%" PRId32 " uid=%" PRId32, pid, uid);
    return binder::Status::fromStatusT(PERMISSION_DENIED);
  }
#endif
  return binder::Status::fromStatusT(Connect(in_fd.get()));
}

binder::Status VrWindowManagerBinder::disconnectController() {
  // TODO(kpschoedel): check permission
#if 0
  int32_t pid, uid;
  if (!PermissionCache::checkCallingPermission(kSendMeControllerInputPermission,
                                               &pid, &uid)) {
    ALOGE("permission denied to pid=%" PRId32 " uid=%" PRId32, pid, uid);
    return binder::Status::fromStatusT(PERMISSION_DENIED);
  }
#endif
  return binder::Status::fromStatusT(Disconnect());
}

binder::Status VrWindowManagerBinder::enterVrMode() {
  // TODO(kpschoedel): check permission
  app_.VrMode(true);
  return binder::Status::ok();
}

binder::Status VrWindowManagerBinder::exitVrMode() {
  // TODO(kpschoedel): check permission
  app_.VrMode(false);
  return binder::Status::ok();
}

binder::Status VrWindowManagerBinder::setDebugMode(int32_t mode) {
  // TODO(kpschoedel): check permission
  app_.EnableDebug(static_cast<bool>(mode));
  return binder::Status::ok();
}

binder::Status VrWindowManagerBinder::set2DMode(int32_t mode) {
  app_.Set2DMode(static_cast<bool>(mode));
  return binder::Status::ok();
}

status_t VrWindowManagerBinder::dump(
    int fd, const Vector<String16>& args [[gnu::unused]]) {
  String8 result;
  const android::IPCThreadState* ipc = android::IPCThreadState::self();
  const pid_t pid = ipc->getCallingPid();
  const uid_t uid = ipc->getCallingUid();
  if ((uid != AID_SHELL) &&
      !PermissionCache::checkPermission(kDumpPermission, pid, uid)) {
    result.appendFormat("Permission denial: can't dump " LOG_TAG
                        " from pid=%d, uid=%d\n",
                        pid, uid);
  } else {
    app_.dumpInternal(result);
    AshmemControllerDataProvider::dumpInternal(result);
  }
  write(fd, result.string(), result.size());
  return OK;
}

}  // namespace vr
}  // namespace service
}  // namespace android
