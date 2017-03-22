#ifndef VR_WINDOW_MANAGER_VR_WINDOW_MANAGER_BINDER_H_
#define VR_WINDOW_MANAGER_VR_WINDOW_MANAGER_BINDER_H_

#include <android/service/vr/BnVrWindowManager.h>

#include <mutex>

#include "controller_data_provider.h"
#include "shell_view_binder_interface.h"

namespace android {
namespace service {
namespace vr {

class AshmemControllerDataProvider : public dvr::ControllerDataProvider {
 public:
  AshmemControllerDataProvider() {}
  virtual ~AshmemControllerDataProvider() {}

  status_t Connect(int fd);
  status_t Disconnect();

  // ControllerDataProvider:
  const void* LockControllerData() override;
  void UnlockControllerData() override;

 protected:
  void dumpInternal(String8& result);

 private:
  static constexpr size_t kRegionLength = 8192;  // TODO(kpschoedel)
  ::android::base::unique_fd fd_;

  // Mutex for guarding shared_region_.
  std::mutex mutex_;
  void* shared_region_ = nullptr;

  AshmemControllerDataProvider(const AshmemControllerDataProvider&) = delete;
  void operator=(const AshmemControllerDataProvider&) = delete;
};

class VrWindowManagerBinder : public BnVrWindowManager,
                              public AshmemControllerDataProvider {
 public:
  VrWindowManagerBinder(android::dvr::ShellViewBinderInterface& app)
      : app_(app) {}
  virtual ~VrWindowManagerBinder() {}

  // Must be called before clients can connect.
  // Returns 0 if initialization is successful.
  int Initialize();
  static char const* getServiceName() { return "vr_window_manager"; }

 protected:
  // Implements IVrWindowManagerBinder.
  ::android::binder::Status connectController(
      const ::android::base::unique_fd& fd) override;
  ::android::binder::Status disconnectController() override;
  ::android::binder::Status enterVrMode() override;
  ::android::binder::Status exitVrMode() override;
  ::android::binder::Status setDebugMode(int32_t mode) override;
  ::android::binder::Status set2DMode(int32_t mode) override;

  // Implements BBinder::dump().
  status_t dump(int fd, const Vector<String16>& args) override;

 private:
  android::dvr::ShellViewBinderInterface& app_;

  VrWindowManagerBinder(const VrWindowManagerBinder&) = delete;
  void operator=(const VrWindowManagerBinder&) = delete;
};

}  // namespace vr
}  // namespace service
}  // namespace android

#endif  // VR_WINDOW_MANAGER_VR_WINDOW_MANAGER_BINDER_H_
