#ifndef VR_WINDOW_MANAGER_CONTROLLER_DATA_PROVIDER_H_
#define VR_WINDOW_MANAGER_CONTROLLER_DATA_PROVIDER_H_

namespace android {
namespace dvr {

class ControllerDataProvider {
 public:
  virtual ~ControllerDataProvider() {}
  // Returns data pointer or nullptr. If pointer is valid, call to
  // UnlockControllerData is required.
  virtual const void* LockControllerData() = 0;
  virtual void UnlockControllerData() = 0;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_CONTROLLER_DATA_PROVIDER_H_