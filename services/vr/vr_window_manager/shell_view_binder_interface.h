#ifndef VR_WINDOW_MANAGER_SHELL_VIEWBINDER_INTERFACE_H_
#define VR_WINDOW_MANAGER_SHELL_VIEWBINDER_INTERFACE_H_

namespace android {
namespace dvr {

class ShellViewBinderInterface {
 public:
  ShellViewBinderInterface() {};
  virtual ~ShellViewBinderInterface() {};

  virtual void EnableDebug(bool debug) = 0;
  virtual void VrMode(bool mode) = 0;
  virtual void dumpInternal(String8& result) = 0;
  virtual void Set2DMode(bool mode) = 0;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_SHELL_VIEWBINDER_INTERFACE_H_
