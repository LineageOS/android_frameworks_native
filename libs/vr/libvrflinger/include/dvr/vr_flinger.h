#ifndef ANDROID_DVR_VR_FLINGER_H_
#define ANDROID_DVR_VR_FLINGER_H_

#include <thread>
#include <memory>

namespace android {

namespace Hwc2 {
class Composer;
}  // namespace Hwc2

namespace dvr {

class DisplayService;

class VrFlinger {
 public:
  VrFlinger();
  int Run(Hwc2::Composer* hidl);

  void EnterVrMode();
  void ExitVrMode();

 private:
  std::thread displayd_thread_;
  std::shared_ptr<android::dvr::DisplayService> display_service_;
};

} // namespace dvr
} // namespace android

#endif // ANDROID_DVR_VR_FLINGER_H_
