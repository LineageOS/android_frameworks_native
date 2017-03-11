#ifndef ANDROID_DVR_SENSORD_EXTENSION_H_
#define ANDROID_DVR_SENSORD_EXTENSION_H_

namespace android {
namespace dvr {

// Allows sensord to be extended with additional code.
class SensordExtension {
 public:
  static void run();
};

} // namespace dvr
} // namespace android

#endif // ANDROID_DVR_SENSORD_EXTENSION_H_
