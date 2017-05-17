#ifndef ANDROID_FRAMEWORKS_DISPLAYSERVICE_V1_0_DISPLAYSERVICE_H
#define ANDROID_FRAMEWORKS_DISPLAYSERVICE_V1_0_DISPLAYSERVICE_H

#include <android/frameworks/displayservice/1.0/IDisplayService.h>
#include <hidl/Status.h>

namespace android {
namespace frameworks {
namespace displayservice {
namespace V1_0 {
namespace implementation {

using ::android::hardware::Return;
using ::android::hardware::Void;

struct DisplayService : public IDisplayService {
    Return<sp<IDisplayEventReceiver>> getEventReceiver() override;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace displayservice
}  // namespace frameworks
}  // namespace android

#endif  // ANDROID_FRAMEWORKS_DISPLAYSERVICE_V1_0_DISPLAYSERVICE_H
