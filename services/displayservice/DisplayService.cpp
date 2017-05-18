#include <displayservice/DisplayService.h>
#include <displayservice/DisplayEventReceiver.h>

namespace android {
namespace frameworks {
namespace displayservice {
namespace V1_0 {
namespace implementation {

Return<sp<IDisplayEventReceiver>> DisplayService::getEventReceiver() {
    return new DisplayEventReceiver();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace displayservice
}  // namespace frameworks
}  // namespace android
