#ifndef ANDROID_FRAMEWORKS_DISPLAYSERVICE_V1_0_DISPLAYEVENTRECEIVER_H
#define ANDROID_FRAMEWORKS_DISPLAYSERVICE_V1_0_DISPLAYEVENTRECEIVER_H

#include <android/frameworks/displayservice/1.0/IDisplayEventReceiver.h>
#include <gui/DisplayEventReceiver.h>
#include <hidl/Status.h>
#include <gui/DisplayEventReceiver.h>
#include <utils/Looper.h>

#include <mutex>

namespace android {
namespace frameworks {
namespace displayservice {
namespace V1_0 {
namespace implementation {

using ::android::hardware::Return;
using ::android::hardware::Void;

class DisplayEventReceiver : public IDisplayEventReceiver {
public:
    Return<Status> init(const sp<IEventCallback>& callback) override;
    Return<Status> setVsyncRate(int32_t count) override;
    Return<Status> requestNextVsync() override;
    Return<Status> close() override;

private:
    using FwkReceiver = ::android::DisplayEventReceiver;

    struct AttachedEvent : LooperCallback {
        AttachedEvent(const sp<IEventCallback> &callback);
        ~AttachedEvent();

        bool detach();
        bool valid() const;
        FwkReceiver &receiver();
        virtual int handleEvent(int fd, int events, void* /* data */) override;

    private:
        FwkReceiver mFwkReceiver;
        sp<IEventCallback> mCallback;
        bool mLooperAttached;
    };

    sp<AttachedEvent> mAttached;
    std::mutex mMutex;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace displayservice
}  // namespace frameworks
}  // namespace android

#endif  // ANDROID_FRAMEWORKS_DISPLAYSERVICE_V1_0_DISPLAYEVENTRECEIVER_H
