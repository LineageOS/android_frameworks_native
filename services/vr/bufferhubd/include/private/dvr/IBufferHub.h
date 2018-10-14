#ifndef ANDROID_DVR_IBUFFERHUB_H
#define ANDROID_DVR_IBUFFERHUB_H

#include <binder/IInterface.h>
#include <binder/Parcel.h>

namespace android {
namespace dvr {

class IBufferHub : public IInterface {
 public:
  DECLARE_META_INTERFACE(BufferHub);
};

class BnBufferHub : public BnInterface<IBufferHub> {
 public:
  virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                              uint32_t flags = 0);
};

class BpBufferHub : public BpInterface<IBufferHub> {
 public:
  explicit BpBufferHub(const sp<IBinder>& impl)
      : BpInterface<IBufferHub>(impl) {}
};

}  // namespace dvr
}  // namespace android

#endif