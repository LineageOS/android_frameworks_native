#ifndef ANDROID_DVR_IBUFFERHUB_H
#define ANDROID_DVR_IBUFFERHUB_H

#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <private/dvr/IBufferClient.h>

namespace android {
namespace dvr {

class IBufferHub : public IInterface {
 public:
  DECLARE_META_INTERFACE(BufferHub);

  static const char* getServiceName() { return "bufferhubd"; }
  virtual sp<IBufferClient> createBuffer(uint32_t width, uint32_t height,
                                         uint32_t layer_count, uint32_t format,
                                         uint64_t usage,
                                         uint64_t user_metadata_size) = 0;

  virtual status_t importBuffer(uint64_t token,
                                sp<IBufferClient>* outClient) = 0;
};

class BnBufferHub : public BnInterface<IBufferHub> {
 public:
  virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                              uint32_t flags = 0);
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_IBUFFERHUB_H