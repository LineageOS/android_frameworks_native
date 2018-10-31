#ifndef ANDROID_DVR_IBUFFERCLIENT_H
#define ANDROID_DVR_IBUFFERCLIENT_H

#include <binder/IInterface.h>
#include <binder/Parcel.h>

namespace android {
namespace dvr {

// Interface for acessing BufferHubBuffer remotely.
class IBufferClient : public IInterface {
 public:
  DECLARE_META_INTERFACE(BufferClient);

  // Checks if the buffer node is valid.
  virtual bool isValid() = 0;

  // Duplicates the client. Token_out will be set to a new token when succeed,
  // and not changed when failed.
  virtual status_t duplicate(uint64_t* outToken) = 0;
};

// BnInterface for IBufferClient. Should only be created in bufferhub service.
class BnBufferClient : public BnInterface<IBufferClient> {
 public:
  virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                              uint32_t flags = 0);
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_IBUFFERCLIENT_H