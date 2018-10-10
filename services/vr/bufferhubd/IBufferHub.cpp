#include <log/log.h>
#include <private/dvr/IBufferHub.h>

namespace android {
namespace dvr {

IMPLEMENT_META_INTERFACE(BufferHub, "android.dvr.IBufferHub");

status_t BnBufferHub::onTransact(uint32_t code, const Parcel& data,
                                 Parcel* reply, uint32_t flags) {
  switch (code) {
    default:
      // Should not reach
      ALOGE("onTransact(): unknown code %u received!", code);
      return BBinder::onTransact(code, data, reply, flags);
  }
}

}  // namespace dvr
}  // namespace android