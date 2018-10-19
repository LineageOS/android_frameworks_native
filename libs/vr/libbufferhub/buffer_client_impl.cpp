#include <log/log.h>
#include <private/dvr/IBufferClient.h>

namespace android {
namespace dvr {

class BpBufferClient : public BpInterface<IBufferClient> {
 public:
  explicit BpBufferClient(const sp<IBinder>& impl)
      : BpInterface<IBufferClient>(impl) {}

  bool isValid() override;

  status_t duplicate(uint64_t* outToken) override;
};

IMPLEMENT_META_INTERFACE(BufferClient, "android.dvr.IBufferClient");

// Transaction code
enum {
  IS_VALID = IBinder::FIRST_CALL_TRANSACTION,
  DUPLICATE,
};

bool BpBufferClient::isValid() {
  Parcel data, reply;
  status_t ret =
      data.writeInterfaceToken(IBufferClient::getInterfaceDescriptor());
  if (ret != NO_ERROR) {
    ALOGE("BpBufferClient::isValid: failed to write into parcel; errno=%d",
          ret);
    return false;
  }

  ret = remote()->transact(IS_VALID, data, &reply);
  if (ret == NO_ERROR) {
    return reply.readBool();
  } else {
    ALOGE("BpBufferClient::isValid: failed to transact; errno=%d", ret);
    return false;
  }
}

status_t BpBufferClient::duplicate(uint64_t* outToken) {
  Parcel data, reply;
  status_t ret =
      data.writeInterfaceToken(IBufferClient::getInterfaceDescriptor());
  if (ret != NO_ERROR) {
    ALOGE("BpBufferClient::duplicate: failed to write into parcel; errno=%d",
          ret);
    return ret;
  }

  ret = remote()->transact(DUPLICATE, data, &reply);
  if (ret == NO_ERROR) {
    *outToken = reply.readUint64();
    return NO_ERROR;
  } else {
    ALOGE("BpBufferClient::duplicate: failed to transact; errno=%d", ret);
    return ret;
  }
}

status_t BnBufferClient::onTransact(uint32_t code, const Parcel& data,
                                    Parcel* reply, uint32_t flags) {
  switch (code) {
    case IS_VALID: {
      CHECK_INTERFACE(IBufferClient, data, reply);
      return reply->writeBool(isValid());
    }
    case DUPLICATE: {
      CHECK_INTERFACE(IBufferClient, data, reply);
      uint64_t token = 0;
      status_t ret = duplicate(&token);
      if (ret != NO_ERROR) {
        return ret;
      }
      return reply->writeUint64(token);
    }
    default:
      // Should not reach except binder defined transactions such as dumpsys
      return BBinder::onTransact(code, data, reply, flags);
  }
}

}  // namespace dvr
}  // namespace android