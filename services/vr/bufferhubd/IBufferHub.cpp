#include <log/log.h>
#include <private/dvr/IBufferHub.h>

namespace android {
namespace dvr {

class BpBufferHub : public BpInterface<IBufferHub> {
 public:
  explicit BpBufferHub(const sp<IBinder>& impl)
      : BpInterface<IBufferHub>(impl) {}

  sp<IBufferClient> createBuffer(uint32_t width, uint32_t height,
                                 uint32_t layer_count, uint32_t format,
                                 uint64_t usage,
                                 uint64_t user_metadata_size) override;

  status_t importBuffer(uint64_t token, sp<IBufferClient>* outClient) override;
};

IMPLEMENT_META_INTERFACE(BufferHub, "android.dvr.IBufferHub");

// Transaction code
enum {
  CREATE_BUFFER = IBinder::FIRST_CALL_TRANSACTION,
  IMPORT_BUFFER,
};

sp<IBufferClient> BpBufferHub::createBuffer(uint32_t width, uint32_t height,
                                            uint32_t layer_count,
                                            uint32_t format, uint64_t usage,
                                            uint64_t user_metadata_size) {
  Parcel data, reply;
  status_t ret = NO_ERROR;
  ret |= data.writeInterfaceToken(IBufferHub::getInterfaceDescriptor());
  ret |= data.writeUint32(width);
  ret |= data.writeUint32(height);
  ret |= data.writeUint32(layer_count);
  ret |= data.writeUint32(format);
  ret |= data.writeUint64(usage);
  ret |= data.writeUint64(user_metadata_size);

  if (ret != NO_ERROR) {
    ALOGE("BpBufferHub::createBuffer: failed to write into parcel");
    return nullptr;
  }

  ret = remote()->transact(CREATE_BUFFER, data, &reply);
  if (ret == NO_ERROR) {
    return interface_cast<IBufferClient>(reply.readStrongBinder());
  } else {
    ALOGE("BpBufferHub::createBuffer: failed to transact; errno=%d", ret);
    return nullptr;
  }
}

status_t BpBufferHub::importBuffer(uint64_t token,
                                   sp<IBufferClient>* outClient) {
  Parcel data, reply;
  status_t ret = NO_ERROR;
  ret |= data.writeInterfaceToken(IBufferHub::getInterfaceDescriptor());
  ret |= data.writeUint64(token);
  if (ret != NO_ERROR) {
    ALOGE("BpBufferHub::importBuffer: failed to write into parcel");
    return ret;
  }

  ret = remote()->transact(IMPORT_BUFFER, data, &reply);
  if (ret == NO_ERROR) {
    *outClient = interface_cast<IBufferClient>(reply.readStrongBinder());
    return NO_ERROR;
  } else {
    ALOGE("BpBufferHub::importBuffer: failed to transact; errno=%d", ret);
    return ret;
  }
}

status_t BnBufferHub::onTransact(uint32_t code, const Parcel& data,
                                 Parcel* reply, uint32_t flags) {
  switch (code) {
    case CREATE_BUFFER: {
      CHECK_INTERFACE(IBufferHub, data, reply);
      uint32_t width = data.readUint32();
      uint32_t height = data.readUint32();
      uint32_t layer_count = data.readUint32();
      uint32_t format = data.readUint32();
      uint64_t usage = data.readUint64();
      uint64_t user_metadata_size = data.readUint64();
      sp<IBufferClient> ret = createBuffer(width, height, layer_count, format,
                                           usage, user_metadata_size);
      return reply->writeStrongBinder(IInterface::asBinder(ret));
    }
    case IMPORT_BUFFER: {
      CHECK_INTERFACE(IBufferHub, data, reply);
      uint64_t token = data.readUint64();
      sp<IBufferClient> client;
      status_t ret = importBuffer(token, &client);
      if (ret == NO_ERROR) {
        return reply->writeStrongBinder(IInterface::asBinder(client));
      } else {
        return ret;
      }
    }
    default:
      // Should not reach except binder defined transactions such as dumpsys
      return BBinder::onTransact(code, data, reply, flags);
  }
}

}  // namespace dvr
}  // namespace android