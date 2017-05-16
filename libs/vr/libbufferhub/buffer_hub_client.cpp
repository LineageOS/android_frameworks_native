#include <private/dvr/buffer_hub_client.h>

#include <log/log.h>
#include <poll.h>
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include <utils/Trace.h>

#include <mutex>

#include <pdx/default_transport/client_channel.h>
#include <pdx/default_transport/client_channel_factory.h>

#include "include/private/dvr/bufferhub_rpc.h"

using android::pdx::LocalHandle;
using android::pdx::LocalChannelHandle;
using android::pdx::rpc::WrapBuffer;
using android::pdx::Status;

namespace android {
namespace dvr {

BufferHubBuffer::BufferHubBuffer(LocalChannelHandle channel_handle)
    : Client{pdx::default_transport::ClientChannel::Create(
          std::move(channel_handle))},
      id_(-1) {}
BufferHubBuffer::BufferHubBuffer(const std::string& endpoint_path)
    : Client{pdx::default_transport::ClientChannelFactory::Create(
          endpoint_path)},
      id_(-1) {}

BufferHubBuffer::~BufferHubBuffer() {}

Status<LocalChannelHandle> BufferHubBuffer::CreateConsumer() {
  Status<LocalChannelHandle> status =
      InvokeRemoteMethod<BufferHubRPC::NewConsumer>();
  ALOGE_IF(!status,
           "BufferHub::CreateConsumer: Failed to create consumer channel: %s",
           status.GetErrorMessage().c_str());
  return status;
}

int BufferHubBuffer::ImportBuffer() {
  ATRACE_NAME("BufferHubBuffer::ImportBuffer");

  Status<NativeBufferHandle<LocalHandle>> status =
      InvokeRemoteMethod<BufferHubRPC::GetBuffer>();
  if (!status) {
    ALOGE("BufferHubBuffer::ImportBuffer: Failed to get buffer: %s",
          status.GetErrorMessage().c_str());
    return -status.error();
  } else if (status.get().id() < 0) {
    ALOGE("BufferHubBuffer::ImportBuffer: Received an invalid id!");
    return -EIO;
  }

  auto buffer_handle = status.take();

  // Stash the buffer id to replace the value in id_.
  const int new_id = buffer_handle.id();

  // Import the buffer.
  IonBuffer ion_buffer;
  ALOGD_IF(
      TRACE, "BufferHubBuffer::ImportBuffer: id=%d FdCount=%zu IntCount=%zu",
      buffer_handle.id(), buffer_handle.FdCount(), buffer_handle.IntCount());

  const int ret = buffer_handle.Import(&ion_buffer);
  if (ret < 0)
    return ret;

  // If the import succeeds, replace the previous buffer and id.
  buffer_ = std::move(ion_buffer);
  id_ = new_id;
  return 0;
}

int BufferHubBuffer::Poll(int timeout_ms) {
  ATRACE_NAME("BufferHubBuffer::Poll");
  pollfd p = {event_fd(), POLLIN, 0};
  return poll(&p, 1, timeout_ms);
}

int BufferHubBuffer::Lock(int usage, int x, int y, int width, int height,
                          void** address) {
  return buffer_.Lock(usage, x, y, width, height, address);
}

int BufferHubBuffer::Unlock() { return buffer_.Unlock(); }

int BufferHubBuffer::GetBlobReadWritePointer(size_t size, void** addr) {
  int width = static_cast<int>(size);
  int height = 1;
  int ret = Lock(usage(), 0, 0, width, height, addr);
  if (ret == 0)
    Unlock();
  return ret;
}

int BufferHubBuffer::GetBlobReadOnlyPointer(size_t size, void** addr) {
  return GetBlobReadWritePointer(size, addr);
}

void BufferHubBuffer::GetBlobFds(int* fds, size_t* fds_count,
                                 size_t max_fds_count) const {
  size_t numFds = static_cast<size_t>(native_handle()->numFds);
  *fds_count = std::min(max_fds_count, numFds);
  std::copy(native_handle()->data, native_handle()->data + *fds_count, fds);
}

BufferConsumer::BufferConsumer(LocalChannelHandle channel)
    : BASE(std::move(channel)) {
  const int ret = ImportBuffer();
  if (ret < 0) {
    ALOGE("BufferConsumer::BufferConsumer: Failed to import buffer: %s",
          strerror(-ret));
    Close(ret);
  }
}

std::unique_ptr<BufferConsumer> BufferConsumer::Import(
    LocalChannelHandle channel) {
  ATRACE_NAME("BufferConsumer::Import");
  ALOGD_IF(TRACE, "BufferConsumer::Import: channel=%d", channel.value());
  return BufferConsumer::Create(std::move(channel));
}

std::unique_ptr<BufferConsumer> BufferConsumer::Import(
    Status<LocalChannelHandle> status) {
  return Import(status ? status.take()
                       : LocalChannelHandle{nullptr, -status.error()});
}

int BufferConsumer::Acquire(LocalHandle* ready_fence) {
  return Acquire(ready_fence, nullptr, 0);
}

int BufferConsumer::Acquire(LocalHandle* ready_fence, void* meta,
                            size_t meta_size_bytes) {
  ATRACE_NAME("BufferConsumer::Acquire");
  LocalFence fence;
  auto return_value =
      std::make_pair(std::ref(fence), WrapBuffer(meta, meta_size_bytes));
  auto status = InvokeRemoteMethodInPlace<BufferHubRPC::ConsumerAcquire>(
      &return_value, meta_size_bytes);
  if (status && ready_fence)
    *ready_fence = fence.take();
  return status ? 0 : -status.error();
}

int BufferConsumer::Release(const LocalHandle& release_fence) {
  ATRACE_NAME("BufferConsumer::Release");
  return ReturnStatusOrError(InvokeRemoteMethod<BufferHubRPC::ConsumerRelease>(
      BorrowedFence(release_fence.Borrow())));
}

int BufferConsumer::ReleaseAsync() {
  ATRACE_NAME("BufferConsumer::ReleaseAsync");
  return ReturnStatusOrError(
      SendImpulse(BufferHubRPC::ConsumerRelease::Opcode));
}

int BufferConsumer::Discard() { return Release(LocalHandle()); }

int BufferConsumer::SetIgnore(bool ignore) {
  return ReturnStatusOrError(
      InvokeRemoteMethod<BufferHubRPC::ConsumerSetIgnore>(ignore));
}

BufferProducer::BufferProducer(uint32_t width, uint32_t height, uint32_t format,
                               uint32_t usage, size_t metadata_size)
    : BufferProducer(width, height, format, usage, usage, metadata_size) {}

BufferProducer::BufferProducer(uint32_t width, uint32_t height, uint32_t format,
                               uint64_t producer_usage, uint64_t consumer_usage,
                               size_t metadata_size)
    : BASE(BufferHubRPC::kClientPath) {
  ATRACE_NAME("BufferProducer::BufferProducer");
  ALOGD_IF(TRACE,
           "BufferProducer::BufferProducer: fd=%d width=%u height=%u format=%u "
           "producer_usage=%" PRIx64 " consumer_usage=%" PRIx64
           " metadata_size=%zu",
           event_fd(), width, height, format, producer_usage, consumer_usage,
           metadata_size);

  // (b/37881101) Deprecate producer/consumer usage
  auto status = InvokeRemoteMethod<BufferHubRPC::CreateBuffer>(
      width, height, format, (producer_usage | consumer_usage), metadata_size);
  if (!status) {
    ALOGE(
        "BufferProducer::BufferProducer: Failed to create producer buffer: %s",
        status.GetErrorMessage().c_str());
    Close(-status.error());
    return;
  }

  const int ret = ImportBuffer();
  if (ret < 0) {
    ALOGE(
        "BufferProducer::BufferProducer: Failed to import producer buffer: %s",
        strerror(-ret));
    Close(ret);
  }
}

BufferProducer::BufferProducer(const std::string& name, int user_id,
                               int group_id, uint32_t width, uint32_t height,
                               uint32_t format, uint32_t usage,
                               size_t meta_size_bytes)
    : BufferProducer(name, user_id, group_id, width, height, format, usage,
                     usage, meta_size_bytes) {}

BufferProducer::BufferProducer(const std::string& name, int user_id,
                               int group_id, uint32_t width, uint32_t height,
                               uint32_t format, uint64_t producer_usage,
                               uint64_t consumer_usage, size_t meta_size_bytes)
    : BASE(BufferHubRPC::kClientPath) {
  ATRACE_NAME("BufferProducer::BufferProducer");
  ALOGD_IF(TRACE,
           "BufferProducer::BufferProducer: fd=%d name=%s user_id=%d "
           "group_id=%d width=%u height=%u format=%u producer_usage=%" PRIx64
           " consumer_usage=%" PRIx64 " meta_size_bytes=%zu",
           event_fd(), name.c_str(), user_id, group_id, width, height, format,
           producer_usage, consumer_usage, meta_size_bytes);

  // (b/37881101) Deprecate producer/consumer usage
  auto status = InvokeRemoteMethod<BufferHubRPC::CreatePersistentBuffer>(
      name, user_id, group_id, width, height, format,
      (producer_usage | consumer_usage), meta_size_bytes);
  if (!status) {
    ALOGE(
        "BufferProducer::BufferProducer: Failed to create/get persistent "
        "buffer \"%s\": %s",
        name.c_str(), status.GetErrorMessage().c_str());
    Close(-status.error());
    return;
  }

  const int ret = ImportBuffer();
  if (ret < 0) {
    ALOGE(
        "BufferProducer::BufferProducer: Failed to import producer buffer "
        "\"%s\": %s",
        name.c_str(), strerror(-ret));
    Close(ret);
  }
}

BufferProducer::BufferProducer(uint32_t usage, size_t size)
    : BufferProducer(usage, usage, size) {}

BufferProducer::BufferProducer(uint64_t producer_usage, uint64_t consumer_usage,
                               size_t size)
    : BASE(BufferHubRPC::kClientPath) {
  ATRACE_NAME("BufferProducer::BufferProducer");
  ALOGD_IF(TRACE,
           "BufferProducer::BufferProducer: producer_usage=%" PRIx64
           " consumer_usage=%" PRIx64 " size=%zu",
           producer_usage, consumer_usage, size);
  const int width = static_cast<int>(size);
  const int height = 1;
  const int format = HAL_PIXEL_FORMAT_BLOB;
  const size_t meta_size_bytes = 0;

  // (b/37881101) Deprecate producer/consumer usage
  auto status = InvokeRemoteMethod<BufferHubRPC::CreateBuffer>(
      width, height, format, (producer_usage | consumer_usage),
      meta_size_bytes);
  if (!status) {
    ALOGE("BufferProducer::BufferProducer: Failed to create blob: %s",
          status.GetErrorMessage().c_str());
    Close(-status.error());
    return;
  }

  const int ret = ImportBuffer();
  if (ret < 0) {
    ALOGE(
        "BufferProducer::BufferProducer: Failed to import producer buffer: %s",
        strerror(-ret));
    Close(ret);
  }
}

BufferProducer::BufferProducer(const std::string& name, int user_id,
                               int group_id, uint32_t usage, size_t size)
    : BufferProducer(name, user_id, group_id, usage, usage, size) {}

BufferProducer::BufferProducer(const std::string& name, int user_id,
                               int group_id, uint64_t producer_usage,
                               uint64_t consumer_usage, size_t size)
    : BASE(BufferHubRPC::kClientPath) {
  ATRACE_NAME("BufferProducer::BufferProducer");
  ALOGD_IF(TRACE,
           "BufferProducer::BufferProducer: name=%s user_id=%d group=%d "
           "producer_usage=%" PRIx64 " consumer_usage=%" PRIx64 " size=%zu",
           name.c_str(), user_id, group_id, producer_usage, consumer_usage,
           size);
  const int width = static_cast<int>(size);
  const int height = 1;
  const int format = HAL_PIXEL_FORMAT_BLOB;
  const size_t meta_size_bytes = 0;

  // (b/37881101) Deprecate producer/consumer usage
  auto status = InvokeRemoteMethod<BufferHubRPC::CreatePersistentBuffer>(
      name, user_id, group_id, width, height, format,
      (producer_usage | consumer_usage), meta_size_bytes);
  if (!status) {
    ALOGE(
        "BufferProducer::BufferProducer: Failed to create persistent "
        "buffer \"%s\": %s",
        name.c_str(), status.GetErrorMessage().c_str());
    Close(-status.error());
    return;
  }

  const int ret = ImportBuffer();
  if (ret < 0) {
    ALOGE(
        "BufferProducer::BufferProducer: Failed to import producer buffer "
        "\"%s\": %s",
        name.c_str(), strerror(-ret));
    Close(ret);
  }
}

BufferProducer::BufferProducer(const std::string& name)
    : BASE(BufferHubRPC::kClientPath) {
  ATRACE_NAME("BufferProducer::BufferProducer");
  ALOGD_IF(TRACE, "BufferProducer::BufferProducer: name=%s", name.c_str());

  auto status = InvokeRemoteMethod<BufferHubRPC::GetPersistentBuffer>(name);
  if (!status) {
    ALOGE(
        "BufferProducer::BufferProducer: Failed to get producer buffer by name "
        "\"%s\": %s",
        name.c_str(), status.GetErrorMessage().c_str());
    Close(-status.error());
    return;
  }

  const int ret = ImportBuffer();
  if (ret < 0) {
    ALOGE(
        "BufferProducer::BufferProducer: Failed to import producer buffer "
        "\"%s\": %s",
        name.c_str(), strerror(-ret));
    Close(ret);
  }
}

BufferProducer::BufferProducer(LocalChannelHandle channel)
    : BASE(std::move(channel)) {
  const int ret = ImportBuffer();
  if (ret < 0) {
    ALOGE(
        "BufferProducer::BufferProducer: Failed to import producer buffer: %s",
        strerror(-ret));
    Close(ret);
  }
}

int BufferProducer::Post(const LocalHandle& ready_fence, const void* meta,
                         size_t meta_size_bytes) {
  ATRACE_NAME("BufferProducer::Post");
  return ReturnStatusOrError(InvokeRemoteMethod<BufferHubRPC::ProducerPost>(
      BorrowedFence(ready_fence.Borrow()), WrapBuffer(meta, meta_size_bytes)));
}

int BufferProducer::Gain(LocalHandle* release_fence) {
  ATRACE_NAME("BufferProducer::Gain");
  auto status = InvokeRemoteMethod<BufferHubRPC::ProducerGain>();
  if (!status)
    return -status.error();
  if (release_fence)
    *release_fence = status.take().take();
  return 0;
}

int BufferProducer::GainAsync() {
  ATRACE_NAME("BufferProducer::GainAsync");
  return ReturnStatusOrError(SendImpulse(BufferHubRPC::ProducerGain::Opcode));
}

std::unique_ptr<BufferProducer> BufferProducer::Import(
    LocalChannelHandle channel) {
  ALOGD_IF(TRACE, "BufferProducer::Import: channel=%d", channel.value());
  return BufferProducer::Create(std::move(channel));
}

std::unique_ptr<BufferProducer> BufferProducer::Import(
    Status<LocalChannelHandle> status) {
  return Import(status ? status.take()
                       : LocalChannelHandle{nullptr, -status.error()});
}

int BufferProducer::MakePersistent(const std::string& name, int user_id,
                                   int group_id) {
  ATRACE_NAME("BufferProducer::MakePersistent");
  return ReturnStatusOrError(
      InvokeRemoteMethod<BufferHubRPC::ProducerMakePersistent>(name, user_id,
                                                               group_id));
}

int BufferProducer::RemovePersistence() {
  ATRACE_NAME("BufferProducer::RemovePersistence");
  return ReturnStatusOrError(
      InvokeRemoteMethod<BufferHubRPC::ProducerRemovePersistence>());
}

}  // namespace dvr
}  // namespace android
