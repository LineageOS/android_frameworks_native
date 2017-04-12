#include "include/private/dvr/display_client.h"

#include <cutils/native_handle.h>
#include <log/log.h>
#include <pdx/default_transport/client_channel.h>
#include <pdx/default_transport/client_channel_factory.h>
#include <pdx/status.h>

#include <mutex>

#include <private/dvr/display_rpc.h>
#include <private/dvr/late_latch.h>
#include <private/dvr/native_buffer.h>

using android::pdx::LocalHandle;
using android::pdx::LocalChannelHandle;
using android::pdx::Status;
using android::pdx::Transaction;
using android::pdx::rpc::IfAnyOf;

namespace android {
namespace dvr {

SurfaceClient::SurfaceClient(LocalChannelHandle channel_handle,
                             SurfaceType type)
    : Client{pdx::default_transport::ClientChannel::Create(
          std::move(channel_handle))},
      type_(type) {}

SurfaceClient::SurfaceClient(const std::string& endpoint_path, SurfaceType type)
    : Client{pdx::default_transport::ClientChannelFactory::Create(
                 endpoint_path),
             kInfiniteTimeout},
      type_(type) {}

int SurfaceClient::GetMetadataBufferFd(LocalHandle* out_fd) {
  auto buffer_producer = GetMetadataBuffer();
  if (!buffer_producer)
    return -ENOMEM;

  *out_fd = buffer_producer->GetBlobFd();
  return 0;
}

std::shared_ptr<BufferProducer> SurfaceClient::GetMetadataBuffer() {
  if (!metadata_buffer_) {
    auto status = InvokeRemoteMethod<DisplayRPC::GetMetadataBuffer>();
    if (!status) {
      ALOGE(
          "SurfaceClient::AllocateMetadataBuffer: Failed to allocate buffer: "
          "%s",
          status.GetErrorMessage().c_str());
      return nullptr;
    }

    metadata_buffer_ = BufferProducer::Import(status.take());
  }

  return metadata_buffer_;
}

DisplaySurfaceClient::DisplaySurfaceClient(int width, int height, int format,
                                           int usage, int flags)
    : BASE(DisplayRPC::kClientPath, SurfaceTypeEnum::Normal),
      width_(width),
      height_(height),
      format_(format),
      usage_(usage),
      flags_(flags),
      z_order_(0),
      visible_(true),
      exclude_from_blur_(false),
      blur_behind_(true),
      mapped_metadata_buffer_(nullptr) {
  auto status = InvokeRemoteMethod<DisplayRPC::CreateSurface>(
      width, height, format, usage, flags);
  if (!status) {
    ALOGE(
        "DisplaySurfaceClient::DisplaySurfaceClient: Failed to create display "
        "surface: %s",
        status.GetErrorMessage().c_str());
    Close(status.error());
  }
}

void DisplaySurfaceClient::SetVisible(bool visible) {
  SetAttributes({{DisplaySurfaceAttributeEnum::Visible,
                  DisplaySurfaceAttributeValue{visible}}});
}

void DisplaySurfaceClient::SetZOrder(int z_order) {
  SetAttributes({{DisplaySurfaceAttributeEnum::ZOrder,
                  DisplaySurfaceAttributeValue{z_order}}});
}

void DisplaySurfaceClient::SetExcludeFromBlur(bool exclude_from_blur) {
  SetAttributes({{DisplaySurfaceAttributeEnum::ExcludeFromBlur,
                  DisplaySurfaceAttributeValue{exclude_from_blur}}});
}

void DisplaySurfaceClient::SetBlurBehind(bool blur_behind) {
  SetAttributes({{DisplaySurfaceAttributeEnum::BlurBehind,
                  DisplaySurfaceAttributeValue{blur_behind}}});
}

void DisplaySurfaceClient::SetAttributes(
    const DisplaySurfaceAttributes& attributes) {
  Status<int> status =
      InvokeRemoteMethod<DisplayRPC::SetAttributes>(attributes);
  if (!status) {
    ALOGE(
        "DisplaySurfaceClient::SetAttributes: Failed to set display surface "
        "attributes: %s",
        status.GetErrorMessage().c_str());
    return;
  }

  // Set the local cached copies of the attributes we care about from the full
  // set of attributes sent to the display service.
  for (const auto& attribute : attributes) {
    const auto& key = attribute.first;
    const auto* variant = &attribute.second;
    bool invalid_value = false;
    switch (key) {
      case DisplaySurfaceAttributeEnum::Visible:
        invalid_value =
            !IfAnyOf<int32_t, int64_t, bool>::Get(variant, &visible_);
        break;
      case DisplaySurfaceAttributeEnum::ZOrder:
        invalid_value = !IfAnyOf<int32_t>::Get(variant, &z_order_);
        break;
      case DisplaySurfaceAttributeEnum::ExcludeFromBlur:
        invalid_value =
            !IfAnyOf<int32_t, int64_t, bool>::Get(variant, &exclude_from_blur_);
        break;
      case DisplaySurfaceAttributeEnum::BlurBehind:
        invalid_value =
            !IfAnyOf<int32_t, int64_t, bool>::Get(variant, &blur_behind_);
        break;
    }

    if (invalid_value) {
      ALOGW(
          "DisplaySurfaceClient::SetAttributes: Failed to set display "
          "surface attribute '%s' because of incompatible type: %d",
          DisplaySurfaceAttributeEnum::ToString(key).c_str(), variant->index());
    }
  }
}

std::shared_ptr<ProducerQueue> DisplaySurfaceClient::GetProducerQueue() {
  if (producer_queue_ == nullptr) {
    // Create producer queue through DisplayRPC
    auto status = InvokeRemoteMethod<DisplayRPC::CreateBufferQueue>();
    if (!status) {
      ALOGE(
          "DisplaySurfaceClient::GetProducerQueue: failed to create producer "
          "queue: %s",
          status.GetErrorMessage().c_str());
      return nullptr;
    }

    producer_queue_ = ProducerQueue::Import(status.take());
  }
  return producer_queue_;
}

volatile DisplaySurfaceMetadata* DisplaySurfaceClient::GetMetadataBufferPtr() {
  if (!mapped_metadata_buffer_) {
    if (auto buffer_producer = GetMetadataBuffer()) {
      void* addr = nullptr;
      const int ret = buffer_producer->GetBlobReadWritePointer(
          sizeof(DisplaySurfaceMetadata), &addr);
      if (ret < 0) {
        ALOGE(
            "DisplaySurfaceClient::GetMetadataBufferPtr: Failed to map surface "
            "metadata: %s",
            strerror(-ret));
        return nullptr;
      }
      mapped_metadata_buffer_ = static_cast<DisplaySurfaceMetadata*>(addr);
    }
  }

  return mapped_metadata_buffer_;
}

LocalChannelHandle DisplaySurfaceClient::CreateVideoMeshSurface() {
  auto status = InvokeRemoteMethod<DisplayRPC::CreateVideoMeshSurface>();
  if (!status) {
    ALOGE(
        "DisplaySurfaceClient::CreateVideoMeshSurface: Failed to create "
        "video mesh surface: %s",
        status.GetErrorMessage().c_str());
  }
  return status.take();
}

DisplayClient::DisplayClient(int* error)
    : BASE(pdx::default_transport::ClientChannelFactory::Create(
               DisplayRPC::kClientPath),
           kInfiniteTimeout) {
  if (error)
    *error = Client::error();
}

int DisplayClient::GetDisplayMetrics(SystemDisplayMetrics* metrics) {
  auto status = InvokeRemoteMethod<DisplayRPC::GetMetrics>();
  if (!status) {
    ALOGE("DisplayClient::GetDisplayMetrics: Failed to get metrics: %s",
          status.GetErrorMessage().c_str());
    return -status.error();
  }

  *metrics = status.get();
  return 0;
}

pdx::Status<void> DisplayClient::SetViewerParams(
    const ViewerParams& viewer_params) {
  auto status = InvokeRemoteMethod<DisplayRPC::SetViewerParams>(viewer_params);
  if (!status) {
    ALOGE("DisplayClient::SetViewerParams: Failed to set viewer params: %s",
          status.GetErrorMessage().c_str());
  }
  return status;
}

int DisplayClient::GetLastFrameEdsTransform(LateLatchOutput* ll_out) {
  auto status = InvokeRemoteMethod<DisplayRPC::GetEdsCapture>();
  if (!status) {
    ALOGE(
        "DisplayClient::GetLastFrameLateLatch: Failed to get most recent late"
        " latch: %s",
        status.GetErrorMessage().c_str());
    return -status.error();
  }

  if (status.get().size() != sizeof(LateLatchOutput)) {
    ALOGE(
        "DisplayClient::GetLastFrameLateLatch: Error expected to receive %zu "
        "bytes but received %zu",
        sizeof(LateLatchOutput), status.get().size());
    return -EIO;
  }

  *ll_out = *reinterpret_cast<const LateLatchOutput*>(status.get().data());
  return 0;
}

std::unique_ptr<DisplaySurfaceClient> DisplayClient::CreateDisplaySurface(
    int width, int height, int format, int usage, int flags) {
  return DisplaySurfaceClient::Create(width, height, format, usage, flags);
}

std::unique_ptr<IonBuffer> DisplayClient::GetNamedBuffer(
    const std::string& name) {
  auto status = InvokeRemoteMethod<DisplayRPC::GetNamedBuffer>(name);
  if (!status) {
    ALOGE(
        "DisplayClient::GetNamedBuffer: Failed to get pose buffer. name=%s, "
        "error=%s",
        name.c_str(), status.GetErrorMessage().c_str());
    return nullptr;
  }

  auto ion_buffer = std::make_unique<IonBuffer>();
  status.take().Import(ion_buffer.get());
  return ion_buffer;
}

bool DisplayClient::IsVrAppRunning() {
  auto status = InvokeRemoteMethod<DisplayRPC::IsVrAppRunning>();
  if (!status)
    return 0;
  return static_cast<bool>(status.get());
}

}  // namespace dvr
}  // namespace android
