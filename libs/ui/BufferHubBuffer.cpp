/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// We would eliminate the clang warnings introduced by libdpx.
// TODO(b/112338294): Remove those once BufferHub moved to use Binder
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wdouble-promotion"
#pragma clang diagnostic ignored "-Wgnu-case-range"
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#pragma clang diagnostic ignored "-Winconsistent-missing-destructor-override"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wpacked"
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wswitch-enum"
#pragma clang diagnostic ignored "-Wundefined-func-template"
#pragma clang diagnostic ignored "-Wunused-template"
#pragma clang diagnostic ignored "-Wweak-vtables"
#include <pdx/default_transport/client_channel.h>
#include <pdx/default_transport/client_channel_factory.h>
#include <pdx/file_handle.h>
#include <private/dvr/bufferhub_rpc.h>
#pragma clang diagnostic pop

#include <ui/BufferHubBuffer.h>
#include <ui/DetachedBufferHandle.h>

#include <poll.h>

using android::dvr::BufferHubMetadata;
using android::dvr::BufferTraits;
using android::dvr::DetachedBufferRPC;
using android::dvr::NativeHandleWrapper;
using android::pdx::LocalChannelHandle;
using android::pdx::LocalHandle;
using android::pdx::Status;
using android::pdx::default_transport::ClientChannel;
using android::pdx::default_transport::ClientChannelFactory;

namespace android {

namespace {

// TODO(b/112338294): Remove this string literal after refactoring BufferHub
// to use Binder.
static constexpr char kBufferHubClientPath[] = "system/buffer_hub/client";

}  // namespace

BufferHubClient::BufferHubClient()
    : Client(ClientChannelFactory::Create(kBufferHubClientPath)) {}

BufferHubClient::BufferHubClient(LocalChannelHandle channel_handle)
    : Client(ClientChannel::Create(std::move(channel_handle))) {}

BufferHubClient::~BufferHubClient() {}

bool BufferHubClient::IsValid() const {
  return IsConnected() && GetChannelHandle().valid();
}

LocalChannelHandle BufferHubClient::TakeChannelHandle() {
  if (IsConnected()) {
    return std::move(GetChannelHandle());
  } else {
    return {};
  }
}

DetachedBuffer::DetachedBuffer(uint32_t width, uint32_t height,
                               uint32_t layer_count, uint32_t format,
                               uint64_t usage, size_t user_metadata_size) {
  ATRACE_NAME("DetachedBuffer::DetachedBuffer");
  ALOGD("DetachedBuffer::DetachedBuffer: width=%u height=%u layer_count=%u, format=%u "
        "usage=%" PRIx64 " user_metadata_size=%zu",
        width, height, layer_count, format, usage, user_metadata_size);

  auto status = client_.InvokeRemoteMethod<DetachedBufferRPC::Create>(
      width, height, layer_count, format, usage, user_metadata_size);
  if (!status) {
    ALOGE(
        "DetachedBuffer::DetachedBuffer: Failed to create detached buffer: %s",
        status.GetErrorMessage().c_str());
    client_.Close(-status.error());
  }

  const int ret = ImportGraphicBuffer();
  if (ret < 0) {
    ALOGE("DetachedBuffer::DetachedBuffer: Failed to import buffer: %s",
          strerror(-ret));
    client_.Close(ret);
  }
}

DetachedBuffer::DetachedBuffer(LocalChannelHandle channel_handle)
    : client_(std::move(channel_handle)) {
  const int ret = ImportGraphicBuffer();
  if (ret < 0) {
    ALOGE("DetachedBuffer::DetachedBuffer: Failed to import buffer: %s",
          strerror(-ret));
    client_.Close(ret);
  }
}

int DetachedBuffer::ImportGraphicBuffer() {
  ATRACE_NAME("DetachedBuffer::ImportGraphicBuffer");

  auto status = client_.InvokeRemoteMethod<DetachedBufferRPC::Import>();
  if (!status) {
    ALOGE("DetachedBuffer::DetachedBuffer: Failed to import GraphicBuffer: %s",
          status.GetErrorMessage().c_str());
    return -status.error();
  }

  BufferTraits<LocalHandle> buffer_traits = status.take();
  if (buffer_traits.id() < 0) {
    ALOGE("DetachedBuffer::DetachedBuffer: Received an invalid id!");
    return -EIO;
  }

  // Stash the buffer id to replace the value in id_.
  const int buffer_id = buffer_traits.id();

  // Import the metadata.
  metadata_ = BufferHubMetadata::Import(buffer_traits.take_metadata_handle());

  if (!metadata_.IsValid()) {
    ALOGE("DetachedBuffer::ImportGraphicBuffer: invalid metadata.");
    return -ENOMEM;
  }

  if (metadata_.metadata_size() != buffer_traits.metadata_size()) {
    ALOGE(
        "DetachedBuffer::ImportGraphicBuffer: metadata buffer too small: "
        "%zu, expected: %" PRIu64 ".",
        metadata_.metadata_size(), buffer_traits.metadata_size());
    return -ENOMEM;
  }

  size_t metadata_buf_size = static_cast<size_t>(buffer_traits.metadata_size());
  if (metadata_buf_size < dvr::BufferHubDefs::kMetadataHeaderSize) {
    ALOGE("DetachedBuffer::ImportGraphicBuffer: metadata too small: %zu",
          metadata_buf_size);
    return -EINVAL;
  }

  // Import the buffer: We only need to hold on the native_handle_t here so that
  // GraphicBuffer instance can be created in future.
  buffer_handle_ = buffer_traits.take_buffer_handle();

  // If all imports succeed, replace the previous buffer and id.
  id_ = buffer_id;
  buffer_state_bit_ = buffer_traits.buffer_state_bit();

  // TODO(b/112012161) Set up shared fences.
  ALOGD("DetachedBuffer::ImportGraphicBuffer: id=%d, buffer_state=%" PRIx64 ".", id(),
        metadata_.metadata_header()->buffer_state.load(std::memory_order_acquire));
  return 0;
}

int DetachedBuffer::Poll(int timeout_ms) {
  ATRACE_NAME("DetachedBuffer::Poll");
  pollfd p = {client_.event_fd(), POLLIN, 0};
  return poll(&p, 1, timeout_ms);
}

Status<LocalChannelHandle> DetachedBuffer::Promote() {
  // TODO(b/112338294) remove after migrate producer buffer to binder
  ALOGW("DetachedBuffer::Promote: not supported operation during migration");
  return {};

  ATRACE_NAME("DetachedBuffer::Promote");
  ALOGD("DetachedBuffer::Promote: id=%d.", id_);

  auto status_or_handle =
      client_.InvokeRemoteMethod<DetachedBufferRPC::Promote>();
  if (status_or_handle.ok()) {
    // Invalidate the buffer.
    buffer_handle_ = {};
  } else {
    ALOGE("DetachedBuffer::Promote: Failed to promote buffer (id=%d): %s.", id_,
          status_or_handle.GetErrorMessage().c_str());
  }
  return status_or_handle;
}

Status<LocalChannelHandle> DetachedBuffer::Duplicate() {
  ATRACE_NAME("DetachedBuffer::Duplicate");
  ALOGD("DetachedBuffer::Duplicate: id=%d.", id_);

  auto status_or_handle =
      client_.InvokeRemoteMethod<DetachedBufferRPC::Duplicate>();

  if (!status_or_handle.ok()) {
    ALOGE("DetachedBuffer::Duplicate: Failed to duplicate buffer (id=%d): %s.",
          id_, status_or_handle.GetErrorMessage().c_str());
  }
  return status_or_handle;
}

}  // namespace android
