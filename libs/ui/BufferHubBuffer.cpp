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

#include <poll.h>

using android::dvr::BufferTraits;
using android::dvr::DetachedBufferRPC;
using android::dvr::NativeHandleWrapper;

// TODO(b/112338294): Remove PDX dependencies from libui.
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

} // namespace

BufferHubClient::BufferHubClient() : Client(ClientChannelFactory::Create(kBufferHubClientPath)) {}

BufferHubClient::BufferHubClient(LocalChannelHandle mChannelHandle)
      : Client(ClientChannel::Create(std::move(mChannelHandle))) {}

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

BufferHubBuffer::BufferHubBuffer(uint32_t width, uint32_t height, uint32_t layerCount,
                                 uint32_t format, uint64_t usage, size_t mUserMetadataSize) {
    ATRACE_CALL();
    ALOGD("BufferHubBuffer::BufferHubBuffer: width=%u height=%u layerCount=%u, format=%u "
          "usage=%" PRIx64 " mUserMetadataSize=%zu",
          width, height, layerCount, format, usage, mUserMetadataSize);

    auto status =
            mClient.InvokeRemoteMethod<DetachedBufferRPC::Create>(width, height, layerCount, format,
                                                                  usage, mUserMetadataSize);
    if (!status) {
        ALOGE("BufferHubBuffer::BufferHubBuffer: Failed to create detached buffer: %s",
              status.GetErrorMessage().c_str());
        mClient.Close(-status.error());
    }

    const int ret = ImportGraphicBuffer();
    if (ret < 0) {
        ALOGE("BufferHubBuffer::BufferHubBuffer: Failed to import buffer: %s", strerror(-ret));
        mClient.Close(ret);
    }
}

BufferHubBuffer::BufferHubBuffer(LocalChannelHandle mChannelHandle)
      : mClient(std::move(mChannelHandle)) {
    const int ret = ImportGraphicBuffer();
    if (ret < 0) {
        ALOGE("BufferHubBuffer::BufferHubBuffer: Failed to import buffer: %s", strerror(-ret));
        mClient.Close(ret);
    }
}

int BufferHubBuffer::ImportGraphicBuffer() {
    ATRACE_CALL();

    auto status = mClient.InvokeRemoteMethod<DetachedBufferRPC::Import>();
    if (!status) {
        ALOGE("BufferHubBuffer::BufferHubBuffer: Failed to import GraphicBuffer: %s",
              status.GetErrorMessage().c_str());
        return -status.error();
    }

    BufferTraits<LocalHandle> bufferTraits = status.take();
    if (bufferTraits.id() < 0) {
        ALOGE("BufferHubBuffer::BufferHubBuffer: Received an invalid id!");
        return -EIO;
    }

    // Stash the buffer id to replace the value in mId.
    const int bufferId = bufferTraits.id();

    // Import the metadata.
    mMetadata = BufferHubMetadata::Import(bufferTraits.take_metadata_handle());

    if (!mMetadata.IsValid()) {
        ALOGE("BufferHubBuffer::ImportGraphicBuffer: invalid metadata.");
        return -ENOMEM;
    }

    if (mMetadata.metadata_size() != bufferTraits.metadata_size()) {
        ALOGE("BufferHubBuffer::ImportGraphicBuffer: metadata buffer too small: "
              "%zu, expected: %" PRIu64 ".",
              mMetadata.metadata_size(), bufferTraits.metadata_size());
        return -ENOMEM;
    }

    size_t metadataSize = static_cast<size_t>(bufferTraits.metadata_size());
    if (metadataSize < dvr::BufferHubDefs::kMetadataHeaderSize) {
        ALOGE("BufferHubBuffer::ImportGraphicBuffer: metadata too small: %zu", metadataSize);
        return -EINVAL;
    }

    // Import the buffer: We only need to hold on the native_handle_t here so that
    // GraphicBuffer instance can be created in future.
    mBufferHandle = bufferTraits.take_buffer_handle();

    // If all imports succeed, replace the previous buffer and id.
    mId = bufferId;
    mClientStateMask = bufferTraits.client_state_mask();

    // TODO(b/112012161) Set up shared fences.
    ALOGD("BufferHubBuffer::ImportGraphicBuffer: id=%d, buffer_state=%" PRIx64 ".", id(),
          mMetadata.metadata_header()->buffer_state.load(std::memory_order_acquire));
    return 0;
}

int BufferHubBuffer::Poll(int timeoutMs) {
    ATRACE_CALL();

    pollfd p = {mClient.event_fd(), POLLIN, 0};
    return poll(&p, 1, timeoutMs);
}

Status<LocalChannelHandle> BufferHubBuffer::Duplicate() {
    ATRACE_CALL();
    ALOGD("BufferHubBuffer::Duplicate: id=%d.", mId);

    auto statusOrHandle = mClient.InvokeRemoteMethod<DetachedBufferRPC::Duplicate>();

    if (!statusOrHandle.ok()) {
        ALOGE("BufferHubBuffer::Duplicate: Failed to duplicate buffer (id=%d): %s.", mId,
              statusOrHandle.GetErrorMessage().c_str());
    }
    return statusOrHandle;
}

} // namespace android
