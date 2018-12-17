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

#include <poll.h>

#include <android-base/unique_fd.h>
#include <ui/BufferHubBuffer.h>
#include <ui/BufferHubDefs.h>

using android::base::unique_fd;
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

using BufferHubDefs::AnyClientAcquired;
using BufferHubDefs::AnyClientGained;
using BufferHubDefs::AnyClientPosted;
using BufferHubDefs::IsClientAcquired;
using BufferHubDefs::IsClientGained;
using BufferHubDefs::IsClientPosted;
using BufferHubDefs::IsClientReleased;
using BufferHubDefs::kHighBitsMask;

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
    ALOGD("%s: width=%u height=%u layerCount=%u, format=%u usage=%" PRIx64 " mUserMetadataSize=%zu",
          __FUNCTION__, width, height, layerCount, format, usage, mUserMetadataSize);

    auto status =
            mClient.InvokeRemoteMethod<DetachedBufferRPC::Create>(width, height, layerCount, format,
                                                                  usage, mUserMetadataSize);
    if (!status) {
        ALOGE("%s: Failed to create detached buffer: %s", __FUNCTION__,
              status.GetErrorMessage().c_str());
        mClient.Close(-status.error());
    }

    const int ret = ImportGraphicBuffer();
    if (ret < 0) {
        ALOGE("%s: Failed to import buffer: %s", __FUNCTION__, strerror(-ret));
        mClient.Close(ret);
    }
}

BufferHubBuffer::BufferHubBuffer(LocalChannelHandle mChannelHandle)
      : mClient(std::move(mChannelHandle)) {
    const int ret = ImportGraphicBuffer();
    if (ret < 0) {
        ALOGE("%s: Failed to import buffer: %s", __FUNCTION__, strerror(-ret));
        mClient.Close(ret);
    }
}

int BufferHubBuffer::ImportGraphicBuffer() {
    ATRACE_CALL();

    auto status = mClient.InvokeRemoteMethod<DetachedBufferRPC::Import>();
    if (!status) {
        ALOGE("%s: Failed to import GraphicBuffer: %s", __FUNCTION__,
              status.GetErrorMessage().c_str());
        return -status.error();
    }

    BufferTraits<LocalHandle> bufferTraits = status.take();
    if (bufferTraits.id() < 0) {
        ALOGE("%s: Received an invalid id!", __FUNCTION__);
        return -EIO;
    }

    // Stash the buffer id to replace the value in mId.
    const int bufferId = bufferTraits.id();

    // Import the metadata.
    LocalHandle metadataHandle = bufferTraits.take_metadata_handle();
    unique_fd metadataFd(metadataHandle.Release());
    mMetadata = BufferHubMetadata::Import(std::move(metadataFd));

    if (!mMetadata.IsValid()) {
        ALOGE("%s: invalid metadata.", __FUNCTION__);
        return -ENOMEM;
    }

    if (mMetadata.metadata_size() != bufferTraits.metadata_size()) {
        ALOGE("%s: metadata buffer too small: %zu, expected: %" PRIu64 ".", __FUNCTION__,
              mMetadata.metadata_size(), bufferTraits.metadata_size());
        return -ENOMEM;
    }

    size_t metadataSize = static_cast<size_t>(bufferTraits.metadata_size());
    if (metadataSize < BufferHubDefs::kMetadataHeaderSize) {
        ALOGE("%s: metadata too small: %zu", __FUNCTION__, metadataSize);
        return -EINVAL;
    }

    // Populate shortcuts to the atomics in metadata.
    auto metadata_header = mMetadata.metadata_header();
    buffer_state_ = &metadata_header->buffer_state;
    fence_state_ = &metadata_header->fence_state;
    active_clients_bit_mask_ = &metadata_header->active_clients_bit_mask;

    // Import the buffer: We only need to hold on the native_handle_t here so that
    // GraphicBuffer instance can be created in future.
    mBufferHandle = bufferTraits.take_buffer_handle();

    // Populate buffer desc based on buffer traits.
    mBufferDesc.width = bufferTraits.width();
    mBufferDesc.height = bufferTraits.height();
    mBufferDesc.layers = bufferTraits.layer_count();
    mBufferDesc.format = bufferTraits.format();
    mBufferDesc.usage = bufferTraits.usage();
    mBufferDesc.stride = bufferTraits.stride();
    mBufferDesc.rfu0 = 0U;
    mBufferDesc.rfu1 = 0U;

    // If all imports succeed, replace the previous buffer and id.
    mId = bufferId;
    mClientStateMask = bufferTraits.client_state_mask();

    // TODO(b/112012161) Set up shared fences.
    ALOGD("%s: id=%d, buffer_state=%" PRIx32 ".", __FUNCTION__, id(),
          buffer_state_->load(std::memory_order_acquire));
    return 0;
}

int BufferHubBuffer::Gain() {
    uint32_t current_buffer_state = buffer_state_->load(std::memory_order_acquire);
    if (IsClientGained(current_buffer_state, mClientStateMask)) {
        ALOGV("%s: Buffer is already gained by this client %" PRIx32 ".", __FUNCTION__,
              mClientStateMask);
        return 0;
    }
    do {
        if (AnyClientGained(current_buffer_state & (~mClientStateMask)) ||
            AnyClientAcquired(current_buffer_state)) {
            ALOGE("%s: Buffer is in use, id=%d mClientStateMask=%" PRIx32 " state=%" PRIx32 ".",
                  __FUNCTION__, mId, mClientStateMask, current_buffer_state);
            return -EBUSY;
        }
        // Change the buffer state to gained state, whose value happens to be the same as
        // mClientStateMask.
    } while (!buffer_state_->compare_exchange_weak(current_buffer_state, mClientStateMask,
                                                   std::memory_order_acq_rel,
                                                   std::memory_order_acquire));
    // TODO(b/119837586): Update fence state and return GPU fence.
    return 0;
}

int BufferHubBuffer::Post() {
    uint32_t current_buffer_state = buffer_state_->load(std::memory_order_acquire);
    uint32_t current_active_clients_bit_mask = 0U;
    uint32_t updated_buffer_state = 0U;
    do {
        if (!IsClientGained(current_buffer_state, mClientStateMask)) {
            ALOGE("%s: Cannot post a buffer that is not gained by this client. buffer_id=%d "
                  "mClientStateMask=%" PRIx32 " state=%" PRIx32 ".",
                  __FUNCTION__, mId, mClientStateMask, current_buffer_state);
            return -EBUSY;
        }
        // Set the producer client buffer state to released, other clients' buffer state to posted.
        current_active_clients_bit_mask = active_clients_bit_mask_->load(std::memory_order_acquire);
        updated_buffer_state =
                current_active_clients_bit_mask & (~mClientStateMask) & kHighBitsMask;
    } while (!buffer_state_->compare_exchange_weak(current_buffer_state, updated_buffer_state,
                                                   std::memory_order_acq_rel,
                                                   std::memory_order_acquire));
    // TODO(b/119837586): Update fence state and return GPU fence if needed.
    return 0;
}

int BufferHubBuffer::Acquire() {
    uint32_t current_buffer_state = buffer_state_->load(std::memory_order_acquire);
    if (IsClientAcquired(current_buffer_state, mClientStateMask)) {
        ALOGV("%s: Buffer is already acquired by this client %" PRIx32 ".", __FUNCTION__,
              mClientStateMask);
        return 0;
    }
    uint32_t updated_buffer_state = 0U;
    do {
        if (!IsClientPosted(current_buffer_state, mClientStateMask)) {
            ALOGE("%s: Cannot acquire a buffer that is not in posted state. buffer_id=%d "
                  "mClientStateMask=%" PRIx32 " state=%" PRIx32 ".",
                  __FUNCTION__, mId, mClientStateMask, current_buffer_state);
            return -EBUSY;
        }
        // Change the buffer state for this consumer from posted to acquired.
        updated_buffer_state = current_buffer_state ^ mClientStateMask;
    } while (!buffer_state_->compare_exchange_weak(current_buffer_state, updated_buffer_state,
                                                   std::memory_order_acq_rel,
                                                   std::memory_order_acquire));
    // TODO(b/119837586): Update fence state and return GPU fence.
    return 0;
}

int BufferHubBuffer::Release() {
    uint32_t current_buffer_state = buffer_state_->load(std::memory_order_acquire);
    if (IsClientReleased(current_buffer_state, mClientStateMask)) {
        ALOGV("%s: Buffer is already released by this client %" PRIx32 ".", __FUNCTION__,
              mClientStateMask);
        return 0;
    }
    uint32_t updated_buffer_state = 0U;
    do {
        updated_buffer_state = current_buffer_state & (~mClientStateMask);
    } while (!buffer_state_->compare_exchange_weak(current_buffer_state, updated_buffer_state,
                                                   std::memory_order_acq_rel,
                                                   std::memory_order_acquire));
    // TODO(b/119837586): Update fence state and return GPU fence if needed.
    return 0;
}

int BufferHubBuffer::Poll(int timeoutMs) {
    ATRACE_CALL();

    pollfd p = {mClient.event_fd(), POLLIN, 0};
    return poll(&p, 1, timeoutMs);
}

Status<LocalChannelHandle> BufferHubBuffer::Duplicate() {
    ATRACE_CALL();
    ALOGD("%s: id=%d.", __FUNCTION__, mId);

    auto statusOrHandle = mClient.InvokeRemoteMethod<DetachedBufferRPC::Duplicate>();

    if (!statusOrHandle.ok()) {
        ALOGE("%s: Failed to duplicate buffer (id=%d): %s.", __FUNCTION__, mId,
              statusOrHandle.GetErrorMessage().c_str());
    }
    return statusOrHandle;
}

} // namespace android
