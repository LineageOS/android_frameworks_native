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

#include <poll.h>

#include <android-base/unique_fd.h>
#include <android/frameworks/bufferhub/1.0/IBufferHub.h>
#include <log/log.h>
#include <ui/BufferHubBuffer.h>
#include <ui/BufferHubDefs.h>
#include <utils/Trace.h>

using ::android::base::unique_fd;
using ::android::BufferHubDefs::AnyClientAcquired;
using ::android::BufferHubDefs::AnyClientGained;
using ::android::BufferHubDefs::IsClientAcquired;
using ::android::BufferHubDefs::IsClientGained;
using ::android::BufferHubDefs::IsClientPosted;
using ::android::BufferHubDefs::IsClientReleased;
using ::android::frameworks::bufferhub::V1_0::BufferHubStatus;
using ::android::frameworks::bufferhub::V1_0::BufferTraits;
using ::android::frameworks::bufferhub::V1_0::IBufferClient;
using ::android::frameworks::bufferhub::V1_0::IBufferHub;
using ::android::hardware::hidl_handle;
using ::android::hardware::graphics::common::V1_2::HardwareBufferDescription;

namespace android {

std::unique_ptr<BufferHubBuffer> BufferHubBuffer::Create(uint32_t width, uint32_t height,
                                                         uint32_t layerCount, uint32_t format,
                                                         uint64_t usage, size_t userMetadataSize) {
    auto buffer = std::unique_ptr<BufferHubBuffer>(
            new BufferHubBuffer(width, height, layerCount, format, usage, userMetadataSize));
    return buffer->IsValid() ? std::move(buffer) : nullptr;
}

std::unique_ptr<BufferHubBuffer> BufferHubBuffer::Import(const native_handle_t* token) {
    if (token == nullptr) {
        ALOGE("%s: token cannot be nullptr!", __FUNCTION__);
        return nullptr;
    }

    auto buffer = std::unique_ptr<BufferHubBuffer>(new BufferHubBuffer(token));
    return buffer->IsValid() ? std::move(buffer) : nullptr;
}

BufferHubBuffer::BufferHubBuffer(uint32_t width, uint32_t height, uint32_t layerCount,
                                 uint32_t format, uint64_t usage, size_t userMetadataSize) {
    ATRACE_CALL();
    ALOGD("%s: width=%u height=%u layerCount=%u, format=%u "
          "usage=%" PRIx64 " mUserMetadataSize=%zu",
          __FUNCTION__, width, height, layerCount, format, usage, userMetadataSize);

    sp<IBufferHub> bufferhub = IBufferHub::getService();
    if (bufferhub.get() == nullptr) {
        ALOGE("%s: BufferHub service not found!", __FUNCTION__);
        return;
    }

    AHardwareBuffer_Desc aDesc = {width, height,         layerCount,   format,
                                  usage, /*stride=*/0UL, /*rfu0=*/0UL, /*rfu1=*/0ULL};
    HardwareBufferDescription desc;
    memcpy(&desc, &aDesc, sizeof(HardwareBufferDescription));

    BufferHubStatus ret;
    sp<IBufferClient> client;
    BufferTraits bufferTraits;
    IBufferHub::allocateBuffer_cb alloc_cb = [&](const auto& status, const auto& outClient,
                                                 const auto& traits) {
        ret = status;
        client = std::move(outClient);
        bufferTraits = std::move(traits);
    };

    if (!bufferhub->allocateBuffer(desc, static_cast<uint32_t>(userMetadataSize), alloc_cb)
                 .isOk()) {
        ALOGE("%s: allocateBuffer transaction failed!", __FUNCTION__);
        return;
    } else if (ret != BufferHubStatus::NO_ERROR) {
        ALOGE("%s: allocateBuffer failed with error %u.", __FUNCTION__, ret);
        return;
    } else if (client == nullptr) {
        ALOGE("%s: allocateBuffer got null BufferClient.", __FUNCTION__);
        return;
    }

    const int importRet = initWithBufferTraits(bufferTraits);
    if (importRet < 0) {
        ALOGE("%s: Failed to import buffer: %s", __FUNCTION__, strerror(-importRet));
        client->close();
    }
    mBufferClient = std::move(client);
}

BufferHubBuffer::BufferHubBuffer(const native_handle_t* token) {
    sp<IBufferHub> bufferhub = IBufferHub::getService();
    if (bufferhub.get() == nullptr) {
        ALOGE("%s: BufferHub service not found!", __FUNCTION__);
        return;
    }

    BufferHubStatus ret;
    sp<IBufferClient> client;
    BufferTraits bufferTraits;
    IBufferHub::importBuffer_cb import_cb = [&](const auto& status, const auto& outClient,
                                                const auto& traits) {
        ret = status;
        client = std::move(outClient);
        bufferTraits = std::move(traits);
    };

    // hidl_handle(native_handle_t*) simply creates a raw pointer reference withouth ownership
    // transfer.
    if (!bufferhub->importBuffer(hidl_handle(token), import_cb).isOk()) {
        ALOGE("%s: importBuffer transaction failed!", __FUNCTION__);
        return;
    } else if (ret != BufferHubStatus::NO_ERROR) {
        ALOGE("%s: importBuffer failed with error %u.", __FUNCTION__, ret);
        return;
    } else if (client == nullptr) {
        ALOGE("%s: importBuffer got null BufferClient.", __FUNCTION__);
        return;
    }

    const int importRet = initWithBufferTraits(bufferTraits);
    if (importRet < 0) {
        ALOGE("%s: Failed to import buffer: %s", __FUNCTION__, strerror(-importRet));
        client->close();
    }
    mBufferClient = std::move(client);
}

BufferHubBuffer::~BufferHubBuffer() {
    // Close buffer client to avoid possible race condition: user could first duplicate and hold
    // token with the original buffer gone, and then try to import the token. The close function
    // will explicitly invalidate the token to avoid this.
    if (mBufferClient != nullptr) {
        if (!mBufferClient->close().isOk()) {
            ALOGE("%s: close BufferClient transaction failed!", __FUNCTION__);
        }
    }
}

int BufferHubBuffer::initWithBufferTraits(const BufferTraits& bufferTraits) {
    ATRACE_CALL();

    if (bufferTraits.bufferInfo.getNativeHandle() == nullptr) {
        ALOGE("%s: missing buffer info handle.", __FUNCTION__);
        return -EINVAL;
    }

    if (bufferTraits.bufferHandle.getNativeHandle() == nullptr) {
        ALOGE("%s: missing gralloc handle.", __FUNCTION__);
        return -EINVAL;
    }

    // Import fds. Dup fds because hidl_handle owns the fds.
    unique_fd ashmemFd(fcntl(bufferTraits.bufferInfo->data[0], F_DUPFD_CLOEXEC, 0));
    mMetadata = BufferHubMetadata::Import(std::move(ashmemFd));
    if (!mMetadata.IsValid()) {
        ALOGE("%s: Received an invalid metadata.", __FUNCTION__);
        return -EINVAL;
    }

    mEventFd = BufferHubEventFd(fcntl(bufferTraits.bufferInfo->data[1], F_DUPFD_CLOEXEC, 0));
    if (!mEventFd.isValid()) {
        ALOGE("%s: Received ad invalid event fd.", __FUNCTION__);
        return -EINVAL;
    }

    int bufferId = bufferTraits.bufferInfo->data[2];
    if (bufferId < 0) {
        ALOGE("%s: Received an invalid (negative) id.", __FUNCTION__);
        return -EINVAL;
    }

    uint32_t clientBitMask;
    memcpy(&clientBitMask, &bufferTraits.bufferInfo->data[3], sizeof(clientBitMask));
    if (clientBitMask == 0U) {
        ALOGE("%s: Received an invalid client state mask.", __FUNCTION__);
        return -EINVAL;
    }

    uint32_t userMetadataSize;
    memcpy(&userMetadataSize, &bufferTraits.bufferInfo->data[4], sizeof(userMetadataSize));
    if (mMetadata.user_metadata_size() != userMetadataSize) {
        ALOGE("%s: user metadata size not match: expected %u, actual %zu.", __FUNCTION__,
              userMetadataSize, mMetadata.user_metadata_size());
        return -EINVAL;
    }

    size_t metadataSize = static_cast<size_t>(mMetadata.metadata_size());
    if (metadataSize < BufferHubDefs::kMetadataHeaderSize) {
        ALOGE("%s: metadata too small: %zu", __FUNCTION__, metadataSize);
        return -EINVAL;
    }

    // Populate shortcuts to the atomics in metadata.
    auto metadata_header = mMetadata.metadata_header();
    buffer_state_ = &metadata_header->buffer_state;
    fence_state_ = &metadata_header->fence_state;
    active_clients_bit_mask_ = &metadata_header->active_clients_bit_mask;
    // The C++ standard recommends (but does not require) that lock-free atomic operations are
    // also address-free, that is, suitable for communication between processes using shared
    // memory.
    LOG_ALWAYS_FATAL_IF(!std::atomic_is_lock_free(buffer_state_) ||
                                !std::atomic_is_lock_free(fence_state_) ||
                                !std::atomic_is_lock_free(active_clients_bit_mask_),
                        "Atomic variables in ashmen are not lock free.");

    // Import the buffer: We only need to hold on the native_handle_t here so that
    // GraphicBuffer instance can be created in future.
    mBufferHandle = std::move(bufferTraits.bufferHandle);
    memcpy(&mBufferDesc, &bufferTraits.bufferDesc, sizeof(AHardwareBuffer_Desc));

    mId = bufferId;
    mClientStateMask = clientBitMask;

    // TODO(b/112012161) Set up shared fences.
    ALOGD("%s: id=%d, buffer_state=%" PRIx32 ".", __FUNCTION__, mId,
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
    uint32_t updated_buffer_state = (~mClientStateMask) & BufferHubDefs::kHighBitsMask;
    do {
        if (!IsClientGained(current_buffer_state, mClientStateMask)) {
            ALOGE("%s: Cannot post a buffer that is not gained by this client. buffer_id=%d "
                  "mClientStateMask=%" PRIx32 " state=%" PRIx32 ".",
                  __FUNCTION__, mId, mClientStateMask, current_buffer_state);
            return -EBUSY;
        }
        // Set the producer client buffer state to released, other clients' buffer state to posted.
        // Post to all existing and non-existing clients.
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

bool BufferHubBuffer::IsReleased() const {
    return (buffer_state_->load(std::memory_order_acquire) &
            active_clients_bit_mask_->load(std::memory_order_acquire)) == 0;
}

bool BufferHubBuffer::IsValid() const {
    return mBufferHandle.getNativeHandle() != nullptr && mId >= 0 && mClientStateMask != 0U &&
            mEventFd.get() >= 0 && mMetadata.IsValid() && mBufferClient != nullptr;
}

native_handle_t* BufferHubBuffer::Duplicate() {
    if (mBufferClient == nullptr) {
        ALOGE("%s: missing BufferClient!", __FUNCTION__);
        return nullptr;
    }

    hidl_handle token;
    BufferHubStatus ret;
    IBufferClient::duplicate_cb dup_cb = [&](const auto& outToken, const auto& status) {
        token = std::move(outToken);
        ret = status;
    };

    if (!mBufferClient->duplicate(dup_cb).isOk()) {
        ALOGE("%s: duplicate transaction failed!", __FUNCTION__);
        return nullptr;
    } else if (ret != BufferHubStatus::NO_ERROR) {
        ALOGE("%s: duplicate failed with error %u.", __FUNCTION__, ret);
        return nullptr;
    } else if (token.getNativeHandle() == nullptr) {
        ALOGE("%s: duplicate got null token.", __FUNCTION__);
        return nullptr;
    }

    return native_handle_clone(token.getNativeHandle());
}

} // namespace android
