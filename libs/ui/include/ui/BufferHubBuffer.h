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

#ifndef ANDROID_BUFFER_HUB_BUFFER_H_
#define ANDROID_BUFFER_HUB_BUFFER_H_

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
#include <pdx/client.h>
#include <private/dvr/buffer_hub_defs.h>
#include <private/dvr/native_handle_wrapper.h>
#pragma clang diagnostic pop

#include <ui/BufferHubMetadata.h>

namespace android {

class BufferHubClient : public pdx::Client {
public:
    BufferHubClient();
    virtual ~BufferHubClient();
    explicit BufferHubClient(pdx::LocalChannelHandle mChannelHandle);

    bool IsValid() const;
    pdx::LocalChannelHandle TakeChannelHandle();

    using pdx::Client::Close;
    using pdx::Client::event_fd;
    using pdx::Client::GetChannel;
    using pdx::Client::InvokeRemoteMethod;
};

class BufferHubBuffer {
public:
    // Allocates a standalone BufferHubBuffer not associated with any producer consumer set.
    static std::unique_ptr<BufferHubBuffer> Create(uint32_t width, uint32_t height,
                                                   uint32_t layerCount, uint32_t format,
                                                   uint64_t usage, size_t mUserMetadataSize) {
        return std::unique_ptr<BufferHubBuffer>(
                new BufferHubBuffer(width, height, layerCount, format, usage, mUserMetadataSize));
    }

    // Imports the given channel handle to a BufferHubBuffer, taking ownership.
    static std::unique_ptr<BufferHubBuffer> Import(pdx::LocalChannelHandle mChannelHandle) {
        return std::unique_ptr<BufferHubBuffer>(new BufferHubBuffer(std::move(mChannelHandle)));
    }

    BufferHubBuffer(const BufferHubBuffer&) = delete;
    void operator=(const BufferHubBuffer&) = delete;

    // Gets ID of the buffer client. All BufferHubBuffer clients derived from the same buffer in
    // bufferhubd share the same buffer id.
    int id() const { return mId; }

    const native_handle_t* DuplicateHandle() { return mBufferHandle.DuplicateHandle(); }

    // Returns the current value of MetadataHeader::buffer_state.
    uint64_t buffer_state() {
        return mMetadata.metadata_header()->buffer_state.load(std::memory_order_acquire);
    }

    // A state mask which is unique to a buffer hub client among all its siblings sharing the same
    // concrete graphic buffer.
    uint64_t client_state_mask() const { return mClientStateMask; }

    size_t user_metadata_size() const { return mMetadata.user_metadata_size(); }

    // Returns true if the buffer holds an open PDX channels towards bufferhubd.
    bool IsConnected() const { return mClient.IsValid(); }

    // Returns true if the buffer holds an valid native buffer handle that's availble for the client
    // to read from and/or write into.
    bool IsValid() const { return mBufferHandle.IsValid(); }

    // Returns the event mask for all the events that are pending on this buffer (see sys/poll.h for
    // all possible bits).
    pdx::Status<int> GetEventMask(int events) {
        if (auto* channel = mClient.GetChannel()) {
            return channel->GetEventMask(events);
        } else {
            return pdx::ErrorStatus(EINVAL);
        }
    }

    // Polls the fd for |timeoutMs| milliseconds (-1 for infinity).
    int Poll(int timeoutMs);

    // Creates a BufferHubBuffer client from an existing one. The new client will
    // share the same underlying gralloc buffer and ashmem region for metadata.
    pdx::Status<pdx::LocalChannelHandle> Duplicate();

private:
    BufferHubBuffer(uint32_t width, uint32_t height, uint32_t layerCount, uint32_t format,
                    uint64_t usage, size_t mUserMetadataSize);

    BufferHubBuffer(pdx::LocalChannelHandle mChannelHandle);

    int ImportGraphicBuffer();

    // Global id for the buffer that is consistent across processes.
    int mId = -1;
    uint64_t mClientStateMask = 0;

    // Wrapps the gralloc buffer handle of this buffer.
    dvr::NativeHandleWrapper<pdx::LocalHandle> mBufferHandle;

    // An ashmem-based metadata object. The same shared memory are mapped to the
    // bufferhubd daemon and all buffer clients.
    BufferHubMetadata mMetadata;

    // PDX backend.
    BufferHubClient mClient;
};

} // namespace android

#endif // ANDROID_BUFFER_HUB_BUFFER_H_
