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

#include <android/hardware_buffer.h>
#include <bufferhub/BufferHubService.h>
#include <cutils/native_handle.h>
#include <log/log.h>

namespace android {
namespace frameworks {
namespace bufferhub {
namespace V1_0 {
namespace implementation {

using hardware::Void;

Return<void> BufferHubService::allocateBuffer(const HardwareBufferDescription& description,
                                              const uint32_t userMetadataSize,
                                              allocateBuffer_cb _hidl_cb) {
    AHardwareBuffer_Desc desc;
    memcpy(&desc, &description, sizeof(AHardwareBuffer_Desc));

    std::shared_ptr<BufferNode> node =
            std::make_shared<BufferNode>(desc.width, desc.height, desc.layers, desc.format,
                                         desc.usage, userMetadataSize,
                                         BufferHubIdGenerator::getInstance().getId());
    if (node == nullptr || !node->IsValid()) {
        ALOGE("%s: creating BufferNode failed.", __FUNCTION__);
        _hidl_cb(/*status=*/BufferHubStatus::ALLOCATION_FAILED, /*bufferClient=*/nullptr,
                 /*bufferTraits=*/{});
        return Void();
    }

    sp<BufferClient> client = BufferClient::create(this, node);
    // Add it to list for bookkeeping and dumpsys.
    std::lock_guard<std::mutex> lock(mClientSetMutex);
    mClientSet.emplace(client);

    BufferTraits bufferTraits = {/*bufferDesc=*/description,
                                 /*bufferHandle=*/hidl_handle(node->buffer_handle()),
                                 // TODO(b/116681016): return real data to client
                                 /*bufferInfo=*/hidl_handle()};

    _hidl_cb(/*status=*/BufferHubStatus::NO_ERROR, /*bufferClient=*/client,
             /*bufferTraits=*/bufferTraits);
    return Void();
}

Return<void> BufferHubService::importBuffer(const hidl_handle& tokenHandle,
                                            importBuffer_cb _hidl_cb) {
    if (!tokenHandle.getNativeHandle() || tokenHandle->numFds != 0 || tokenHandle->numInts != 1) {
        // nullptr handle or wrong format
        _hidl_cb(/*status=*/BufferHubStatus::INVALID_TOKEN, /*bufferClient=*/nullptr,
                 /*bufferTraits=*/{});
        return Void();
    }

    uint32_t token = tokenHandle->data[0];

    wp<BufferClient> originClientWp;
    {
        std::lock_guard<std::mutex> lock(mTokenMapMutex);
        auto iter = mTokenMap.find(token);
        if (iter == mTokenMap.end()) {
            // Invalid token
            _hidl_cb(/*status=*/BufferHubStatus::INVALID_TOKEN, /*bufferClient=*/nullptr,
                     /*bufferTraits=*/{});
            return Void();
        }

        originClientWp = iter->second;
        mTokenMap.erase(iter);
    }

    // Check if original client is dead
    sp<BufferClient> originClient = originClientWp.promote();
    if (!originClient) {
        // Should not happen since token should be removed if already gone
        ALOGE("%s: original client %p gone!", __FUNCTION__, originClientWp.unsafe_get());
        _hidl_cb(/*status=*/BufferHubStatus::BUFFER_FREED, /*bufferClient=*/nullptr,
                 /*bufferTraits=*/{});
        return Void();
    }

    sp<BufferClient> client = new BufferClient(*originClient);
    uint32_t clientStateMask = client->getBufferNode()->AddNewActiveClientsBitToMask();
    if (clientStateMask == 0U) {
        // Reach max client count
        ALOGE("%s: import failed, BufferNode#%u reached maximum clients.", __FUNCTION__,
              client->getBufferNode()->id());
        _hidl_cb(/*status=*/BufferHubStatus::MAX_CLIENT, /*bufferClient=*/nullptr,
                 /*bufferTraits=*/{});
        return Void();
    }

    std::lock_guard<std::mutex> lock(mClientSetMutex);
    mClientSet.emplace(client);

    std::shared_ptr<BufferNode> node = client->getBufferNode();

    HardwareBufferDescription bufferDesc;
    memcpy(&bufferDesc, &node->buffer_desc(), sizeof(HardwareBufferDescription));

    BufferTraits bufferTraits = {/*bufferDesc=*/bufferDesc,
                                 /*bufferHandle=*/hidl_handle(node->buffer_handle()),
                                 // TODO(b/116681016): return real data to client
                                 /*bufferInfo=*/hidl_handle()};

    _hidl_cb(/*status=*/BufferHubStatus::NO_ERROR, /*bufferClient=*/client,
             /*bufferTraits=*/bufferTraits);
    return Void();
}

hidl_handle BufferHubService::registerToken(const wp<BufferClient>& client) {
    uint32_t token;
    std::lock_guard<std::mutex> lock(mTokenMapMutex);
    do {
        token = mTokenEngine();
    } while (mTokenMap.find(token) != mTokenMap.end());

    // native_handle_t use int[], so here need one slots to fit in uint32_t
    native_handle_t* handle = native_handle_create(/*numFds=*/0, /*numInts=*/1);
    handle->data[0] = token;

    // returnToken owns the native_handle_t* thus doing lifecycle management
    hidl_handle returnToken;
    returnToken.setTo(handle, /*shoudOwn=*/true);

    mTokenMap.emplace(token, client);
    return returnToken;
}

void BufferHubService::onClientClosed(const BufferClient* client) {
    removeTokenByClient(client);

    std::lock_guard<std::mutex> lock(mClientSetMutex);
    auto iter = std::find(mClientSet.begin(), mClientSet.end(), client);
    if (iter != mClientSet.end()) {
        mClientSet.erase(iter);
    }
}

void BufferHubService::removeTokenByClient(const BufferClient* client) {
    std::lock_guard<std::mutex> lock(mTokenMapMutex);
    auto iter = mTokenMap.begin();
    while (iter != mTokenMap.end()) {
        if (iter->second == client) {
            auto oldIter = iter;
            ++iter;
            mTokenMap.erase(oldIter);
        } else {
            ++iter;
        }
    }
}

} // namespace implementation
} // namespace V1_0
} // namespace bufferhub
} // namespace frameworks
} // namespace android
