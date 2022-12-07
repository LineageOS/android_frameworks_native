/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define LOG_TAG "SurfaceComposerClient"

#include <stdint.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/SortedVector.h>
#include <utils/String8.h>
#include <utils/threads.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>

#include <system/graphics.h>

#include <gui/BufferItemConsumer.h>
#include <gui/CpuConsumer.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/ISurfaceComposer.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/LayerState.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <ui/DisplayConfig.h>

#ifndef NO_INPUT
#include <input/InputWindow.h>
#endif

#include <private/gui/ComposerService.h>

// This server size should always be smaller than the server cache size
#define BUFFER_CACHE_MAX_SIZE 64

namespace android {

using ui::ColorMode;
// ---------------------------------------------------------------------------

ANDROID_SINGLETON_STATIC_INSTANCE(ComposerService);

ComposerService::ComposerService()
: Singleton<ComposerService>() {
    Mutex::Autolock _l(mLock);
    connectLocked();
}

void ComposerService::connectLocked() {
    const String16 name("SurfaceFlinger");
    while (getService(name, &mComposerService) != NO_ERROR) {
        usleep(250000);
    }
    assert(mComposerService != nullptr);

    // Create the death listener.
    class DeathObserver : public IBinder::DeathRecipient {
        ComposerService& mComposerService;
        virtual void binderDied(const wp<IBinder>& who) {
            ALOGW("ComposerService remote (surfaceflinger) died [%p]",
                  who.unsafe_get());
            mComposerService.composerServiceDied();
        }
     public:
        explicit DeathObserver(ComposerService& mgr) : mComposerService(mgr) { }
    };

    mDeathObserver = new DeathObserver(*const_cast<ComposerService*>(this));
    IInterface::asBinder(mComposerService)->linkToDeath(mDeathObserver);
}

/*static*/ sp<ISurfaceComposer> ComposerService::getComposerService() {
    ComposerService& instance = ComposerService::getInstance();
    Mutex::Autolock _l(instance.mLock);
    if (instance.mComposerService == nullptr) {
        ComposerService::getInstance().connectLocked();
        assert(instance.mComposerService != nullptr);
        ALOGD("ComposerService reconnected");
    }
    return instance.mComposerService;
}

void ComposerService::composerServiceDied()
{
    Mutex::Autolock _l(mLock);
    mComposerService = nullptr;
    mDeathObserver = nullptr;
}

class DefaultComposerClient: public Singleton<DefaultComposerClient> {
    Mutex mLock;
    sp<SurfaceComposerClient> mClient;
    friend class Singleton<ComposerService>;
public:
    static sp<SurfaceComposerClient> getComposerClient() {
        DefaultComposerClient& dc = DefaultComposerClient::getInstance();
        Mutex::Autolock _l(dc.mLock);
        if (dc.mClient == nullptr) {
            dc.mClient = new SurfaceComposerClient;
        }
        return dc.mClient;
    }
};
ANDROID_SINGLETON_STATIC_INSTANCE(DefaultComposerClient);


sp<SurfaceComposerClient> SurfaceComposerClient::getDefault() {
    return DefaultComposerClient::getComposerClient();
}

// ---------------------------------------------------------------------------

// TransactionCompletedListener does not use ANDROID_SINGLETON_STATIC_INSTANCE because it needs
// to be able to return a sp<> to its instance to pass to SurfaceFlinger.
// ANDROID_SINGLETON_STATIC_INSTANCE only allows a reference to an instance.

// 0 is an invalid callback id
TransactionCompletedListener::TransactionCompletedListener() : mCallbackIdCounter(1) {}

CallbackId TransactionCompletedListener::getNextIdLocked() {
    return mCallbackIdCounter++;
}

sp<TransactionCompletedListener> TransactionCompletedListener::getInstance() {
    static sp<TransactionCompletedListener> sInstance = new TransactionCompletedListener;
    return sInstance;
}

sp<ITransactionCompletedListener> TransactionCompletedListener::getIInstance() {
    return static_cast<sp<ITransactionCompletedListener>>(getInstance());
}

void TransactionCompletedListener::startListeningLocked() {
    if (mListening) {
        return;
    }
    ProcessState::self()->startThreadPool();
    mListening = true;
}

CallbackId TransactionCompletedListener::addCallbackFunction(
        const TransactionCompletedCallback& callbackFunction,
        const std::unordered_set<sp<SurfaceControl>, SurfaceComposerClient::SCHash>&
                surfaceControls) {
    std::lock_guard<std::mutex> lock(mMutex);
    startListeningLocked();

    CallbackId callbackId = getNextIdLocked();
    mCallbacks[callbackId].callbackFunction = callbackFunction;

    auto& callbackSurfaceControls = mCallbacks[callbackId].surfaceControls;

    for (const auto& surfaceControl : surfaceControls) {
        callbackSurfaceControls[surfaceControl->getHandle()] = surfaceControl;
    }

    return callbackId;
}

void TransactionCompletedListener::addSurfaceControlToCallbacks(
        const sp<SurfaceControl>& surfaceControl,
        const std::unordered_set<CallbackId>& callbackIds) {
    std::lock_guard<std::mutex> lock(mMutex);

    for (auto callbackId : callbackIds) {
        mCallbacks[callbackId].surfaceControls.emplace(std::piecewise_construct,
                                                       std::forward_as_tuple(
                                                               surfaceControl->getHandle()),
                                                       std::forward_as_tuple(surfaceControl));
    }
}

void TransactionCompletedListener::onTransactionCompleted(ListenerStats listenerStats) {
    std::unordered_map<CallbackId, CallbackTranslation> callbacksMap;
    {
        std::lock_guard<std::mutex> lock(mMutex);

        /* This listener knows all the sp<IBinder> to sp<SurfaceControl> for all its registered
         * callbackIds, except for when Transactions are merged together. This probably cannot be
         * solved before this point because the Transactions could be merged together and applied in
         * a different process.
         *
         * Fortunately, we get all the callbacks for this listener for the same frame together at
         * the same time. This means if any Transactions were merged together, we will get their
         * callbacks at the same time. We can combine all the sp<IBinder> to sp<SurfaceControl> maps
         * for all the callbackIds to generate one super map that contains all the sp<IBinder> to
         * sp<SurfaceControl> that could possibly exist for the callbacks.
         */
        callbacksMap = mCallbacks;
        for (const auto& transactionStats : listenerStats.transactionStats) {
            for (auto& callbackId : transactionStats.callbackIds) {
                mCallbacks.erase(callbackId);
            }
        }
    }
    for (const auto& transactionStats : listenerStats.transactionStats) {
        for (auto callbackId : transactionStats.callbackIds) {
            auto& [callbackFunction, callbackSurfaceControls] = callbacksMap[callbackId];
            if (!callbackFunction) {
                ALOGE("cannot call null callback function, skipping");
                continue;
            }
            std::vector<SurfaceControlStats> surfaceControlStats;
            for (const auto& surfaceStats : transactionStats.surfaceStats) {
                surfaceControlStats
                        .emplace_back(callbacksMap[callbackId]
                                              .surfaceControls[surfaceStats.surfaceControl],
                                      transactionStats.latchTime, surfaceStats.acquireTime,
                                      transactionStats.presentFence,
                                      surfaceStats.previousReleaseFence, surfaceStats.transformHint,
                                      surfaceStats.eventStats);
                if (callbacksMap[callbackId].surfaceControls[surfaceStats.surfaceControl]) {
                    callbacksMap[callbackId]
                            .surfaceControls[surfaceStats.surfaceControl]
                            ->setTransformHint(surfaceStats.transformHint);
                }
            }

            callbackFunction(transactionStats.latchTime, transactionStats.presentFence,
                             surfaceControlStats);
        }
    }
}

// ---------------------------------------------------------------------------

void removeDeadBufferCallback(void* /*context*/, uint64_t graphicBufferId);

/**
 * We use the BufferCache to reduce the overhead of exchanging GraphicBuffers with
 * the server. If we were to simply parcel the GraphicBuffer we would pay two overheads
 *     1. Cost of sending the FD
 *     2. Cost of importing the GraphicBuffer with the mapper in the receiving process.
 * To ease this cost we implement the following scheme of caching buffers to integers,
 * or said-otherwise, naming them with integers. This is the scheme known as slots in
 * the legacy BufferQueue system.
 *     1. When sending Buffers to SurfaceFlinger we look up the Buffer in the cache.
 *     2. If there is a cache-hit we remove the Buffer from the Transaction and instead
 *        send the cached integer.
 *     3. If there is a cache miss, we cache the new buffer and send the integer
 *        along with the Buffer, SurfaceFlinger on it's side creates a new cache
 *        entry, and we use the integer for further communication.
 * A few details about lifetime:
 *     1. The cache evicts by LRU. The server side cache is keyed by BufferCache::getToken
 *        which is per process Unique. The server side cache is larger than the client side
 *        cache so that the server will never evict entries before the client.
 *     2. When the client evicts an entry it notifies the server via an uncacheBuffer
 *        transaction.
 *     3. The client only references the Buffers by ID, and uses buffer->addDeathCallback
 *        to auto-evict destroyed buffers.
 */
class BufferCache : public Singleton<BufferCache> {
public:
    BufferCache() : token(new BBinder()) {}

    sp<IBinder> getToken() {
        return IInterface::asBinder(TransactionCompletedListener::getIInstance());
    }

    status_t getCacheId(const sp<GraphicBuffer>& buffer, uint64_t* cacheId) {
        std::lock_guard<std::mutex> lock(mMutex);

        auto itr = mBuffers.find(buffer->getId());
        if (itr == mBuffers.end()) {
            return BAD_VALUE;
        }
        itr->second = getCounter();
        *cacheId = buffer->getId();
        return NO_ERROR;
    }

    uint64_t cache(const sp<GraphicBuffer>& buffer) {
        std::lock_guard<std::mutex> lock(mMutex);

        if (mBuffers.size() >= BUFFER_CACHE_MAX_SIZE) {
            evictLeastRecentlyUsedBuffer();
        }

        buffer->addDeathCallback(removeDeadBufferCallback, nullptr);

        mBuffers[buffer->getId()] = getCounter();
        return buffer->getId();
    }

    void uncache(uint64_t cacheId) {
        std::lock_guard<std::mutex> lock(mMutex);
        uncacheLocked(cacheId);
    }

    void uncacheLocked(uint64_t cacheId) REQUIRES(mMutex) {
        mBuffers.erase(cacheId);
        SurfaceComposerClient::doUncacheBufferTransaction(cacheId);
    }

private:
    void evictLeastRecentlyUsedBuffer() REQUIRES(mMutex) {
        auto itr = mBuffers.begin();
        uint64_t minCounter = itr->second;
        auto minBuffer = itr;
        itr++;

        while (itr != mBuffers.end()) {
            uint64_t counter = itr->second;
            if (counter < minCounter) {
                minCounter = counter;
                minBuffer = itr;
            }
            itr++;
        }
        uncacheLocked(minBuffer->first);
    }

    uint64_t getCounter() REQUIRES(mMutex) {
        static uint64_t counter = 0;
        return counter++;
    }

    std::mutex mMutex;
    std::map<uint64_t /*Cache id*/, uint64_t /*counter*/> mBuffers GUARDED_BY(mMutex);

    // Used by ISurfaceComposer to identify which process is sending the cached buffer.
    sp<IBinder> token;
};

ANDROID_SINGLETON_STATIC_INSTANCE(BufferCache);

void removeDeadBufferCallback(void* /*context*/, uint64_t graphicBufferId) {
    // GraphicBuffer id's are used as the cache ids.
    BufferCache::getInstance().uncache(graphicBufferId);
}

// ---------------------------------------------------------------------------

SurfaceComposerClient::Transaction::Transaction(const Transaction& other)
      : mForceSynchronous(other.mForceSynchronous),
        mTransactionNestCount(other.mTransactionNestCount),
        mAnimation(other.mAnimation),
        mEarlyWakeup(other.mEarlyWakeup),
        mExplicitEarlyWakeupStart(other.mExplicitEarlyWakeupStart),
        mExplicitEarlyWakeupEnd(other.mExplicitEarlyWakeupEnd),
        mContainsBuffer(other.mContainsBuffer),
        mDesiredPresentTime(other.mDesiredPresentTime) {
    mDisplayStates = other.mDisplayStates;
    mComposerStates = other.mComposerStates;
    mInputWindowCommands = other.mInputWindowCommands;
    mListenerCallbacks = other.mListenerCallbacks;
}

std::unique_ptr<SurfaceComposerClient::Transaction>
SurfaceComposerClient::Transaction::createFromParcel(const Parcel* parcel) {
    auto transaction = std::make_unique<Transaction>();
    if (transaction->readFromParcel(parcel) == NO_ERROR) {
        return transaction;
    }
    return nullptr;
}

status_t SurfaceComposerClient::Transaction::readFromParcel(const Parcel* parcel) {
    const uint32_t forceSynchronous = parcel->readUint32();
    const uint32_t transactionNestCount = parcel->readUint32();
    const bool animation = parcel->readBool();
    const bool earlyWakeup = parcel->readBool();
    const bool explicitEarlyWakeupStart = parcel->readBool();
    const bool explicitEarlyWakeupEnd = parcel->readBool();
    const bool containsBuffer = parcel->readBool();
    const int64_t desiredPresentTime = parcel->readInt64();

    size_t count = static_cast<size_t>(parcel->readUint32());
    if (count > parcel->dataSize()) {
        return BAD_VALUE;
    }
    SortedVector<DisplayState> displayStates;
    displayStates.setCapacity(count);
    for (size_t i = 0; i < count; i++) {
        DisplayState displayState;
        if (displayState.read(*parcel) == BAD_VALUE) {
            return BAD_VALUE;
        }
        displayStates.add(displayState);
    }

    count = static_cast<size_t>(parcel->readUint32());
    if (count > parcel->dataSize()) {
        return BAD_VALUE;
    }
    std::unordered_map<sp<ITransactionCompletedListener>, CallbackInfo, TCLHash> listenerCallbacks;
    listenerCallbacks.reserve(count);
    for (size_t i = 0; i < count; i++) {
        sp<ITransactionCompletedListener> listener =
                interface_cast<ITransactionCompletedListener>(parcel->readStrongBinder());
        size_t numCallbackIds = parcel->readUint32();
        if (numCallbackIds > parcel->dataSize()) {
            return BAD_VALUE;
        }
        for (size_t j = 0; j < numCallbackIds; j++) {
            listenerCallbacks[listener].callbackIds.insert(parcel->readInt64());
        }
        size_t numSurfaces = parcel->readUint32();
        if (numSurfaces > parcel->dataSize()) {
            return BAD_VALUE;
        }
        for (size_t j = 0; j < numSurfaces; j++) {
            sp<SurfaceControl> surface;
            surface = SurfaceControl::readFromParcel(parcel);
            listenerCallbacks[listener].surfaceControls.insert(surface);
        }
    }

    count = static_cast<size_t>(parcel->readUint32());
    if (count > parcel->dataSize()) {
        return BAD_VALUE;
    }
    std::unordered_map<sp<IBinder>, ComposerState, IBinderHash> composerStates;
    composerStates.reserve(count);
    for (size_t i = 0; i < count; i++) {
        sp<IBinder> surfaceControlHandle = parcel->readStrongBinder();

        ComposerState composerState;
        if (composerState.read(*parcel) == BAD_VALUE) {
            return BAD_VALUE;
        }
        composerStates[surfaceControlHandle] = composerState;
    }

    InputWindowCommands inputWindowCommands;
    inputWindowCommands.read(*parcel);

    // Parsing was successful. Update the object.
    mForceSynchronous = forceSynchronous;
    mTransactionNestCount = transactionNestCount;
    mAnimation = animation;
    mEarlyWakeup = earlyWakeup;
    mExplicitEarlyWakeupStart = explicitEarlyWakeupStart;
    mExplicitEarlyWakeupEnd = explicitEarlyWakeupEnd;
    mContainsBuffer = containsBuffer;
    mDesiredPresentTime = desiredPresentTime;
    mDisplayStates = displayStates;
    mListenerCallbacks = listenerCallbacks;
    mComposerStates = composerStates;
    mInputWindowCommands = inputWindowCommands;
    return NO_ERROR;
}

status_t SurfaceComposerClient::Transaction::writeToParcel(Parcel* parcel) const {
    // If we write the Transaction to a parcel, we want to ensure the Buffers are cached
    // before crossing the IPC boundary. Otherwise the receiving party will cache the buffers
    // but is unlikely to use them again as they are owned by the other process.
    // You may be asking yourself, is this const cast safe? Const cast is safe up
    // until the point where you try and write to an object that was originally const at which
    // point we enter undefined behavior. In this case we are safe though, because there are
    // two possibilities:
    //    1. The SurfaceComposerClient::Transaction was originally non-const. Safe.
    //    2. It was originall const! In this case not only was it useless, but it by definition
    //       contains no composer states and so cacheBuffers will not perform any writes.

    const_cast<SurfaceComposerClient::Transaction*>(this)->cacheBuffers();

    parcel->writeUint32(mForceSynchronous);
    parcel->writeUint32(mTransactionNestCount);
    parcel->writeBool(mAnimation);
    parcel->writeBool(mEarlyWakeup);
    parcel->writeBool(mExplicitEarlyWakeupStart);
    parcel->writeBool(mExplicitEarlyWakeupEnd);
    parcel->writeBool(mContainsBuffer);
    parcel->writeInt64(mDesiredPresentTime);
    parcel->writeUint32(static_cast<uint32_t>(mDisplayStates.size()));
    for (auto const& displayState : mDisplayStates) {
        displayState.write(*parcel);
    }

    parcel->writeUint32(static_cast<uint32_t>(mListenerCallbacks.size()));
    for (auto const& [listener, callbackInfo] : mListenerCallbacks) {
        parcel->writeStrongBinder(ITransactionCompletedListener::asBinder(listener));
        parcel->writeUint32(static_cast<uint32_t>(callbackInfo.callbackIds.size()));
        for (auto callbackId : callbackInfo.callbackIds) {
            parcel->writeInt64(callbackId);
        }
        parcel->writeUint32(static_cast<uint32_t>(callbackInfo.surfaceControls.size()));
        for (auto surfaceControl : callbackInfo.surfaceControls) {
            surfaceControl->writeToParcel(parcel);
        }
    }

    parcel->writeUint32(static_cast<uint32_t>(mComposerStates.size()));
    for (auto const& [surfaceHandle, composerState] : mComposerStates) {
        parcel->writeStrongBinder(surfaceHandle);
        composerState.write(*parcel);
    }

    mInputWindowCommands.write(*parcel);
    return NO_ERROR;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::merge(Transaction&& other) {
    for (auto const& [surfaceHandle, composerState] : other.mComposerStates) {
        if (mComposerStates.count(surfaceHandle) == 0) {
            mComposerStates[surfaceHandle] = composerState;
        } else {
            mComposerStates[surfaceHandle].state.merge(composerState.state);
        }
    }

    for (auto const& state : other.mDisplayStates) {
        ssize_t index = mDisplayStates.indexOf(state);
        if (index < 0) {
            mDisplayStates.add(state);
        } else {
            mDisplayStates.editItemAt(static_cast<size_t>(index)).merge(state);
        }
    }

    for (const auto& [listener, callbackInfo] : other.mListenerCallbacks) {
        auto& [callbackIds, surfaceControls] = callbackInfo;
        mListenerCallbacks[listener].callbackIds.insert(std::make_move_iterator(
                                                                callbackIds.begin()),
                                                        std::make_move_iterator(callbackIds.end()));

        mListenerCallbacks[listener].surfaceControls.insert(surfaceControls.begin(),
                                                            surfaceControls.end());

        auto& currentProcessCallbackInfo =
                mListenerCallbacks[TransactionCompletedListener::getIInstance()];
        currentProcessCallbackInfo.surfaceControls
                .insert(std::make_move_iterator(surfaceControls.begin()),
                        std::make_move_iterator(surfaceControls.end()));

        // register all surface controls for all callbackIds for this listener that is merging
        for (const auto& surfaceControl : currentProcessCallbackInfo.surfaceControls) {
            TransactionCompletedListener::getInstance()
                    ->addSurfaceControlToCallbacks(surfaceControl,
                                                   currentProcessCallbackInfo.callbackIds);
        }
    }

    mInputWindowCommands.merge(other.mInputWindowCommands);

    mContainsBuffer |= other.mContainsBuffer;
    mEarlyWakeup = mEarlyWakeup || other.mEarlyWakeup;
    mExplicitEarlyWakeupStart = mExplicitEarlyWakeupStart || other.mExplicitEarlyWakeupStart;
    mExplicitEarlyWakeupEnd = mExplicitEarlyWakeupEnd || other.mExplicitEarlyWakeupEnd;
    other.clear();
    return *this;
}

void SurfaceComposerClient::Transaction::clear() {
    mComposerStates.clear();
    mDisplayStates.clear();
    mListenerCallbacks.clear();
    mInputWindowCommands.clear();
    mContainsBuffer = false;
    mForceSynchronous = 0;
    mTransactionNestCount = 0;
    mAnimation = false;
    mEarlyWakeup = false;
    mExplicitEarlyWakeupStart = false;
    mExplicitEarlyWakeupEnd = false;
    mDesiredPresentTime = -1;
}

void SurfaceComposerClient::doUncacheBufferTransaction(uint64_t cacheId) {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());

    client_cache_t uncacheBuffer;
    uncacheBuffer.token = BufferCache::getInstance().getToken();
    uncacheBuffer.id = cacheId;

    sp<IBinder> applyToken = IInterface::asBinder(TransactionCompletedListener::getIInstance());
    sf->setTransactionState({}, {}, 0, applyToken, {}, -1, uncacheBuffer, false, {});
}

void SurfaceComposerClient::Transaction::cacheBuffers() {
    if (!mContainsBuffer) {
        return;
    }

    size_t count = 0;
    for (auto& [handle, cs] : mComposerStates) {
        layer_state_t* s = getLayerState(handle);
        if (!(s->what & layer_state_t::eBufferChanged)) {
            continue;
        } else if (s->what & layer_state_t::eCachedBufferChanged) {
            // If eBufferChanged and eCachedBufferChanged are both trued then that means
            // we already cached the buffer in a previous call to cacheBuffers, perhaps
            // from writeToParcel on a Transaction that was merged in to this one.
            continue;
        }

        // Don't try to cache a null buffer. Sending null buffers is cheap so we shouldn't waste
        // time trying to cache them.
        if (!s->buffer) {
            continue;
        }

        uint64_t cacheId = 0;
        status_t ret = BufferCache::getInstance().getCacheId(s->buffer, &cacheId);
        if (ret == NO_ERROR) {
            // Cache-hit. Strip the buffer and send only the id.
            s->what &= ~static_cast<uint64_t>(layer_state_t::eBufferChanged);
            s->buffer = nullptr;
        } else {
            // Cache-miss. Include the buffer and send the new cacheId.
            cacheId = BufferCache::getInstance().cache(s->buffer);
        }
        s->what |= layer_state_t::eCachedBufferChanged;
        s->cachedBuffer.token = BufferCache::getInstance().getToken();
        s->cachedBuffer.id = cacheId;

        // If we have more buffers than the size of the cache, we should stop caching so we don't
        // evict other buffers in this transaction
        count++;
        if (count >= BUFFER_CACHE_MAX_SIZE) {
            break;
        }
    }
}

status_t SurfaceComposerClient::Transaction::apply(bool synchronous) {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }

    sp<ISurfaceComposer> sf(ComposerService::getComposerService());

    bool hasListenerCallbacks = !mListenerCallbacks.empty();
    std::vector<ListenerCallbacks> listenerCallbacks;
    // For every listener with registered callbacks
    for (const auto& [listener, callbackInfo] : mListenerCallbacks) {
        auto& [callbackIds, surfaceControls] = callbackInfo;
        if (callbackIds.empty()) {
            continue;
        }

        if (surfaceControls.empty()) {
            listenerCallbacks.emplace_back(IInterface::asBinder(listener), std::move(callbackIds));
        } else {
            // If the listener has any SurfaceControls set on this Transaction update the surface
            // state
            for (const auto& surfaceControl : surfaceControls) {
                layer_state_t* s = getLayerState(surfaceControl);
                if (!s) {
                    ALOGE("failed to get layer state");
                    continue;
                }
                std::vector<CallbackId> callbacks(callbackIds.begin(), callbackIds.end());
                s->what |= layer_state_t::eHasListenerCallbacksChanged;
                s->listeners.emplace_back(IInterface::asBinder(listener), callbacks);
            }
        }
    }

    mListenerCallbacks.clear();

    cacheBuffers();

    Vector<ComposerState> composerStates;
    Vector<DisplayState> displayStates;
    uint32_t flags = 0;

    mForceSynchronous |= synchronous;

    for (auto const& kv : mComposerStates){
        composerStates.add(kv.second);
    }

    mComposerStates.clear();

    displayStates = mDisplayStates;
    mDisplayStates.clear();

    if (mForceSynchronous) {
        flags |= ISurfaceComposer::eSynchronous;
    }
    if (mAnimation) {
        flags |= ISurfaceComposer::eAnimation;
    }
    if (mEarlyWakeup) {
        flags |= ISurfaceComposer::eEarlyWakeup;
    }

    // If both mExplicitEarlyWakeupStart and mExplicitEarlyWakeupEnd are set
    // it is equivalent for none
    if (mExplicitEarlyWakeupStart && !mExplicitEarlyWakeupEnd) {
        flags |= ISurfaceComposer::eExplicitEarlyWakeupStart;
    }
    if (mExplicitEarlyWakeupEnd && !mExplicitEarlyWakeupStart) {
        flags |= ISurfaceComposer::eExplicitEarlyWakeupEnd;
    }

    mForceSynchronous = false;
    mAnimation = false;
    mEarlyWakeup = false;
    mExplicitEarlyWakeupStart = false;
    mExplicitEarlyWakeupEnd = false;

    sp<IBinder> applyToken = IInterface::asBinder(TransactionCompletedListener::getIInstance());
    sf->setTransactionState(composerStates, displayStates, flags, applyToken, mInputWindowCommands,
                            mDesiredPresentTime,
                            {} /*uncacheBuffer - only set in doUncacheBufferTransaction*/,
                            hasListenerCallbacks, listenerCallbacks);
    mInputWindowCommands.clear();
    mStatus = NO_ERROR;
    return NO_ERROR;
}

// ---------------------------------------------------------------------------

sp<IBinder> SurfaceComposerClient::createDisplay(const String8& displayName, bool secure) {
    return ComposerService::getComposerService()->createDisplay(displayName,
            secure);
}

void SurfaceComposerClient::destroyDisplay(const sp<IBinder>& display) {
    return ComposerService::getComposerService()->destroyDisplay(display);
}

std::vector<PhysicalDisplayId> SurfaceComposerClient::getPhysicalDisplayIds() {
    return ComposerService::getComposerService()->getPhysicalDisplayIds();
}

std::optional<PhysicalDisplayId> SurfaceComposerClient::getInternalDisplayId() {
    return ComposerService::getComposerService()->getInternalDisplayId();
}

sp<IBinder> SurfaceComposerClient::getPhysicalDisplayToken(PhysicalDisplayId displayId) {
    return ComposerService::getComposerService()->getPhysicalDisplayToken(displayId);
}

sp<IBinder> SurfaceComposerClient::getInternalDisplayToken() {
    return ComposerService::getComposerService()->getInternalDisplayToken();
}

void SurfaceComposerClient::Transaction::setAnimationTransaction() {
    mAnimation = true;
}

void SurfaceComposerClient::Transaction::setEarlyWakeup() {
    mEarlyWakeup = true;
}

void SurfaceComposerClient::Transaction::setExplicitEarlyWakeupStart() {
    mExplicitEarlyWakeupStart = true;
}

void SurfaceComposerClient::Transaction::setExplicitEarlyWakeupEnd() {
    mExplicitEarlyWakeupEnd = true;
}

layer_state_t* SurfaceComposerClient::Transaction::getLayerState(const sp<IBinder>& handle) {
    if (mComposerStates.count(handle) == 0) {
        // we don't have it, add an initialized layer_state to our list
        ComposerState s;
        s.state.surface = handle;
        mComposerStates[handle] = s;
    }

    return &(mComposerStates[handle].state);
}

void SurfaceComposerClient::Transaction::registerSurfaceControlForCallback(
        const sp<SurfaceControl>& sc) {
    auto& callbackInfo = mListenerCallbacks[TransactionCompletedListener::getIInstance()];
    callbackInfo.surfaceControls.insert(sc);

    TransactionCompletedListener::getInstance()
            ->addSurfaceControlToCallbacks(sc, callbackInfo.callbackIds);
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setPosition(
        const sp<SurfaceControl>& sc, float x, float y) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::ePositionChanged;
    s->x = x;
    s->y = y;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::show(
        const sp<SurfaceControl>& sc) {
    return setFlags(sc, 0, layer_state_t::eLayerHidden);
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::hide(
        const sp<SurfaceControl>& sc) {
    return setFlags(sc, layer_state_t::eLayerHidden, layer_state_t::eLayerHidden);
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setSize(
        const sp<SurfaceControl>& sc, uint32_t w, uint32_t h) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eSizeChanged;
    s->w = w;
    s->h = h;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setLayer(
        const sp<SurfaceControl>& sc, int32_t z) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eLayerChanged;
    s->what &= ~layer_state_t::eRelativeLayerChanged;
    s->z = z;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setRelativeLayer(const sp<SurfaceControl>& sc, const sp<IBinder>& relativeTo,
        int32_t z) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eRelativeLayerChanged;
    s->what &= ~layer_state_t::eLayerChanged;
    s->relativeLayerHandle = relativeTo;
    s->z = z;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setFlags(
        const sp<SurfaceControl>& sc, uint32_t flags,
        uint32_t mask) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    if ((mask & layer_state_t::eLayerOpaque) ||
            (mask & layer_state_t::eLayerHidden) ||
            (mask & layer_state_t::eLayerSecure)) {
        s->what |= layer_state_t::eFlagsChanged;
    }
    s->flags &= ~mask;
    s->flags |= (flags & mask);
    s->mask |= mask;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setTransparentRegionHint(
        const sp<SurfaceControl>& sc,
        const Region& transparentRegion) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eTransparentRegionChanged;
    s->transparentRegion = transparentRegion;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setAlpha(
        const sp<SurfaceControl>& sc, float alpha) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eAlphaChanged;
    s->alpha = alpha;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setLayerStack(
        const sp<SurfaceControl>& sc, uint32_t layerStack) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eLayerStackChanged;
    s->layerStack = layerStack;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setMetadata(
        const sp<SurfaceControl>& sc, uint32_t key, const Parcel& p) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eMetadataChanged;

    s->metadata.mMap[key] = {p.data(), p.data() + p.dataSize()};

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setMatrix(
        const sp<SurfaceControl>& sc, float dsdx, float dtdx,
        float dtdy, float dsdy) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eMatrixChanged;
    layer_state_t::matrix22_t matrix;
    matrix.dsdx = dsdx;
    matrix.dtdx = dtdx;
    matrix.dsdy = dsdy;
    matrix.dtdy = dtdy;
    s->matrix = matrix;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setCrop_legacy(
        const sp<SurfaceControl>& sc, const Rect& crop) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eCropChanged_legacy;
    s->crop_legacy = crop;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setCornerRadius(
        const sp<SurfaceControl>& sc, float cornerRadius) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eCornerRadiusChanged;
    s->cornerRadius = cornerRadius;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setBackgroundBlurRadius(
        const sp<SurfaceControl>& sc, int backgroundBlurRadius) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eBackgroundBlurRadiusChanged;
    s->backgroundBlurRadius = backgroundBlurRadius;
    return *this;
}

SurfaceComposerClient::Transaction&
SurfaceComposerClient::Transaction::deferTransactionUntil_legacy(const sp<SurfaceControl>& sc,
                                                                 const sp<IBinder>& handle,
                                                                 uint64_t frameNumber) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eDeferTransaction_legacy;
    s->barrierHandle_legacy = handle;
    s->frameNumber_legacy = frameNumber;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction&
SurfaceComposerClient::Transaction::deferTransactionUntil_legacy(const sp<SurfaceControl>& sc,
                                                                 const sp<Surface>& barrierSurface,
                                                                 uint64_t frameNumber) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eDeferTransaction_legacy;
    s->barrierGbp_legacy = barrierSurface->getIGraphicBufferProducer();
    s->frameNumber_legacy = frameNumber;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::reparentChildren(
        const sp<SurfaceControl>& sc,
        const sp<IBinder>& newParentHandle) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eReparentChildren;
    s->reparentHandle = newParentHandle;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::reparent(
        const sp<SurfaceControl>& sc,
        const sp<IBinder>& newParentHandle) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eReparent;
    s->parentHandleForChild = newParentHandle;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setColor(
        const sp<SurfaceControl>& sc,
        const half3& color) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eColorChanged;
    s->color = color;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setBackgroundColor(
        const sp<SurfaceControl>& sc, const half3& color, float alpha, ui::Dataspace dataspace) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eBackgroundColorChanged;
    s->color = color;
    s->bgColorAlpha = alpha;
    s->bgColorDataspace = dataspace;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setTransform(
        const sp<SurfaceControl>& sc, uint32_t transform) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eTransformChanged;
    s->transform = transform;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction&
SurfaceComposerClient::Transaction::setTransformToDisplayInverse(const sp<SurfaceControl>& sc,
                                                                 bool transformToDisplayInverse) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eTransformToDisplayInverseChanged;
    s->transformToDisplayInverse = transformToDisplayInverse;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setCrop(
        const sp<SurfaceControl>& sc, const Rect& crop) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eCropChanged;
    s->crop = crop;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setFrame(
        const sp<SurfaceControl>& sc, const Rect& frame) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eFrameChanged;
    s->frame = frame;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setBuffer(
        const sp<SurfaceControl>& sc, const sp<GraphicBuffer>& buffer) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eBufferChanged;
    s->buffer = buffer;

    registerSurfaceControlForCallback(sc);

    mContainsBuffer = true;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setAcquireFence(
        const sp<SurfaceControl>& sc, const sp<Fence>& fence) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eAcquireFenceChanged;
    s->acquireFence = fence;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setDataspace(
        const sp<SurfaceControl>& sc, ui::Dataspace dataspace) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eDataspaceChanged;
    s->dataspace = dataspace;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setHdrMetadata(
        const sp<SurfaceControl>& sc, const HdrMetadata& hdrMetadata) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eHdrMetadataChanged;
    s->hdrMetadata = hdrMetadata;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setSurfaceDamageRegion(
        const sp<SurfaceControl>& sc, const Region& surfaceDamageRegion) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eSurfaceDamageRegionChanged;
    s->surfaceDamageRegion = surfaceDamageRegion;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setApi(
        const sp<SurfaceControl>& sc, int32_t api) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eApiChanged;
    s->api = api;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setSidebandStream(
        const sp<SurfaceControl>& sc, const sp<NativeHandle>& sidebandStream) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eSidebandStreamChanged;
    s->sidebandStream = sidebandStream;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setDesiredPresentTime(
        nsecs_t desiredPresentTime) {
    mDesiredPresentTime = desiredPresentTime;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setColorSpaceAgnostic(
        const sp<SurfaceControl>& sc, const bool agnostic) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eColorSpaceAgnosticChanged;
    s->colorSpaceAgnostic = agnostic;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction&
SurfaceComposerClient::Transaction::setFrameRateSelectionPriority(const sp<SurfaceControl>& sc,
                                                                  int32_t priority) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eFrameRateSelectionPriority;
    s->frameRateSelectionPriority = priority;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction&
SurfaceComposerClient::Transaction::addTransactionCompletedCallback(
        TransactionCompletedCallbackTakesContext callback, void* callbackContext) {
    auto listener = TransactionCompletedListener::getInstance();

    auto callbackWithContext = std::bind(callback, callbackContext, std::placeholders::_1,
                                         std::placeholders::_2, std::placeholders::_3);
    const auto& surfaceControls =
            mListenerCallbacks[TransactionCompletedListener::getIInstance()].surfaceControls;

    CallbackId callbackId = listener->addCallbackFunction(callbackWithContext, surfaceControls);

    mListenerCallbacks[TransactionCompletedListener::getIInstance()].callbackIds.emplace(
            callbackId);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::notifyProducerDisconnect(
        const sp<SurfaceControl>& sc) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eProducerDisconnect;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::detachChildren(
        const sp<SurfaceControl>& sc) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eDetachChildren;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setOverrideScalingMode(
        const sp<SurfaceControl>& sc, int32_t overrideScalingMode) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    switch (overrideScalingMode) {
        case NATIVE_WINDOW_SCALING_MODE_FREEZE:
        case NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW:
        case NATIVE_WINDOW_SCALING_MODE_SCALE_CROP:
        case NATIVE_WINDOW_SCALING_MODE_NO_SCALE_CROP:
        case -1:
            break;
        default:
            ALOGE("unknown scaling mode: %d",
                    overrideScalingMode);
            mStatus = BAD_VALUE;
            return *this;
    }

    s->what |= layer_state_t::eOverrideScalingModeChanged;
    s->overrideScalingMode = overrideScalingMode;

    registerSurfaceControlForCallback(sc);
    return *this;
}

#ifndef NO_INPUT
SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setInputWindowInfo(
        const sp<SurfaceControl>& sc,
        const InputWindowInfo& info) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->inputInfo = info;
    s->what |= layer_state_t::eInputInfoChanged;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::syncInputWindows() {
    mInputWindowCommands.syncInputWindows = true;
    return *this;
}

#endif

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setColorTransform(
    const sp<SurfaceControl>& sc, const mat3& matrix, const vec3& translation) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eColorTransformChanged;
    s->colorTransform = mat4(matrix, translation);

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setGeometry(
        const sp<SurfaceControl>& sc, const Rect& source, const Rect& dst, int transform) {
    setCrop_legacy(sc, source);

    int x = dst.left;
    int y = dst.top;

    float sourceWidth = source.getWidth();
    float sourceHeight = source.getHeight();

    float xScale = sourceWidth < 0 ? 1.0f : dst.getWidth() / sourceWidth;
    float yScale = sourceHeight < 0 ? 1.0f : dst.getHeight() / sourceHeight;
    float matrix[4] = {1, 0, 0, 1};

    switch (transform) {
        case NATIVE_WINDOW_TRANSFORM_FLIP_H:
            matrix[0] = -xScale; matrix[1] = 0;
            matrix[2] = 0; matrix[3] = yScale;
            x += source.getWidth();
            break;
        case NATIVE_WINDOW_TRANSFORM_FLIP_V:
            matrix[0] = xScale; matrix[1] = 0;
            matrix[2] = 0; matrix[3] = -yScale;
            y += source.getHeight();
            break;
        case NATIVE_WINDOW_TRANSFORM_ROT_90:
            matrix[0] = 0; matrix[1] = -yScale;
            matrix[2] = xScale; matrix[3] = 0;
            x += source.getHeight();
            break;
        case NATIVE_WINDOW_TRANSFORM_ROT_180:
            matrix[0] = -xScale; matrix[1] = 0;
            matrix[2] = 0; matrix[3] = -yScale;
            x += source.getWidth();
            y += source.getHeight();
            break;
        case NATIVE_WINDOW_TRANSFORM_ROT_270:
            matrix[0] = 0; matrix[1] = yScale;
            matrix[2] = -xScale; matrix[3] = 0;
            y += source.getWidth();
            break;
        default:
            matrix[0] = xScale; matrix[1] = 0;
            matrix[2] = 0; matrix[3] = yScale;
            break;
    }
    setMatrix(sc, matrix[0], matrix[1], matrix[2], matrix[3]);
    float offsetX = xScale * source.left;
    float offsetY = yScale * source.top;
    setPosition(sc, x - offsetX, y - offsetY);

    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setShadowRadius(
        const sp<SurfaceControl>& sc, float shadowRadius) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eShadowRadiusChanged;
    s->shadowRadius = shadowRadius;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setFrameRate(
        const sp<SurfaceControl>& sc, float frameRate, int8_t compatibility) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    if (!ValidateFrameRate(frameRate, compatibility, "Transaction::setFrameRate")) {
        mStatus = BAD_VALUE;
        return *this;
    }
    s->what |= layer_state_t::eFrameRateChanged;
    s->frameRate = frameRate;
    s->frameRateCompatibility = compatibility;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setFixedTransformHint(
        const sp<SurfaceControl>& sc, int32_t fixedTransformHint) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    const ui::Transform::RotationFlags transform = fixedTransformHint == -1
            ? ui::Transform::ROT_INVALID
            : ui::Transform::toRotationFlags(static_cast<ui::Rotation>(fixedTransformHint));
    s->what |= layer_state_t::eFixedTransformHintChanged;
    s->fixedTransformHint = transform;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setTrustedOverlay(
        const sp<SurfaceControl>& sc, bool isTrustedOverlay) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eTrustedOverlayChanged;
    s->isTrustedOverlay = isTrustedOverlay;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setDropInputMode(
        const sp<SurfaceControl>& sc, gui::DropInputMode mode) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eDropInputModeChanged;
    s->dropInputMode = mode;

    registerSurfaceControlForCallback(sc);
    return *this;
}

// ---------------------------------------------------------------------------

DisplayState& SurfaceComposerClient::Transaction::getDisplayState(const sp<IBinder>& token) {
    DisplayState s;
    s.token = token;
    ssize_t index = mDisplayStates.indexOf(s);
    if (index < 0) {
        // we don't have it, add an initialized layer_state to our list
        s.what = 0;
        index = mDisplayStates.add(s);
    }
    return mDisplayStates.editItemAt(static_cast<size_t>(index));
}

status_t SurfaceComposerClient::Transaction::setDisplaySurface(const sp<IBinder>& token,
        const sp<IGraphicBufferProducer>& bufferProducer) {
    if (bufferProducer.get() != nullptr) {
        // Make sure that composition can never be stalled by a virtual display
        // consumer that isn't processing buffers fast enough.
        status_t err = bufferProducer->setAsyncMode(true);
        if (err != NO_ERROR) {
            ALOGE("Composer::setDisplaySurface Failed to enable async mode on the "
                    "BufferQueue. This BufferQueue cannot be used for virtual "
                    "display. (%d)", err);
            return err;
        }
    }
    DisplayState& s(getDisplayState(token));
    s.surface = bufferProducer;
    s.what |= DisplayState::eSurfaceChanged;
    return NO_ERROR;
}

void SurfaceComposerClient::Transaction::setDisplayLayerStack(const sp<IBinder>& token,
        uint32_t layerStack) {
    DisplayState& s(getDisplayState(token));
    s.layerStack = layerStack;
    s.what |= DisplayState::eLayerStackChanged;
}

void SurfaceComposerClient::Transaction::setDisplayProjection(const sp<IBinder>& token,
                                                              ui::Rotation orientation,
                                                              const Rect& layerStackRect,
                                                              const Rect& displayRect) {
    DisplayState& s(getDisplayState(token));
    s.orientation = orientation;
    s.viewport = layerStackRect;
    s.frame = displayRect;
    s.what |= DisplayState::eDisplayProjectionChanged;
    mForceSynchronous = true; // TODO: do we actually still need this?
}

void SurfaceComposerClient::Transaction::setDisplaySize(const sp<IBinder>& token, uint32_t width, uint32_t height) {
    DisplayState& s(getDisplayState(token));
    s.width = width;
    s.height = height;
    s.what |= DisplayState::eDisplaySizeChanged;
}

// ---------------------------------------------------------------------------

SurfaceComposerClient::SurfaceComposerClient()
    : mStatus(NO_INIT)
{
}

SurfaceComposerClient::SurfaceComposerClient(const sp<ISurfaceComposerClient>& client)
    : mStatus(NO_ERROR), mClient(client)
{
}

void SurfaceComposerClient::onFirstRef() {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    if (sf != nullptr && mStatus == NO_INIT) {
        sp<ISurfaceComposerClient> conn;
        conn = sf->createConnection();
        if (conn != nullptr) {
            mClient = conn;
            mStatus = NO_ERROR;
        }
    }
}

SurfaceComposerClient::~SurfaceComposerClient() {
    dispose();
}

status_t SurfaceComposerClient::initCheck() const {
    return mStatus;
}

sp<IBinder> SurfaceComposerClient::connection() const {
    return IInterface::asBinder(mClient);
}

status_t SurfaceComposerClient::linkToComposerDeath(
        const sp<IBinder::DeathRecipient>& recipient,
        void* cookie, uint32_t flags) {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    return IInterface::asBinder(sf)->linkToDeath(recipient, cookie, flags);
}

void SurfaceComposerClient::dispose() {
    // this can be called more than once.
    sp<ISurfaceComposerClient> client;
    Mutex::Autolock _lm(mLock);
    if (mClient != nullptr) {
        client = mClient; // hold ref while lock is held
        mClient.clear();
    }
    mStatus = NO_INIT;
}

sp<SurfaceControl> SurfaceComposerClient::createSurface(const String8& name, uint32_t w, uint32_t h,
                                                        PixelFormat format, uint32_t flags,
                                                        SurfaceControl* parent,
                                                        LayerMetadata metadata,
                                                        uint32_t* outTransformHint) {
    sp<SurfaceControl> s;
    createSurfaceChecked(name, w, h, format, &s, flags, parent, std::move(metadata),
                         outTransformHint);
    return s;
}

sp<SurfaceControl> SurfaceComposerClient::createWithSurfaceParent(const String8& name, uint32_t w,
                                                                  uint32_t h, PixelFormat format,
                                                                  uint32_t flags, Surface* parent,
                                                                  LayerMetadata metadata,
                                                                  uint32_t* outTransformHint) {
    sp<SurfaceControl> sur;
    status_t err = mStatus;

    if (mStatus == NO_ERROR) {
        sp<IBinder> handle;
        sp<IGraphicBufferProducer> parentGbp = parent->getIGraphicBufferProducer();
        sp<IGraphicBufferProducer> gbp;

        uint32_t transformHint = 0;
        err = mClient->createWithSurfaceParent(name, w, h, format, flags, parentGbp,
                                               std::move(metadata), &handle, &gbp, &transformHint);
        if (outTransformHint) {
            *outTransformHint = transformHint;
        }
        ALOGE_IF(err, "SurfaceComposerClient::createWithSurfaceParent error %s", strerror(-err));
        if (err == NO_ERROR) {
            return new SurfaceControl(this, handle, gbp, transformHint);
        }
    }
    return nullptr;
}

status_t SurfaceComposerClient::createSurfaceChecked(const String8& name, uint32_t w, uint32_t h,
                                                     PixelFormat format,
                                                     sp<SurfaceControl>* outSurface, uint32_t flags,
                                                     SurfaceControl* parent, LayerMetadata metadata,
                                                     uint32_t* outTransformHint) {
    sp<SurfaceControl> sur;
    status_t err = mStatus;

    if (mStatus == NO_ERROR) {
        sp<IBinder> handle;
        sp<IBinder> parentHandle;
        sp<IGraphicBufferProducer> gbp;

        if (parent != nullptr) {
            parentHandle = parent->getHandle();
        }

        uint32_t transformHint = 0;
        err = mClient->createSurface(name, w, h, format, flags, parentHandle, std::move(metadata),
                                     &handle, &gbp, &transformHint);
        if (outTransformHint) {
            *outTransformHint = transformHint;
        }
        ALOGE_IF(err, "SurfaceComposerClient::createSurface error %s", strerror(-err));
        if (err == NO_ERROR) {
            *outSurface = new SurfaceControl(this, handle, gbp, transformHint);
        }
    }
    return err;
}

sp<SurfaceControl> SurfaceComposerClient::mirrorSurface(SurfaceControl* mirrorFromSurface) {
    if (mirrorFromSurface == nullptr) {
        return nullptr;
    }

    sp<IBinder> handle;
    sp<IBinder> mirrorFromHandle = mirrorFromSurface->getHandle();
    status_t err = mClient->mirrorSurface(mirrorFromHandle, &handle);
    if (err == NO_ERROR) {
        return new SurfaceControl(this, handle, nullptr, true /* owned */);
    }
    return nullptr;
}

status_t SurfaceComposerClient::clearLayerFrameStats(const sp<IBinder>& token) const {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    return mClient->clearLayerFrameStats(token);
}

status_t SurfaceComposerClient::getLayerFrameStats(const sp<IBinder>& token,
        FrameStats* outStats) const {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    return mClient->getLayerFrameStats(token, outStats);
}

// ----------------------------------------------------------------------------

status_t SurfaceComposerClient::enableVSyncInjections(bool enable) {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    return sf->enableVSyncInjections(enable);
}

status_t SurfaceComposerClient::injectVSync(nsecs_t when) {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    return sf->injectVSync(when);
}

status_t SurfaceComposerClient::getDisplayState(const sp<IBinder>& display,
                                                ui::DisplayState* state) {
    return ComposerService::getComposerService()->getDisplayState(display, state);
}

status_t SurfaceComposerClient::getDisplayInfo(const sp<IBinder>& display, DisplayInfo* info) {
    return ComposerService::getComposerService()->getDisplayInfo(display, info);
}

status_t SurfaceComposerClient::getDisplayConfigs(const sp<IBinder>& display,
                                                  Vector<DisplayConfig>* configs) {
    return ComposerService::getComposerService()->getDisplayConfigs(display, configs);
}

status_t SurfaceComposerClient::getActiveDisplayConfig(const sp<IBinder>& display,
                                                       DisplayConfig* config) {
    Vector<DisplayConfig> configs;
    status_t result = getDisplayConfigs(display, &configs);
    if (result != NO_ERROR) {
        return result;
    }

    int activeId = getActiveConfig(display);
    if (activeId < 0) {
        ALOGE("No active configuration found");
        return NAME_NOT_FOUND;
    }

    *config = configs[static_cast<size_t>(activeId)];
    return NO_ERROR;
}

int SurfaceComposerClient::getActiveConfig(const sp<IBinder>& display) {
    return ComposerService::getComposerService()->getActiveConfig(display);
}

status_t SurfaceComposerClient::setDesiredDisplayConfigSpecs(const sp<IBinder>& displayToken,
                                                             int32_t defaultConfig,
                                                             float primaryRefreshRateMin,
                                                             float primaryRefreshRateMax,
                                                             float appRequestRefreshRateMin,
                                                             float appRequestRefreshRateMax) {
    return ComposerService::getComposerService()
            ->setDesiredDisplayConfigSpecs(displayToken, defaultConfig, primaryRefreshRateMin,
                                           primaryRefreshRateMax, appRequestRefreshRateMin,
                                           appRequestRefreshRateMax);
}

status_t SurfaceComposerClient::getDesiredDisplayConfigSpecs(const sp<IBinder>& displayToken,
                                                             int32_t* outDefaultConfig,
                                                             float* outPrimaryRefreshRateMin,
                                                             float* outPrimaryRefreshRateMax,
                                                             float* outAppRequestRefreshRateMin,
                                                             float* outAppRequestRefreshRateMax) {
    return ComposerService::getComposerService()
            ->getDesiredDisplayConfigSpecs(displayToken, outDefaultConfig, outPrimaryRefreshRateMin,
                                           outPrimaryRefreshRateMax, outAppRequestRefreshRateMin,
                                           outAppRequestRefreshRateMax);
}

status_t SurfaceComposerClient::getDisplayColorModes(const sp<IBinder>& display,
        Vector<ColorMode>* outColorModes) {
    return ComposerService::getComposerService()->getDisplayColorModes(display, outColorModes);
}

status_t SurfaceComposerClient::getDisplayNativePrimaries(const sp<IBinder>& display,
        ui::DisplayPrimaries& outPrimaries) {
    return ComposerService::getComposerService()->getDisplayNativePrimaries(display, outPrimaries);
}

ColorMode SurfaceComposerClient::getActiveColorMode(const sp<IBinder>& display) {
    return ComposerService::getComposerService()->getActiveColorMode(display);
}

status_t SurfaceComposerClient::setActiveColorMode(const sp<IBinder>& display,
        ColorMode colorMode) {
    return ComposerService::getComposerService()->setActiveColorMode(display, colorMode);
}

bool SurfaceComposerClient::getAutoLowLatencyModeSupport(const sp<IBinder>& display) {
    bool supported = false;
    ComposerService::getComposerService()->getAutoLowLatencyModeSupport(display, &supported);
    return supported;
}

void SurfaceComposerClient::setAutoLowLatencyMode(const sp<IBinder>& display, bool on) {
    ComposerService::getComposerService()->setAutoLowLatencyMode(display, on);
}

bool SurfaceComposerClient::getGameContentTypeSupport(const sp<IBinder>& display) {
    bool supported = false;
    ComposerService::getComposerService()->getGameContentTypeSupport(display, &supported);
    return supported;
}

void SurfaceComposerClient::setGameContentType(const sp<IBinder>& display, bool on) {
    ComposerService::getComposerService()->setGameContentType(display, on);
}

void SurfaceComposerClient::setDisplayPowerMode(const sp<IBinder>& token,
        int mode) {
    ComposerService::getComposerService()->setPowerMode(token, mode);
}

status_t SurfaceComposerClient::getCompositionPreference(
        ui::Dataspace* defaultDataspace, ui::PixelFormat* defaultPixelFormat,
        ui::Dataspace* wideColorGamutDataspace, ui::PixelFormat* wideColorGamutPixelFormat) {
    return ComposerService::getComposerService()
            ->getCompositionPreference(defaultDataspace, defaultPixelFormat,
                                       wideColorGamutDataspace, wideColorGamutPixelFormat);
}

bool SurfaceComposerClient::getProtectedContentSupport() {
    bool supported = false;
    ComposerService::getComposerService()->getProtectedContentSupport(&supported);
    return supported;
}

status_t SurfaceComposerClient::clearAnimationFrameStats() {
    return ComposerService::getComposerService()->clearAnimationFrameStats();
}

status_t SurfaceComposerClient::getAnimationFrameStats(FrameStats* outStats) {
    return ComposerService::getComposerService()->getAnimationFrameStats(outStats);
}

status_t SurfaceComposerClient::getHdrCapabilities(const sp<IBinder>& display,
        HdrCapabilities* outCapabilities) {
    return ComposerService::getComposerService()->getHdrCapabilities(display,
            outCapabilities);
}

status_t SurfaceComposerClient::getDisplayedContentSamplingAttributes(const sp<IBinder>& display,
                                                                      ui::PixelFormat* outFormat,
                                                                      ui::Dataspace* outDataspace,
                                                                      uint8_t* outComponentMask) {
    return ComposerService::getComposerService()
            ->getDisplayedContentSamplingAttributes(display, outFormat, outDataspace,
                                                    outComponentMask);
}

status_t SurfaceComposerClient::setDisplayContentSamplingEnabled(const sp<IBinder>& display,
                                                                 bool enable, uint8_t componentMask,
                                                                 uint64_t maxFrames) {
    return ComposerService::getComposerService()->setDisplayContentSamplingEnabled(display, enable,
                                                                                   componentMask,
                                                                                   maxFrames);
}

status_t SurfaceComposerClient::getDisplayedContentSample(const sp<IBinder>& display,
                                                          uint64_t maxFrames, uint64_t timestamp,
                                                          DisplayedFrameStats* outStats) {
    return ComposerService::getComposerService()->getDisplayedContentSample(display, maxFrames,
                                                                            timestamp, outStats);
}

status_t SurfaceComposerClient::isWideColorDisplay(const sp<IBinder>& display,
                                                   bool* outIsWideColorDisplay) {
    return ComposerService::getComposerService()->isWideColorDisplay(display,
                                                                     outIsWideColorDisplay);
}

status_t SurfaceComposerClient::addRegionSamplingListener(
        const Rect& samplingArea, const sp<IBinder>& stopLayerHandle,
        const sp<IRegionSamplingListener>& listener) {
    return ComposerService::getComposerService()->addRegionSamplingListener(samplingArea,
                                                                            stopLayerHandle,
                                                                            listener);
}

status_t SurfaceComposerClient::removeRegionSamplingListener(
        const sp<IRegionSamplingListener>& listener) {
    return ComposerService::getComposerService()->removeRegionSamplingListener(listener);
}

bool SurfaceComposerClient::getDisplayBrightnessSupport(const sp<IBinder>& displayToken) {
    bool support = false;
    ComposerService::getComposerService()->getDisplayBrightnessSupport(displayToken, &support);
    return support;
}

status_t SurfaceComposerClient::setDisplayBrightness(const sp<IBinder>& displayToken,
                                                     float brightness) {
    return ComposerService::getComposerService()->setDisplayBrightness(displayToken, brightness);
}

status_t SurfaceComposerClient::notifyPowerHint(int32_t hintId) {
    return ComposerService::getComposerService()->notifyPowerHint(hintId);
}

status_t SurfaceComposerClient::setGlobalShadowSettings(const half4& ambientColor,
                                                        const half4& spotColor, float lightPosY,
                                                        float lightPosZ, float lightRadius) {
    return ComposerService::getComposerService()->setGlobalShadowSettings(ambientColor, spotColor,
                                                                          lightPosY, lightPosZ,
                                                                          lightRadius);
}

// ----------------------------------------------------------------------------

status_t ScreenshotClient::capture(const sp<IBinder>& display, ui::Dataspace reqDataSpace,
                                   ui::PixelFormat reqPixelFormat, const Rect& sourceCrop,
                                   uint32_t reqWidth, uint32_t reqHeight, bool useIdentityTransform,
                                   ui::Rotation rotation, bool captureSecureLayers,
                                   sp<GraphicBuffer>* outBuffer, bool& outCapturedSecureLayers) {
    sp<ISurfaceComposer> s(ComposerService::getComposerService());
    if (s == nullptr) return NO_INIT;
    status_t ret = s->captureScreen(display, outBuffer, outCapturedSecureLayers, reqDataSpace,
                                    reqPixelFormat, sourceCrop, reqWidth, reqHeight,
                                    useIdentityTransform, rotation, captureSecureLayers);
    if (ret != NO_ERROR) {
        return ret;
    }
    return ret;
}

status_t ScreenshotClient::capture(const sp<IBinder>& display, ui::Dataspace reqDataSpace,
                                   ui::PixelFormat reqPixelFormat, const Rect& sourceCrop,
                                   uint32_t reqWidth, uint32_t reqHeight, bool useIdentityTransform,
                                   ui::Rotation rotation, sp<GraphicBuffer>* outBuffer) {
    bool ignored;
    return capture(display, reqDataSpace, reqPixelFormat, sourceCrop, reqWidth, reqHeight,
                   useIdentityTransform, rotation, false, outBuffer, ignored);
}

status_t ScreenshotClient::capture(uint64_t displayOrLayerStack, ui::Dataspace* outDataspace,
                                   sp<GraphicBuffer>* outBuffer) {
    sp<ISurfaceComposer> s(ComposerService::getComposerService());
    if (s == nullptr) return NO_INIT;
    return s->captureScreen(displayOrLayerStack, outDataspace, outBuffer);
}

status_t ScreenshotClient::captureLayers(const sp<IBinder>& layerHandle, ui::Dataspace reqDataSpace,
                                         ui::PixelFormat reqPixelFormat, const Rect& sourceCrop,
                                         float frameScale, sp<GraphicBuffer>* outBuffer) {
    sp<ISurfaceComposer> s(ComposerService::getComposerService());
    if (s == nullptr) return NO_INIT;
    status_t ret = s->captureLayers(layerHandle, outBuffer, reqDataSpace, reqPixelFormat,
                                    sourceCrop, {}, frameScale, false /* childrenOnly */);
    return ret;
}

status_t ScreenshotClient::captureChildLayers(
        const sp<IBinder>& layerHandle, ui::Dataspace reqDataSpace, ui::PixelFormat reqPixelFormat,
        const Rect& sourceCrop,
        const std::unordered_set<sp<IBinder>, ISurfaceComposer::SpHash<IBinder>>& excludeHandles,
        float frameScale, sp<GraphicBuffer>* outBuffer) {
    sp<ISurfaceComposer> s(ComposerService::getComposerService());
    if (s == nullptr) return NO_INIT;
    status_t ret =
            s->captureLayers(layerHandle, outBuffer, reqDataSpace, reqPixelFormat, sourceCrop,
                             excludeHandles, frameScale, true /* childrenOnly */);
    return ret;
}

} // namespace android
