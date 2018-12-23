/*
 * Copyright 2018 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "TransactionCompletedThread"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "TransactionCompletedThread.h"

#include <cinttypes>

#include <binder/IInterface.h>
#include <gui/ITransactionCompletedListener.h>
#include <utils/RefBase.h>

namespace android {

TransactionCompletedThread::~TransactionCompletedThread() {
    std::lock_guard lockThread(mThreadMutex);

    {
        std::lock_guard lock(mMutex);
        mKeepRunning = false;
        mConditionVariable.notify_all();
    }

    if (mThread.joinable()) {
        mThread.join();
    }

    {
        std::lock_guard lock(mMutex);
        for (const auto& [listener, listenerStats] : mListenerStats) {
            listener->unlinkToDeath(mDeathRecipient);
        }
    }
}

void TransactionCompletedThread::run() {
    std::lock_guard lock(mMutex);
    if (mRunning || !mKeepRunning) {
        return;
    }
    mDeathRecipient = new ThreadDeathRecipient();
    mRunning = true;

    std::lock_guard lockThread(mThreadMutex);
    mThread = std::thread(&TransactionCompletedThread::threadMain, this);
}

void TransactionCompletedThread::registerPendingCallbackHandle(const sp<CallbackHandle>& handle) {
    std::lock_guard lock(mMutex);

    sp<IBinder> listener = IInterface::asBinder(handle->listener);
    const auto& callbackIds = handle->callbackIds;

    mPendingTransactions[listener][callbackIds]++;
}

void TransactionCompletedThread::addPresentedCallbackHandles(
        const std::deque<sp<CallbackHandle>>& handles) {
    std::lock_guard lock(mMutex);

    for (const auto& handle : handles) {
        auto listener = mPendingTransactions.find(IInterface::asBinder(handle->listener));
        auto& pendingCallbacks = listener->second;
        auto pendingCallback = pendingCallbacks.find(handle->callbackIds);

        if (pendingCallback != pendingCallbacks.end()) {
            auto& pendingCount = pendingCallback->second;

            // Decrease the pending count for this listener
            if (--pendingCount == 0) {
                pendingCallbacks.erase(pendingCallback);
            }
        } else {
            ALOGE("there are more latched callbacks than there were registered callbacks");
        }

        addCallbackHandle(handle);
    }
}

void TransactionCompletedThread::addUnpresentedCallbackHandle(const sp<CallbackHandle>& handle) {
    std::lock_guard lock(mMutex);
    addCallbackHandle(handle);
}

void TransactionCompletedThread::addCallbackHandle(const sp<CallbackHandle>& handle) {
    const sp<IBinder> listener = IInterface::asBinder(handle->listener);

    // If we don't already have a reference to this listener, linkToDeath so we get a notification
    // if it dies.
    if (mListenerStats.count(listener) == 0) {
        status_t error = listener->linkToDeath(mDeathRecipient);
        if (error != NO_ERROR) {
            ALOGE("cannot add callback handle because linkToDeath failed, err: %d", error);
            return;
        }
    }

    auto& listenerStats = mListenerStats[listener];
    listenerStats.listener = handle->listener;

    auto& transactionStats = listenerStats.transactionStats[handle->callbackIds];
    transactionStats.latchTime = handle->latchTime;
    transactionStats.surfaceStats.emplace_back(handle->surfaceControl, handle->acquireTime,
                                               handle->previousReleaseFence);
}

void TransactionCompletedThread::addPresentFence(const sp<Fence>& presentFence) {
    std::lock_guard<std::mutex> lock(mMutex);
    mPresentFence = presentFence;
}

void TransactionCompletedThread::sendCallbacks() {
    std::lock_guard lock(mMutex);
    if (mRunning) {
        mConditionVariable.notify_all();
    }
}

void TransactionCompletedThread::threadMain() {
    std::lock_guard lock(mMutex);

    while (mKeepRunning) {
        mConditionVariable.wait(mMutex);

        // For each listener
        auto it = mListenerStats.begin();
        while (it != mListenerStats.end()) {
            auto& [listener, listenerStats] = *it;

            // For each transaction
            bool sendCallback = true;
            for (auto& [callbackIds, transactionStats] : listenerStats.transactionStats) {
                // If we are still waiting on the callback handles for this transaction, skip it
                if (mPendingTransactions[listener].count(callbackIds) != 0) {
                    sendCallback = false;
                    break;
                }

                // If the transaction has been latched
                if (transactionStats.latchTime >= 0) {
                    if (!mPresentFence) {
                        sendCallback = false;
                        break;
                    }
                    transactionStats.presentFence = mPresentFence;
                }
            }
            // If the listener has no pending transactions and all latched transactions have been
            // presented
            if (sendCallback) {
                // If the listener is still alive
                if (listener->isBinderAlive()) {
                    // Send callback
                    listenerStats.listener->onTransactionCompleted(listenerStats);
                    listener->unlinkToDeath(mDeathRecipient);
                }
                it = mListenerStats.erase(it);
            } else {
                it++;
            }
        }

        if (mPresentFence) {
            mPresentFence.clear();
        }
    }
}

// -----------------------------------------------------------------------

CallbackHandle::CallbackHandle(const sp<ITransactionCompletedListener>& transactionListener,
                               const std::vector<CallbackId>& ids, const sp<IBinder>& sc)
      : listener(transactionListener), callbackIds(ids), surfaceControl(sc) {}

} // namespace android
