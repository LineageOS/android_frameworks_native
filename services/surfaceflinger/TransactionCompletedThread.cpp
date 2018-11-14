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
    if (mRunning) {
        return;
    }
    mDeathRecipient = new ThreadDeathRecipient();
    mRunning = true;
    mThread = std::thread(&TransactionCompletedThread::threadMain, this);
}

void TransactionCompletedThread::registerPendingLatchedCallbackHandle(
        const sp<CallbackHandle>& handle) {
    std::lock_guard lock(mMutex);

    sp<IBinder> listener = IInterface::asBinder(handle->listener);
    const auto& callbackIds = handle->callbackIds;

    mPendingTransactions[listener][callbackIds]++;
}

void TransactionCompletedThread::addLatchedCallbackHandles(
        const std::deque<sp<CallbackHandle>>& handles, nsecs_t latchTime,
        const sp<Fence>& previousReleaseFence) {
    std::lock_guard lock(mMutex);

    // If the previous release fences have not signaled, something as probably gone wrong.
    // Store the fences and check them again before sending a callback.
    if (previousReleaseFence &&
        previousReleaseFence->getSignalTime() == Fence::SIGNAL_TIME_PENDING) {
        ALOGD("release fence from the previous frame has not signaled");
        mPreviousReleaseFences.push_back(previousReleaseFence);
    }

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

        addCallbackHandle(handle, latchTime);
    }
}

void TransactionCompletedThread::addUnlatchedCallbackHandle(const sp<CallbackHandle>& handle) {
    std::lock_guard lock(mMutex);
    addCallbackHandle(handle);
}

void TransactionCompletedThread::addCallbackHandle(const sp<CallbackHandle>& handle,
                                                   nsecs_t latchTime) {
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
    transactionStats.latchTime = latchTime;
    transactionStats.surfaceStats.emplace_back(handle->surfaceControl, handle->acquireTime,
                                               handle->releasePreviousBuffer);
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

        // Present fence should fire almost immediately. If the fence has not signaled in 100ms,
        // there is a major problem and it will probably never fire.
        nsecs_t presentTime = -1;
        if (mPresentFence) {
            status_t status = mPresentFence->wait(100);
            if (status == NO_ERROR) {
                presentTime = mPresentFence->getSignalTime();
            } else {
                ALOGE("present fence has not signaled, err %d", status);
            }
        }

        // We should never hit this case. The release fences from the previous frame should have
        // signaled long before the current frame is presented.
        for (const auto& fence : mPreviousReleaseFences) {
            status_t status = fence->wait(100);
            if (status != NO_ERROR) {
                ALOGE("previous release fence has not signaled, err %d", status);
            }
        }

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
                    // If the present time is < 0, this transaction has been latched but not
                    // presented. Skip it for now. This can happen when a new transaction comes
                    // in between the latch and present steps. sendCallbacks is called by
                    // SurfaceFlinger when the transaction is received to ensure that if the
                    // transaction that didn't update state it still got a callback.
                    if (presentTime < 0) {
                        sendCallback = false;
                        break;
                    }

                    transactionStats.presentTime = presentTime;
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
            mPreviousReleaseFences.clear();
        }
    }
}

// -----------------------------------------------------------------------

CallbackHandle::CallbackHandle(const sp<ITransactionCompletedListener>& transactionListener,
                               const std::vector<CallbackId>& ids, const sp<IBinder>& sc)
      : listener(transactionListener), callbackIds(ids), surfaceControl(sc) {}

} // namespace android
