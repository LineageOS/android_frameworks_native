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

#pragma once

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <android-base/thread_annotations.h>

#include <binder/IBinder.h>
#include <gui/ITransactionCompletedListener.h>
#include <ui/Fence.h>

namespace android {

class CallbackHandle : public RefBase {
public:
    CallbackHandle(const sp<ITransactionCompletedListener>& transactionListener,
                   const std::vector<CallbackId>& ids, const sp<IBinder>& sc);

    sp<ITransactionCompletedListener> listener;
    std::vector<CallbackId> callbackIds;
    sp<IBinder> surfaceControl;

    bool releasePreviousBuffer = false;
    nsecs_t acquireTime = -1;
};

class TransactionCompletedThread {
public:
    ~TransactionCompletedThread();

    void run();

    // Informs the TransactionCompletedThread that there is a Transaction with a CallbackHandle
    // that needs to be latched and presented this frame. This function should be called once the
    // layer has received the CallbackHandle so the TransactionCompletedThread knows not to send
    // a callback for that Listener/Transaction pair until that CallbackHandle has been latched and
    // presented.
    void registerPendingLatchedCallbackHandle(const sp<CallbackHandle>& handle);
    // Notifies the TransactionCompletedThread that a pending CallbackHandle has been latched.
    void addLatchedCallbackHandles(const std::deque<sp<CallbackHandle>>& handles, nsecs_t latchTime,
                                   const sp<Fence>& previousReleaseFence);

    // Adds the Transaction CallbackHandle from a layer that does not need to be relatched and
    // presented this frame.
    void addUnlatchedCallbackHandle(const sp<CallbackHandle>& handle);

    void addPresentFence(const sp<Fence>& presentFence);

    void sendCallbacks();

private:
    void threadMain();

    void addCallbackHandle(const sp<CallbackHandle>& handle, nsecs_t latchTime = -1)
            REQUIRES(mMutex);

    class ThreadDeathRecipient : public IBinder::DeathRecipient {
    public:
        // This function is a no-op. isBinderAlive needs a linked DeathRecipient to work.
        // Death recipients needs a binderDied function.
        //
        // (isBinderAlive checks if BpBinder's mAlive is 0. mAlive is only set to 0 in sendObituary.
        // sendObituary is only called if linkToDeath was called with a DeathRecipient.)
        void binderDied(const wp<IBinder>& /*who*/) override {}
    };
    sp<ThreadDeathRecipient> mDeathRecipient;

    struct IBinderHash {
        std::size_t operator()(const sp<IBinder>& strongPointer) const {
            return std::hash<IBinder*>{}(strongPointer.get());
        }
    };

    std::thread mThread;

    std::mutex mMutex;
    std::condition_variable_any mConditionVariable;

    std::unordered_map<
            sp<IBinder /*listener*/>,
            std::unordered_map<std::vector<CallbackId>, uint32_t /*count*/, CallbackIdsHash>,
            IBinderHash>
            mPendingTransactions GUARDED_BY(mMutex);
    std::unordered_map<sp<IBinder /*listener*/>, ListenerStats, IBinderHash> mListenerStats
            GUARDED_BY(mMutex);

    bool mRunning GUARDED_BY(mMutex) = false;
    bool mKeepRunning GUARDED_BY(mMutex) = true;

    sp<Fence> mPresentFence GUARDED_BY(mMutex);
    std::vector<sp<Fence>> mPreviousReleaseFences GUARDED_BY(mMutex);
};

} // namespace android
