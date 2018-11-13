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

#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <binder/SafeInterface.h>

#include <utils/Timers.h>

#include <cstdint>
#include <unordered_map>
#include <unordered_set>

namespace android {

class ITransactionCompletedListener;

using CallbackId = int64_t;

struct CallbackIdsHash {
    // CallbackId vectors have several properties that let us get away with this simple hash.
    // 1) CallbackIds are never 0 so if something has gone wrong and our CallbackId vector is
    // empty we can still hash 0.
    // 2) CallbackId vectors for the same listener either are identical or contain none of the
    // same members. It is sufficient to just check the first CallbackId in the vectors. If
    // they match, they are the same. If they do not match, they are not the same.
    std::size_t operator()(const std::vector<CallbackId> callbackIds) const {
        return std::hash<CallbackId>{}((callbackIds.size() == 0) ? 0 : callbackIds.front());
    }
};

class SurfaceStats : public Parcelable {
public:
    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;

    SurfaceStats() = default;
    SurfaceStats(const sp<IBinder>& sc, nsecs_t time, bool releasePrevBuffer)
          : surfaceControl(sc), acquireTime(time), releasePreviousBuffer(releasePrevBuffer) {}

    sp<IBinder> surfaceControl;
    nsecs_t acquireTime = -1;
    bool releasePreviousBuffer = false;
};

class TransactionStats : public Parcelable {
public:
    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;

    nsecs_t latchTime = -1;
    nsecs_t presentTime = -1;
    std::vector<SurfaceStats> surfaceStats;
};

class ListenerStats : public Parcelable {
public:
    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;

    static ListenerStats createEmpty(const sp<ITransactionCompletedListener>& listener,
                                     const std::unordered_set<CallbackId>& callbackIds);

    sp<ITransactionCompletedListener> listener;
    std::unordered_map<std::vector<CallbackId>, TransactionStats, CallbackIdsHash> transactionStats;
};

class ITransactionCompletedListener : public IInterface {
public:
    DECLARE_META_INTERFACE(TransactionCompletedListener)

    virtual void onTransactionCompleted(ListenerStats stats) = 0;
};

class BnTransactionCompletedListener : public SafeBnInterface<ITransactionCompletedListener> {
public:
    BnTransactionCompletedListener()
          : SafeBnInterface<ITransactionCompletedListener>("BnTransactionCompletedListener") {}

    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                        uint32_t flags = 0) override;
};

class ListenerCallbacks {
public:
    ListenerCallbacks(const sp<ITransactionCompletedListener>& listener,
                      const std::unordered_set<CallbackId>& callbacks)
          : transactionCompletedListener(listener),
            callbackIds(callbacks.begin(), callbacks.end()) {}

    ListenerCallbacks(const sp<ITransactionCompletedListener>& listener,
                      const std::vector<CallbackId>& ids)
          : transactionCompletedListener(listener), callbackIds(ids) {}

    sp<ITransactionCompletedListener> transactionCompletedListener;
    std::vector<CallbackId> callbackIds;
};

} // namespace android
