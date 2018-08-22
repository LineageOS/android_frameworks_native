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

#define LOG_TAG "ITransactionCompletedListener"
//#define LOG_NDEBUG 0

#include <gui/ITransactionCompletedListener.h>

namespace android {

namespace { // Anonymous

enum class Tag : uint32_t {
    ON_TRANSACTION_COMPLETED = IBinder::FIRST_CALL_TRANSACTION,
    LAST = ON_TRANSACTION_COMPLETED,
};

} // Anonymous namespace

class BpTransactionCompletedListener : public SafeBpInterface<ITransactionCompletedListener> {
public:
    explicit BpTransactionCompletedListener(const sp<IBinder>& impl)
          : SafeBpInterface<ITransactionCompletedListener>(impl, "BpTransactionCompletedListener") {
    }

    ~BpTransactionCompletedListener() override;

    void onTransactionCompleted() override {
        callRemoteAsync<decltype(&ITransactionCompletedListener::onTransactionCompleted)>(
                Tag::ON_TRANSACTION_COMPLETED);
    }
};

// Out-of-line virtual method definitions to trigger vtable emission in this translation unit (see
// clang warning -Wweak-vtables)
BpTransactionCompletedListener::~BpTransactionCompletedListener() = default;

IMPLEMENT_META_INTERFACE(TransactionCompletedListener, "android.gui.ITransactionComposerListener");

status_t BnTransactionCompletedListener::onTransact(uint32_t code, const Parcel& data,
                                                    Parcel* reply, uint32_t flags) {
    if (code < IBinder::FIRST_CALL_TRANSACTION || code > static_cast<uint32_t>(Tag::LAST)) {
        return BBinder::onTransact(code, data, reply, flags);
    }
    auto tag = static_cast<Tag>(code);
    switch (tag) {
        case Tag::ON_TRANSACTION_COMPLETED:
            return callLocalAsync(data, reply,
                                  &ITransactionCompletedListener::onTransactionCompleted);
    }
}

}; // namespace android
