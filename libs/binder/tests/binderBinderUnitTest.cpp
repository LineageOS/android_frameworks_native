/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <binder/Binder.h>
#include <binder/IInterface.h>
#include <gtest/gtest.h>

using android::BBinder;
using android::IBinder;
using android::OK;
using android::sp;

const void* kObjectId1 = reinterpret_cast<const void*>(1);
const void* kObjectId2 = reinterpret_cast<const void*>(2);
void* kObject1 = reinterpret_cast<void*>(101);
void* kObject2 = reinterpret_cast<void*>(102);
void* kObject3 = reinterpret_cast<void*>(103);

TEST(Binder, AttachObject) {
    auto binder = sp<BBinder>::make();
    EXPECT_EQ(nullptr, binder->attachObject(kObjectId1, kObject1, nullptr, nullptr));
    EXPECT_EQ(nullptr, binder->attachObject(kObjectId2, kObject2, nullptr, nullptr));
    EXPECT_EQ(kObject1, binder->attachObject(kObjectId1, kObject3, nullptr, nullptr));
}

TEST(Binder, DetachObject) {
    auto binder = sp<BBinder>::make();
    EXPECT_EQ(nullptr, binder->attachObject(kObjectId1, kObject1, nullptr, nullptr));
    EXPECT_EQ(kObject1, binder->detachObject(kObjectId1));
    EXPECT_EQ(nullptr, binder->attachObject(kObjectId1, kObject2, nullptr, nullptr));
}

TEST(Binder, AttachExtension) {
    auto binder = sp<BBinder>::make();
    auto ext = sp<BBinder>::make();
    binder->setExtension(ext);
    EXPECT_EQ(ext, binder->getExtension());
}

struct MyCookie {
    bool* deleted;
};

class UniqueBinder : public BBinder {
public:
    UniqueBinder(const void* c) : cookie(reinterpret_cast<const MyCookie*>(c)) {
        *cookie->deleted = false;
    }
    ~UniqueBinder() { *cookie->deleted = true; }
    const MyCookie* cookie;
};

static sp<IBinder> make(const void* arg) {
    return sp<UniqueBinder>::make(arg);
}

TEST(Binder, LookupOrCreateWeak) {
    auto binder = sp<BBinder>::make();
    bool deleted;
    MyCookie cookie = {&deleted};
    sp<IBinder> createdBinder = binder->lookupOrCreateWeak(kObjectId1, make, &cookie);
    EXPECT_NE(binder, createdBinder);

    sp<IBinder> lookedUpBinder = binder->lookupOrCreateWeak(kObjectId1, make, &cookie);
    EXPECT_EQ(createdBinder, lookedUpBinder);
    EXPECT_FALSE(deleted);
}

TEST(Binder, LookupOrCreateWeakDropSp) {
    auto binder = sp<BBinder>::make();
    bool deleted1 = false;
    bool deleted2 = false;
    MyCookie cookie1 = {&deleted1};
    MyCookie cookie2 = {&deleted2};
    sp<IBinder> createdBinder = binder->lookupOrCreateWeak(kObjectId1, make, &cookie1);
    EXPECT_NE(binder, createdBinder);

    createdBinder.clear();
    EXPECT_TRUE(deleted1);

    sp<IBinder> lookedUpBinder = binder->lookupOrCreateWeak(kObjectId1, make, &cookie2);
    EXPECT_EQ(&cookie2, sp<UniqueBinder>::cast(lookedUpBinder)->cookie);
    EXPECT_FALSE(deleted2);
}
