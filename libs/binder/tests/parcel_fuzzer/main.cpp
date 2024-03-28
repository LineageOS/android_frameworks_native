/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define FUZZ_LOG_TAG "main"

#include "binder.h"
#include "binder_ndk.h"
#include "hwbinder.h"
#include "util.h"

#include <iostream>

#include <android-base/logging.h>
#include <android/binder_auto_utils.h>
#include <android/binder_libbinder.h>
#include <fuzzbinder/random_parcel.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <cstdlib>
#include <ctime>
#include <sys/resource.h>
#include <sys/time.h>

#include "../../Utils.h"

using android::fillRandomParcel;
using android::RandomParcelOptions;
using android::sp;
using android::HexString;

void fillRandomParcel(::android::hardware::Parcel* p, FuzzedDataProvider&& provider,
                      RandomParcelOptions* options) {
    // TODO: functionality to create random parcels for libhwbinder parcels
    (void)options;

    std::vector<uint8_t> input = provider.ConsumeRemainingBytes<uint8_t>();

    if (input.size() % 4 != 0) {
        input.resize(input.size() + (sizeof(uint32_t) - input.size() % sizeof(uint32_t)));
    }
    CHECK_EQ(0, input.size() % 4);

    p->setDataCapacity(input.size());
    for (size_t i = 0; i < input.size(); i += 4) {
        p->writeInt32(*((int32_t*)(input.data() + i)));
    }

    CHECK_EQ(0, memcmp(input.data(), p->data(), p->dataSize()));
}
static void fillRandomParcel(NdkParcelAdapter* p, FuzzedDataProvider&& provider,
                             RandomParcelOptions* options) {
    // fill underlying parcel using functions to fill random libbinder parcel
    fillRandomParcel(p->parcel(), std::move(provider), options);
}

template <typename P, typename B>
void doTransactFuzz(const char* backend, const sp<B>& binder, FuzzedDataProvider&& provider) {
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t flag = provider.ConsumeIntegral<uint32_t>();

    FUZZ_LOG() << "backend: " << backend;

    RandomParcelOptions options;

    P reply;
    P data;
    fillRandomParcel(&data, std::move(provider), &options);
    (void)binder->transact(code, data, &reply, flag);
}

template <typename P>
void doReadFuzz(const char* backend, const std::vector<ParcelRead<P>>& reads,
                FuzzedDataProvider&& provider) {
    // Allow some majority of the bytes to be dedicated to telling us what to
    // do. The fixed value added here represents that we want to test doing a
    // lot of 'instructions' even on really short parcels.
    size_t maxInstructions = 20 + (provider.remaining_bytes() * 2 / 3);
    // but don't always use that many instructions. We want to allow the fuzzer
    // to explore large parcels with few instructions if it wants to.
    std::vector<uint8_t> instructions = provider.ConsumeBytes<uint8_t>(
            provider.ConsumeIntegralInRange<size_t>(0, maxInstructions));

    RandomParcelOptions options;

    P p;
    fillRandomParcel(&p, std::move(provider), &options);

    // since we are only using a byte to index
    CHECK(reads.size() <= 255) << reads.size();

    FUZZ_LOG() << "backend: " << backend;
    FUZZ_LOG() << "input: " << HexString(p.data(), p.dataSize());
    FUZZ_LOG() << "instructions: " << HexString(instructions.data(), instructions.size());

    FuzzedDataProvider instructionsProvider(instructions.data(), instructions.size());
    while (instructionsProvider.remaining_bytes() > 0) {
        uint8_t idx = instructionsProvider.ConsumeIntegralInRange<uint8_t>(0, reads.size() - 1);

        FUZZ_LOG() << "Instruction " << idx << " avail: " << p.dataAvail()
                   << " pos: " << p.dataPosition() << " cap: " << p.dataCapacity();

        reads[idx](p, instructionsProvider);
    }
}

// Append two random parcels.
template <typename P>
void doAppendFuzz(const char* backend, FuzzedDataProvider&& provider) {
    int32_t start = provider.ConsumeIntegral<int32_t>();
    int32_t len = provider.ConsumeIntegral<int32_t>();

    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(
            provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes()));

    // same options so that FDs and binders could be shared in both Parcels
    RandomParcelOptions options;

    P p0, p1;
    fillRandomParcel(&p0, FuzzedDataProvider(bytes.data(), bytes.size()), &options);
    fillRandomParcel(&p1, std::move(provider), &options);

    FUZZ_LOG() << "backend: " << backend;
    FUZZ_LOG() << "start: " << start << " len: " << len;

    p0.appendFrom(&p1, start, len);
}

void* NothingClass_onCreate(void* args) {
    return args;
}
void NothingClass_onDestroy(void* /*userData*/) {}
binder_status_t NothingClass_onTransact(AIBinder*, transaction_code_t, const AParcel*, AParcel*) {
    return STATUS_UNKNOWN_ERROR;
}
static AIBinder_Class* kNothingClass =
        AIBinder_Class_define("nothing", NothingClass_onCreate, NothingClass_onDestroy,
                              NothingClass_onTransact);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size <= 1) return 0;  // no use

    // avoid timeouts, see b/142617274, b/142473153
    if (size > 50000) return 0;

    FuzzedDataProvider provider = FuzzedDataProvider(data, size);

    const std::function<void(FuzzedDataProvider &&)> fuzzBackend[] = {
            [](FuzzedDataProvider&& provider) {
                doTransactFuzz<
                        ::android::hardware::Parcel>("hwbinder",
                                                     sp<::android::hardware::BHwBinder>::make(),
                                                     std::move(provider));
            },
            [](FuzzedDataProvider&& provider) {
                doTransactFuzz<::android::Parcel>("binder", sp<::android::BBinder>::make(),
                                                  std::move(provider));
            },
            [](FuzzedDataProvider&& provider) {
                // fuzz from the libbinder layer since it's a superset of the
                // interface you get at the libbinder_ndk layer
                auto ndkBinder = ndk::SpAIBinder(AIBinder_new(kNothingClass, nullptr));
                auto binder = AIBinder_toPlatformBinder(ndkBinder.get());
                doTransactFuzz<::android::Parcel>("binder_ndk", binder, std::move(provider));
            },
            [](FuzzedDataProvider&& provider) {
                doReadFuzz<::android::hardware::Parcel>("hwbinder", HWBINDER_PARCEL_READ_FUNCTIONS,
                                                        std::move(provider));
            },
            [](FuzzedDataProvider&& provider) {
                doReadFuzz<::android::Parcel>("binder", BINDER_PARCEL_READ_FUNCTIONS,
                                              std::move(provider));
            },
            [](FuzzedDataProvider&& provider) {
                doReadFuzz<NdkParcelAdapter>("binder_ndk", BINDER_NDK_PARCEL_READ_FUNCTIONS,
                                             std::move(provider));
            },
            [](FuzzedDataProvider&& provider) {
                doAppendFuzz<::android::Parcel>("binder", std::move(provider));
            },
            [](FuzzedDataProvider&& provider) {
                doAppendFuzz<NdkParcelAdapter>("binder_ndk", std::move(provider));
            },
    };

    provider.PickValueInArray(fuzzBackend)(std::move(provider));

    return 0;
}
