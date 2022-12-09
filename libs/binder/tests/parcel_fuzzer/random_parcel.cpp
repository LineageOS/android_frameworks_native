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

#include <fuzzbinder/random_parcel.h>

#include <android-base/logging.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransportRaw.h>
#include <fuzzbinder/random_binder.h>
#include <fuzzbinder/random_fd.h>
#include <utils/String16.h>

namespace android {

static void fillRandomParcelData(Parcel* p, FuzzedDataProvider&& provider) {
    std::vector<uint8_t> data = provider.ConsumeBytes<uint8_t>(provider.remaining_bytes());
    CHECK(OK == p->write(data.data(), data.size()));
}

void fillRandomParcel(Parcel* p, FuzzedDataProvider&& provider, RandomParcelOptions* options) {
    CHECK_NE(options, nullptr);

    if (provider.ConsumeBool()) {
        auto session = RpcSession::make(RpcTransportCtxFactoryRaw::make());
        CHECK_EQ(OK, session->addNullDebuggingClient());
        // Set the protocol version so that we don't crash if the session
        // actually gets used. This isn't cheating because the version should
        // always be set if the session init succeeded and we aren't testing the
        // session init here (it is bypassed by addNullDebuggingClient).
        session->setProtocolVersion(RPC_WIRE_PROTOCOL_VERSION);
        p->markForRpc(session);

        if (options->writeHeader) {
            options->writeHeader(p, provider);
        }

        fillRandomParcelData(p, std::move(provider));
        return;
    }

    if (options->writeHeader) {
        options->writeHeader(p, provider);
    }

    while (provider.remaining_bytes() > 0) {
        auto fillFunc = provider.PickValueInArray<const std::function<void()>>({
                // write data
                [&]() {
                    size_t toWrite =
                            provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes());
                    std::vector<uint8_t> data = provider.ConsumeBytes<uint8_t>(toWrite);
                    CHECK(OK == p->write(data.data(), data.size()));
                },
                // write FD
                [&]() {
                    if (options->extraFds.size() > 0 && provider.ConsumeBool()) {
                        const base::unique_fd& fd = options->extraFds.at(
                                provider.ConsumeIntegralInRange<size_t>(0,
                                                                        options->extraFds.size() -
                                                                                1));
                        CHECK(OK == p->writeFileDescriptor(fd.get(), false /*takeOwnership*/));
                    } else {
                        // b/260119717 - Adding more FDs can eventually lead to FD limit exhaustion
                        if (options->extraFds.size() > 1000) {
                            return;
                        }

                        std::vector<base::unique_fd> fds = getRandomFds(&provider);
                        CHECK(OK ==
                              p->writeFileDescriptor(fds.begin()->release(),
                                                     true /*takeOwnership*/));

                        options->extraFds.insert(options->extraFds.end(),
                                                 std::make_move_iterator(fds.begin() + 1),
                                                 std::make_move_iterator(fds.end()));
                    }
                },
                // write binder
                [&]() {
                    sp<IBinder> binder;
                    if (options->extraBinders.size() > 0 && provider.ConsumeBool()) {
                        binder = options->extraBinders.at(
                                provider.ConsumeIntegralInRange<size_t>(0,
                                                                        options->extraBinders
                                                                                        .size() -
                                                                                1));
                    } else {
                        binder = getRandomBinder(&provider);
                    }
                    CHECK(OK == p->writeStrongBinder(binder));
                },
        });

        fillFunc();
    }
}

} // namespace android
