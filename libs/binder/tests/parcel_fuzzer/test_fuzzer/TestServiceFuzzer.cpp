/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <BnTestService.h>
#include <fuzzbinder/libbinder_driver.h>

#include <binder/IPCThreadState.h>
#include <log/log.h>

#include <private/android_filesystem_config.h>

using android::binder::Status;

namespace android {

enum class CrashType {
    NONE,
    ON_PLAIN,
    ON_BINDER,
    ON_KNOWN_UID,
    ON_SYSTEM_AID,
    ON_ROOT_AID,
    ON_DUMP_TRANSACT,
    ON_SHELL_CMD_TRANSACT,
    CRASH_ALWAYS,
};

// This service is to verify that fuzzService is functioning properly
class TestService : public BnTestService {
public:
    TestService(CrashType crash) : mCrash(crash) {}

    void onData() {
        switch (mCrash) {
            case CrashType::ON_PLAIN: {
                LOG_ALWAYS_FATAL("Expected crash, PLAIN.");
                break;
            }
            case CrashType::ON_KNOWN_UID: {
                if (IPCThreadState::self()->getCallingUid() == getuid()) {
                    LOG_ALWAYS_FATAL("Expected crash, KNOWN_UID.");
                }
                break;
            }
            case CrashType::ON_SYSTEM_AID: {
                if (IPCThreadState::self()->getCallingUid() == AID_SYSTEM) {
                    LOG_ALWAYS_FATAL("Expected crash, AID_SYSTEM.");
                }
                break;
            }
            case CrashType::ON_ROOT_AID: {
                if (IPCThreadState::self()->getCallingUid() == AID_ROOT) {
                    LOG_ALWAYS_FATAL("Expected crash, AID_ROOT.");
                }
                break;
            }
            default:
                break;
        }
    }

    Status setIntData(int /*input*/) override {
        onData();
        return Status::ok();
    }

    Status setCharData(char16_t /*input*/) override {
        onData();
        return Status::ok();
    }

    Status setBooleanData(bool /*input*/) override {
        onData();
        return Status::ok();
    }

    Status setService(const sp<ITestService>& service) override {
        onData();
        if (mCrash == CrashType::ON_BINDER && service != nullptr) {
            LOG_ALWAYS_FATAL("Expected crash, BINDER.");
        }
        return Status::ok();
    }

    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) override {
        if (mCrash == CrashType::ON_DUMP_TRANSACT && code == DUMP_TRANSACTION) {
            LOG_ALWAYS_FATAL("Expected crash, DUMP.");
        } else if (mCrash == CrashType::ON_SHELL_CMD_TRANSACT &&
                   code == SHELL_COMMAND_TRANSACTION) {
            LOG_ALWAYS_FATAL("Expected crash, SHELL_CMD.");
        }
        return BnTestService::onTransact(code, data, reply, flags);
    }

private:
    CrashType mCrash;
};

CrashType gCrashType = CrashType::NONE;

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    if (*argc < 2) {
        // This fuzzer is also used as test fuzzer to check infra pipeline.
        // It should always run and find a crash in TestService.
        gCrashType = CrashType::CRASH_ALWAYS;
        return 0;
    }

    std::string arg = std::string((*argv)[1]);

    // ignore first argument, because we consume it
    (*argv)[1] = (*argv[0]);
    (*argc)--;
    (*argv)++;

    if (arg == "PLAIN") {
        gCrashType = CrashType::ON_PLAIN;
    } else if (arg == "KNOWN_UID") {
        gCrashType = CrashType::ON_KNOWN_UID;
    } else if (arg == "AID_SYSTEM") {
        gCrashType = CrashType::ON_SYSTEM_AID;
    } else if (arg == "AID_ROOT") {
        gCrashType = CrashType::ON_ROOT_AID;
    } else if (arg == "BINDER") {
        gCrashType = CrashType::ON_BINDER;
    } else if (arg == "DUMP") {
        gCrashType = CrashType::ON_DUMP_TRANSACT;
    } else if (arg == "SHELL_CMD") {
        gCrashType = CrashType::ON_SHELL_CMD_TRANSACT;
    } else {
        printf("INVALID ARG\n");
        exit(0); // success because this is a crash test
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (gCrashType == CrashType::CRASH_ALWAYS) {
        LOG_ALWAYS_FATAL("Expected crash, This fuzzer will always crash.");
    }
    auto service = sp<TestService>::make(gCrashType);
    fuzzService(service, FuzzedDataProvider(data, size));
    return 0;
}

} // namespace android
