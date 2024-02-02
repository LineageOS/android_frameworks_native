/*
 * Copyright (C) 2010 The Android Open Source Project
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

#define LOG_TAG "InputManager"

//#define LOG_NDEBUG 0

#include "InputManager.h"
#include "InputDispatcherFactory.h"
#include "InputReaderFactory.h"
#include "UnwantedInteractionBlocker.h"

#include <aidl/com/android/server/inputflinger/IInputFlingerRust.h>
#include <android/binder_interface_utils.h>
#include <android/sysprop/InputProperties.sysprop.h>
#include <binder/IPCThreadState.h>
#include <com_android_input_flags.h>
#include <inputflinger_bootstrap.rs.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>

namespace input_flags = com::android::input::flags;

namespace android {

namespace {

const bool ENABLE_INPUT_DEVICE_USAGE_METRICS =
        sysprop::InputProperties::enable_input_device_usage_metrics().value_or(true);

const bool ENABLE_POINTER_CHOREOGRAPHER = input_flags::enable_pointer_choreographer();
const bool ENABLE_INPUT_FILTER_RUST = input_flags::enable_input_filter_rust_impl();

int32_t exceptionCodeFromStatusT(status_t status) {
    switch (status) {
        case OK:
            return binder::Status::EX_NONE;
        case INVALID_OPERATION:
            return binder::Status::EX_UNSUPPORTED_OPERATION;
        case BAD_VALUE:
        case BAD_TYPE:
        case NAME_NOT_FOUND:
            return binder::Status::EX_ILLEGAL_ARGUMENT;
        case NO_INIT:
            return binder::Status::EX_ILLEGAL_STATE;
        case PERMISSION_DENIED:
            return binder::Status::EX_SECURITY;
        default:
            return binder::Status::EX_TRANSACTION_FAILED;
    }
}

// Convert a binder interface into a raw pointer to an AIBinder.
using IInputFlingerRustBootstrapCallback = aidl::com::android::server::inputflinger::
        IInputFlingerRust::IInputFlingerRustBootstrapCallback;
IInputFlingerRustBootstrapCallbackAIBinder* binderToPointer(
        IInputFlingerRustBootstrapCallback& interface) {
    ndk::SpAIBinder spAIBinder = interface.asBinder();
    auto* ptr = spAIBinder.get();
    AIBinder_incStrong(ptr);
    return ptr;
}

// Create the Rust component of InputFlinger that uses AIDL interfaces as a the foreign function
// interface (FFI). The bootstraping process for IInputFlingerRust is as follows:
//   - Create BnInputFlingerRustBootstrapCallback in C++.
//   - Use the cxxbridge ffi interface to call the Rust function `create_inputflinger_rust()`, and
//     pass the callback binder object as a raw pointer.
//   - The Rust implementation will create the implementation of IInputFlingerRust, and pass it
//     to C++ through the callback.
//   - After the Rust function returns, the binder interface provided to the callback will be the
//     only strong reference to the IInputFlingerRust.
std::shared_ptr<IInputFlingerRust> createInputFlingerRust() {
    using namespace aidl::com::android::server::inputflinger;

    class Callback : public IInputFlingerRust::BnInputFlingerRustBootstrapCallback {
        ndk::ScopedAStatus onProvideInputFlingerRust(
                const std::shared_ptr<IInputFlingerRust>& inputFlingerRust) override {
            mService = inputFlingerRust;
            return ndk::ScopedAStatus::ok();
        }

    public:
        std::shared_ptr<IInputFlingerRust> consumeInputFlingerRust() {
            auto service = mService;
            mService.reset();
            return service;
        }

    private:
        std::shared_ptr<IInputFlingerRust> mService;
    };

    auto callback = ndk::SharedRefBase::make<Callback>();
    create_inputflinger_rust(binderToPointer(*callback));
    auto service = callback->consumeInputFlingerRust();
    LOG_ALWAYS_FATAL_IF(!service,
                        "create_inputflinger_rust did not provide the IInputFlingerRust "
                        "implementation through the callback.");
    return service;
}

} // namespace

/**
 * The event flow is via the "InputListener" interface, as follows:
 *   InputReader
 *     -> UnwantedInteractionBlocker
 *     -> InputFilter
 *     -> PointerChoreographer
 *     -> InputProcessor
 *     -> InputDeviceMetricsCollector
 *     -> InputDispatcher
 */
InputManager::InputManager(const sp<InputReaderPolicyInterface>& readerPolicy,
                           InputDispatcherPolicyInterface& dispatcherPolicy,
                           PointerChoreographerPolicyInterface& choreographerPolicy,
                           InputFilterPolicyInterface& inputFilterPolicy) {
    mInputFlingerRust = createInputFlingerRust();

    mDispatcher = createInputDispatcher(dispatcherPolicy);
    mTracingStages.emplace_back(
            std::make_unique<TracedInputListener>("InputDispatcher", *mDispatcher));

    if (ENABLE_INPUT_FILTER_RUST) {
        mInputFilter = std::make_unique<InputFilter>(*mTracingStages.back(), *mInputFlingerRust,
                                                     inputFilterPolicy);
        mTracingStages.emplace_back(
                std::make_unique<TracedInputListener>("InputFilter", *mInputFilter));
    }

    if (ENABLE_INPUT_DEVICE_USAGE_METRICS) {
        mCollector = std::make_unique<InputDeviceMetricsCollector>(*mTracingStages.back());
        mTracingStages.emplace_back(
                std::make_unique<TracedInputListener>("MetricsCollector", *mCollector));
    }

    mProcessor = std::make_unique<InputProcessor>(*mTracingStages.back());
    mTracingStages.emplace_back(
            std::make_unique<TracedInputListener>("InputProcessor", *mProcessor));

    if (ENABLE_POINTER_CHOREOGRAPHER) {
        mChoreographer =
                std::make_unique<PointerChoreographer>(*mTracingStages.back(), choreographerPolicy);
        mTracingStages.emplace_back(
                std::make_unique<TracedInputListener>("PointerChoreographer", *mChoreographer));
    }

    mBlocker = std::make_unique<UnwantedInteractionBlocker>(*mTracingStages.back());
    mTracingStages.emplace_back(
            std::make_unique<TracedInputListener>("UnwantedInteractionBlocker", *mBlocker));

    mReader = createInputReader(readerPolicy, *mTracingStages.back());
}

InputManager::~InputManager() {
    stop();
}

status_t InputManager::start() {
    status_t result = mDispatcher->start();
    if (result) {
        ALOGE("Could not start InputDispatcher thread due to error %d.", result);
        return result;
    }

    result = mReader->start();
    if (result) {
        ALOGE("Could not start InputReader due to error %d.", result);

        mDispatcher->stop();
        return result;
    }

    return OK;
}

status_t InputManager::stop() {
    status_t status = OK;

    status_t result = mReader->stop();
    if (result) {
        ALOGW("Could not stop InputReader due to error %d.", result);
        status = result;
    }

    result = mDispatcher->stop();
    if (result) {
        ALOGW("Could not stop InputDispatcher thread due to error %d.", result);
        status = result;
    }

    return status;
}

InputReaderInterface& InputManager::getReader() {
    return *mReader;
}

PointerChoreographerInterface& InputManager::getChoreographer() {
    return *mChoreographer;
}

InputProcessorInterface& InputManager::getProcessor() {
    return *mProcessor;
}

InputDeviceMetricsCollectorInterface& InputManager::getMetricsCollector() {
    return *mCollector;
}

InputDispatcherInterface& InputManager::getDispatcher() {
    return *mDispatcher;
}

InputFilterInterface& InputManager::getInputFilter() {
    return *mInputFilter;
}

void InputManager::monitor() {
    mReader->monitor();
    mBlocker->monitor();
    mProcessor->monitor();
    if (ENABLE_INPUT_DEVICE_USAGE_METRICS) {
        mCollector->monitor();
    }
    mDispatcher->monitor();
}

void InputManager::dump(std::string& dump) {
    mReader->dump(dump);
    dump += '\n';
    mBlocker->dump(dump);
    dump += '\n';
    if (ENABLE_POINTER_CHOREOGRAPHER) {
        mChoreographer->dump(dump);
        dump += '\n';
    }
    mProcessor->dump(dump);
    dump += '\n';
    if (ENABLE_INPUT_DEVICE_USAGE_METRICS) {
        mCollector->dump(dump);
        dump += '\n';
    }
    mDispatcher->dump(dump);
    dump += '\n';
}

// Used by tests only.
binder::Status InputManager::createInputChannel(const std::string& name,
                                                android::os::InputChannelCore* outChannel) {
    IPCThreadState* ipc = IPCThreadState::self();
    const uid_t uid = ipc->getCallingUid();
    if (uid != AID_SHELL && uid != AID_ROOT) {
        LOG(ERROR) << __func__ << " can only be called by SHELL or ROOT users, "
                   << "but was called from UID " << uid;
        return binder::Status::
                fromExceptionCode(EX_SECURITY,
                                  "This uid is not allowed to call createInputChannel");
    }

    base::Result<std::unique_ptr<InputChannel>> channel = mDispatcher->createInputChannel(name);
    if (!channel.ok()) {
        return binder::Status::fromExceptionCode(exceptionCodeFromStatusT(channel.error().code()),
                                                 channel.error().message().c_str());
    }
    InputChannel::moveChannel(std::move(*channel), *outChannel);
    return binder::Status::ok();
}

binder::Status InputManager::removeInputChannel(const sp<IBinder>& connectionToken) {
    mDispatcher->removeInputChannel(connectionToken);
    return binder::Status::ok();
}

status_t InputManager::dump(int fd, const Vector<String16>& args) {
    std::string dump;

    dump += " InputFlinger dump\n";

    TEMP_FAILURE_RETRY(::write(fd, dump.c_str(), dump.size()));
    return NO_ERROR;
}

binder::Status InputManager::setFocusedWindow(const gui::FocusRequest& request) {
    mDispatcher->setFocusedWindow(request);
    return binder::Status::ok();
}

} // namespace android
