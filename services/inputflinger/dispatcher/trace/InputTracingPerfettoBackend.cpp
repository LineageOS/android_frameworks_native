/*
 * Copyright 2024 The Android Open Source Project
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

#define LOG_TAG "InputTracer"

#include "InputTracingPerfettoBackend.h"

#include "AndroidInputEventProtoConverter.h"

#include <android-base/logging.h>
#include <binder/IServiceManager.h>
#include <perfetto/trace/android/android_input_event.pbzero.h>
#include <perfetto/trace/android/winscope_extensions.pbzero.h>
#include <perfetto/trace/android/winscope_extensions_impl.pbzero.h>
#include <private/android_filesystem_config.h>
#include <utils/String16.h>

namespace android::inputdispatcher::trace::impl {

namespace {

constexpr auto INPUT_EVENT_TRACE_DATA_SOURCE_NAME = "android.input.inputevent";

bool isPermanentlyAllowed(gui::Uid uid) {
    switch (uid.val()) {
        case AID_SYSTEM:
        case AID_SHELL:
        case AID_ROOT:
            return true;
        default:
            return false;
    }
}

sp<content::pm::IPackageManagerNative> getPackageManager() {
    sp<IServiceManager> serviceManager = defaultServiceManager();
    if (!serviceManager) {
        LOG(ERROR) << __func__ << ": unable to access native ServiceManager";
        return nullptr;
    }

    sp<IBinder> binder = serviceManager->waitForService(String16("package_native"));
    auto packageManager = interface_cast<content::pm::IPackageManagerNative>(binder);
    if (!packageManager) {
        LOG(ERROR) << ": unable to access native PackageManager";
        return nullptr;
    }
    return packageManager;
}

gui::Uid getPackageUid(const sp<content::pm::IPackageManagerNative>& pm,
                       const std::string& package) {
    int32_t outUid = -1;
    if (auto status = pm->getPackageUid(package, /*flags=*/0, AID_SYSTEM, &outUid);
        !status.isOk()) {
        LOG(INFO) << "Failed to get package UID from native package manager for package '"
                  << package << "': " << status;
        return gui::Uid::INVALID;
    }
    return gui::Uid{static_cast<uid_t>(outUid)};
}

} // namespace

// --- PerfettoBackend::InputEventDataSource ---

PerfettoBackend::InputEventDataSource::InputEventDataSource() : mInstanceId(sNextInstanceId++) {}

void PerfettoBackend::InputEventDataSource::OnSetup(const InputEventDataSource::SetupArgs& args) {
    LOG(INFO) << "Setting up perfetto trace for: " << INPUT_EVENT_TRACE_DATA_SOURCE_NAME
              << ", instanceId: " << mInstanceId;
    const auto rawConfig = args.config->android_input_event_config_raw();
    auto protoConfig = perfetto::protos::pbzero::AndroidInputEventConfig::Decoder{rawConfig};

    mConfig = AndroidInputEventProtoConverter::parseConfig(protoConfig);
}

void PerfettoBackend::InputEventDataSource::OnStart(const InputEventDataSource::StartArgs&) {
    LOG(INFO) << "Starting perfetto trace for: " << INPUT_EVENT_TRACE_DATA_SOURCE_NAME
              << ", instanceId: " << mInstanceId;
}

void PerfettoBackend::InputEventDataSource::OnStop(const InputEventDataSource::StopArgs&) {
    LOG(INFO) << "Stopping perfetto trace for: " << INPUT_EVENT_TRACE_DATA_SOURCE_NAME
              << ", instanceId: " << mInstanceId;
    InputEventDataSource::Trace([&](InputEventDataSource::TraceContext ctx) { ctx.Flush(); });
}

void PerfettoBackend::InputEventDataSource::initializeUidMap() {
    if (mUidMap.has_value()) {
        return;
    }

    mUidMap = {{}};
    auto packageManager = PerfettoBackend::sPackageManagerProvider();
    if (!packageManager) {
        LOG(ERROR) << "Failed to initialize UID map: Could not get native package manager";
        return;
    }

    for (const auto& rule : mConfig.rules) {
        for (const auto& package : rule.matchAllPackages) {
            mUidMap->emplace(package, getPackageUid(packageManager, package));
        }
        for (const auto& package : rule.matchAnyPackages) {
            mUidMap->emplace(package, getPackageUid(packageManager, package));
        }
    }
}

bool PerfettoBackend::InputEventDataSource::shouldIgnoreTracedInputEvent(
        const EventType& type) const {
    if (!getFlags().test(TraceFlag::TRACE_DISPATCHER_INPUT_EVENTS)) {
        // Ignore all input events.
        return true;
    }
    if (!getFlags().test(TraceFlag::TRACE_DISPATCHER_WINDOW_DISPATCH) &&
        type != EventType::INBOUND) {
        // When window dispatch tracing is disabled, ignore any events that are not inbound events.
        return true;
    }
    return false;
}

TraceLevel PerfettoBackend::InputEventDataSource::resolveTraceLevel(
        const TracedEventMetadata& metadata) const {
    // Check for matches with the rules in the order that they are defined.
    for (const auto& rule : mConfig.rules) {
        if (ruleMatches(rule, metadata)) {
            return rule.level;
        }
    }
    // The event is not traced if it matched zero rules.
    return TraceLevel::TRACE_LEVEL_NONE;
}

bool PerfettoBackend::InputEventDataSource::ruleMatches(const TraceRule& rule,
                                                        const TracedEventMetadata& metadata) const {
    // By default, a rule will match all events. Return early if the rule does not match.

    // Match the event if it is directed to a secure window.
    if (rule.matchSecure.has_value() && *rule.matchSecure != metadata.isSecure) {
        return false;
    }

    // Match the event if it was processed while there was an active InputMethod connection.
    if (rule.matchImeConnectionActive.has_value() &&
        *rule.matchImeConnectionActive != metadata.isImeConnectionActive) {
        return false;
    }

    // Match the event if all of its target packages are explicitly allowed in the "match all" list.
    if (!rule.matchAllPackages.empty() &&
        !std::all_of(metadata.targets.begin(), metadata.targets.end(), [&](const auto& uid) {
            return isPermanentlyAllowed(uid) ||
                    std::any_of(rule.matchAllPackages.begin(), rule.matchAllPackages.end(),
                                [&](const auto& pkg) { return uid == mUidMap->at(pkg); });
        })) {
        return false;
    }

    // Match the event if any of its target packages are allowed in the "match any" list.
    if (!rule.matchAnyPackages.empty() &&
        !std::any_of(metadata.targets.begin(), metadata.targets.end(), [&](const auto& uid) {
            return std::any_of(rule.matchAnyPackages.begin(), rule.matchAnyPackages.end(),
                               [&](const auto& pkg) { return uid == mUidMap->at(pkg); });
        })) {
        return false;
    }

    // The event matches all matchers specified in the rule.
    return true;
}

// --- PerfettoBackend ---

bool PerfettoBackend::sUseInProcessBackendForTest{false};

std::function<sp<content::pm::IPackageManagerNative>()> PerfettoBackend::sPackageManagerProvider{
        &getPackageManager};

std::once_flag PerfettoBackend::sDataSourceRegistrationFlag{};

std::atomic<int32_t> PerfettoBackend::sNextInstanceId{1};

PerfettoBackend::PerfettoBackend() {
    // Use a once-flag to ensure that the data source is only registered once per boot, since
    // we never unregister the InputEventDataSource.
    std::call_once(sDataSourceRegistrationFlag, []() {
        perfetto::TracingInitArgs args;
        args.backends = sUseInProcessBackendForTest ? perfetto::kInProcessBackend
                                                    : perfetto::kSystemBackend;
        perfetto::Tracing::Initialize(args);

        // Register our custom data source for input event tracing.
        perfetto::DataSourceDescriptor dsd;
        dsd.set_name(INPUT_EVENT_TRACE_DATA_SOURCE_NAME);
        InputEventDataSource::Register(dsd);
        LOG(INFO) << "InputTracer initialized for data source: "
                  << INPUT_EVENT_TRACE_DATA_SOURCE_NAME;
    });
}

void PerfettoBackend::traceMotionEvent(const TracedMotionEvent& event,
                                       const TracedEventMetadata& metadata) {
    InputEventDataSource::Trace([&](InputEventDataSource::TraceContext ctx) {
        auto dataSource = ctx.GetDataSourceLocked();
        if (!dataSource.valid()) {
            return;
        }
        dataSource->initializeUidMap();
        if (dataSource->shouldIgnoreTracedInputEvent(event.eventType)) {
            return;
        }
        const TraceLevel traceLevel = dataSource->resolveTraceLevel(metadata);
        if (traceLevel == TraceLevel::TRACE_LEVEL_NONE) {
            return;
        }
        const bool isRedacted = traceLevel == TraceLevel::TRACE_LEVEL_REDACTED;
        auto tracePacket = ctx.NewTracePacket();
        tracePacket->set_timestamp(metadata.processingTimestamp);
        tracePacket->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_MONOTONIC);
        auto* winscopeExtensions = static_cast<perfetto::protos::pbzero::WinscopeExtensionsImpl*>(
                tracePacket->set_winscope_extensions());
        auto* inputEvent = winscopeExtensions->set_android_input_event();
        auto* dispatchMotion = isRedacted ? inputEvent->set_dispatcher_motion_event_redacted()
                                          : inputEvent->set_dispatcher_motion_event();
        AndroidInputEventProtoConverter::toProtoMotionEvent(event, *dispatchMotion, isRedacted);
    });
}

void PerfettoBackend::traceKeyEvent(const TracedKeyEvent& event,
                                    const TracedEventMetadata& metadata) {
    InputEventDataSource::Trace([&](InputEventDataSource::TraceContext ctx) {
        auto dataSource = ctx.GetDataSourceLocked();
        if (!dataSource.valid()) {
            return;
        }
        dataSource->initializeUidMap();
        if (dataSource->shouldIgnoreTracedInputEvent(event.eventType)) {
            return;
        }
        const TraceLevel traceLevel = dataSource->resolveTraceLevel(metadata);
        if (traceLevel == TraceLevel::TRACE_LEVEL_NONE) {
            return;
        }
        const bool isRedacted = traceLevel == TraceLevel::TRACE_LEVEL_REDACTED;
        auto tracePacket = ctx.NewTracePacket();
        tracePacket->set_timestamp(metadata.processingTimestamp);
        tracePacket->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_MONOTONIC);
        auto* winscopeExtensions = static_cast<perfetto::protos::pbzero::WinscopeExtensionsImpl*>(
                tracePacket->set_winscope_extensions());
        auto* inputEvent = winscopeExtensions->set_android_input_event();
        auto* dispatchKey = isRedacted ? inputEvent->set_dispatcher_key_event_redacted()
                                       : inputEvent->set_dispatcher_key_event();
        AndroidInputEventProtoConverter::toProtoKeyEvent(event, *dispatchKey, isRedacted);
    });
}

void PerfettoBackend::traceWindowDispatch(const WindowDispatchArgs& dispatchArgs,
                                          const TracedEventMetadata& metadata) {
    InputEventDataSource::Trace([&](InputEventDataSource::TraceContext ctx) {
        auto dataSource = ctx.GetDataSourceLocked();
        if (!dataSource.valid()) {
            return;
        }
        dataSource->initializeUidMap();
        if (!dataSource->getFlags().test(TraceFlag::TRACE_DISPATCHER_WINDOW_DISPATCH)) {
            return;
        }
        const TraceLevel traceLevel = dataSource->resolveTraceLevel(metadata);
        if (traceLevel == TraceLevel::TRACE_LEVEL_NONE) {
            return;
        }
        const bool isRedacted = traceLevel == TraceLevel::TRACE_LEVEL_REDACTED;
        auto tracePacket = ctx.NewTracePacket();
        tracePacket->set_timestamp(dispatchArgs.deliveryTime);
        tracePacket->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_MONOTONIC);
        auto* winscopeExtensions = static_cast<perfetto::protos::pbzero::WinscopeExtensionsImpl*>(
                tracePacket->set_winscope_extensions());
        auto* inputEvent = winscopeExtensions->set_android_input_event();
        auto* dispatchEvent = isRedacted
                ? inputEvent->set_dispatcher_window_dispatch_event_redacted()
                : inputEvent->set_dispatcher_window_dispatch_event();
        AndroidInputEventProtoConverter::toProtoWindowDispatchEvent(dispatchArgs, *dispatchEvent,
                                                                    isRedacted);
    });
}

} // namespace android::inputdispatcher::trace::impl
