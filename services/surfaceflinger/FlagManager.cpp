/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "FlagManager.h"

#include <SurfaceFlingerProperties.sysprop.h>
#include <android-base/parsebool.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <log/log.h>
#include <renderengine/RenderEngine.h>
#include <server_configurable_flags/get_flags.h>
#include <cinttypes>

namespace android {
static constexpr const char* kExperimentNamespace = "surface_flinger_native_boot";

std::unique_ptr<FlagManager> FlagManager::mInstance;
std::once_flag FlagManager::mOnce;

FlagManager::FlagManager(ConstructorTag) {}
FlagManager::~FlagManager() = default;

namespace {
std::optional<bool> parseBool(const char* str) {
    base::ParseBoolResult parseResult = base::ParseBool(str);
    switch (parseResult) {
        case base::ParseBoolResult::kTrue:
            return std::make_optional(true);
        case base::ParseBoolResult::kFalse:
            return std::make_optional(false);
        case base::ParseBoolResult::kError:
            return std::nullopt;
    }
}

void dumpFlag(std::string& result, const char* name, std::function<bool()> getter) {
    base::StringAppendF(&result, "%s: %s\n", name, getter() ? "true" : "false");
}

} // namespace

const FlagManager& FlagManager::getInstance() {
    return getMutableInstance();
}

FlagManager& FlagManager::getMutableInstance() {
    std::call_once(mOnce, [&] {
        LOG_ALWAYS_FATAL_IF(mInstance, "Instance already created");
        mInstance = std::make_unique<FlagManager>(ConstructorTag{});
    });

    return *mInstance;
}

void FlagManager::markBootCompleted() {
    mBootCompleted = true;
}

void FlagManager::dump(std::string& result) const {
#define DUMP_FLAG(name) dumpFlag(result, #name, std::bind(&FlagManager::name, this));

    base::StringAppendF(&result, "FlagManager values: \n");
    DUMP_FLAG(use_adpf_cpu_hint);
    DUMP_FLAG(use_skia_tracing);

#undef DUMP_FLAG
}

std::optional<bool> FlagManager::getBoolProperty(const char* property) const {
    return parseBool(base::GetProperty(property, "").c_str());
}

bool FlagManager::getServerConfigurableFlag(const char* experimentFlagName) const {
    const auto value = server_configurable_flags::GetServerConfigurableFlag(kExperimentNamespace,
                                                                            experimentFlagName, "");
    const auto res = parseBool(value.c_str());
    return res.has_value() && res.value();
}

#define FLAG_MANAGER_SERVER_FLAG(name, syspropOverride, serverFlagName)                     \
    bool FlagManager::name() const {                                                        \
        LOG_ALWAYS_FATAL_IF(!mBootCompleted,                                                \
                            "Can't read %s before boot completed as it is server writable", \
                            __func__);                                                      \
        const auto debugOverride = getBoolProperty(syspropOverride);                        \
        if (debugOverride.has_value()) return debugOverride.value();                        \
        return getServerConfigurableFlag(serverFlagName);                                   \
    }

FLAG_MANAGER_SERVER_FLAG(test_flag, "", "")
FLAG_MANAGER_SERVER_FLAG(use_adpf_cpu_hint, "debug.sf.enable_adpf_cpu_hint",
                         "AdpfFeature__adpf_cpu_hint")
FLAG_MANAGER_SERVER_FLAG(use_skia_tracing, PROPERTY_SKIA_ATRACE_ENABLED,
                         "SkiaTracingFeature__use_skia_tracing")

#undef FLAG_MANAGER_SERVER_FLAG

} // namespace android
