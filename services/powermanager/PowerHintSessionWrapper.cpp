/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *            http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <powermanager/PowerHintSessionWrapper.h>

using namespace aidl::android::hardware::power;

namespace android::power {

// Caches support for a given call in a static variable, checking both
// the return value and interface version.
#define CACHE_SUPPORT(version, method)                      \
    ({                                                      \
        static bool support = mInterfaceVersion >= version; \
        !support ? decltype(method)::unsupported() : ({     \
            auto result = method;                           \
            if (result.isUnsupported()) {                   \
                support = false;                            \
            }                                               \
            std::move(result);                              \
        });                                                 \
    })

#define CHECK_SESSION(resultType)                                    \
    if (mSession == nullptr) {                                       \
        return HalResult<resultType>::failed("Session not running"); \
    }

// FWD_CALL just forwards calls from the wrapper to the session object.
// It only works if the call has no return object, as is the case with all calls
// except getSessionConfig.
#define FWD_CALL(version, name, args, untypedArgs)                                              \
    HalResult<void> PowerHintSessionWrapper::name args {                                        \
        CHECK_SESSION(void)                                                                     \
        return CACHE_SUPPORT(version, HalResult<void>::fromStatus(mSession->name untypedArgs)); \
    }

PowerHintSessionWrapper::PowerHintSessionWrapper(std::shared_ptr<IPowerHintSession>&& session)
      : mSession(session) {
    if (mSession != nullptr) {
        mSession->getInterfaceVersion(&mInterfaceVersion);
    }
}

// Support for individual hints/modes is not really handled here since there
// is no way to check for it, so in the future if a way to check that is added,
// this will need to be updated.

FWD_CALL(2, updateTargetWorkDuration, (int64_t in_targetDurationNanos), (in_targetDurationNanos));
FWD_CALL(2, reportActualWorkDuration, (const std::vector<WorkDuration>& in_durations),
         (in_durations));
FWD_CALL(2, pause, (), ());
FWD_CALL(2, resume, (), ());
FWD_CALL(2, close, (), ());
FWD_CALL(4, sendHint, (SessionHint in_hint), (in_hint));
FWD_CALL(4, setThreads, (const std::vector<int32_t>& in_threadIds), (in_threadIds));
FWD_CALL(5, setMode, (SessionMode in_type, bool in_enabled), (in_type, in_enabled));

HalResult<SessionConfig> PowerHintSessionWrapper::getSessionConfig() {
    CHECK_SESSION(SessionConfig);
    SessionConfig config;
    return CACHE_SUPPORT(5,
                         HalResult<SessionConfig>::fromStatus(mSession->getSessionConfig(&config),
                                                              std::move(config)));
}

} // namespace android::power
