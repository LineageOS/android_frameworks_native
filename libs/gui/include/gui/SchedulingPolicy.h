/*
 * Copyright 2023 The Android Open Source Project
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

#include <sched.h>

#include <android/gui/SchedulingPolicy.h>
#include <binder/Status.h>

namespace android::gui {

static binder::Status getSchedulingPolicy(gui::SchedulingPolicy* outPolicy) {
    outPolicy->policy = sched_getscheduler(0);
    if (outPolicy->policy < 0) {
        return binder::Status::fromExceptionCode(EX_ILLEGAL_STATE);
    }

    struct sched_param param;
    if (sched_getparam(0, &param) < 0) {
        return binder::Status::fromExceptionCode(EX_ILLEGAL_STATE);
    }
    outPolicy->priority = param.sched_priority;
    return binder::Status::ok();
}

} // namespace android::gui