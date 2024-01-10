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

#ifndef ANDROID_PRIVATE_NATIVE_PERFORMANCE_HINT_PRIVATE_H
#define ANDROID_PRIVATE_NATIVE_PERFORMANCE_HINT_PRIVATE_H

#include <stdint.h>

__BEGIN_DECLS

/**
 * For testing only.
 */
void APerformanceHint_setIHintManagerForTesting(void* iManager);

/**
 * Hints for the session used to signal upcoming changes in the mode or workload.
 */
enum SessionHint: int32_t {
    /**
     * This hint indicates a sudden increase in CPU workload intensity. It means
     * that this hint session needs extra CPU resources immediately to meet the
     * target duration for the current work cycle.
     */
    CPU_LOAD_UP = 0,
    /**
     * This hint indicates a decrease in CPU workload intensity. It means that
     * this hint session can reduce CPU resources and still meet the target duration.
     */
    CPU_LOAD_DOWN = 1,
    /*
     * This hint indicates an upcoming CPU workload that is completely changed and
     * unknown. It means that the hint session should reset CPU resources to a known
     * baseline to prepare for an arbitrary load, and must wake up if inactive.
     */
    CPU_LOAD_RESET = 2,
    /*
     * This hint indicates that the most recent CPU workload is resuming after a
     * period of inactivity. It means that the hint session should allocate similar
     * CPU resources to what was used previously, and must wake up if inactive.
     */
    CPU_LOAD_RESUME = 3,

    /**
     * This hint indicates an increase in GPU workload intensity. It means that
     * this hint session needs extra GPU resources to meet the target duration.
     * This hint must be sent before reporting the actual duration to the session.
     */
    GPU_LOAD_UP = 5,

    /**
     * This hint indicates a decrease in GPU workload intensity. It means that
     * this hint session can reduce GPU resources and still meet the target duration.
     */
    GPU_LOAD_DOWN = 6,

    /*
     * This hint indicates an upcoming GPU workload that is completely changed and
     * unknown. It means that the hint session should reset GPU resources to a known
     * baseline to prepare for an arbitrary load, and must wake up if inactive.
     */
    GPU_LOAD_RESET = 7,
};

/**
 * Sends performance hints to inform the hint session of changes in the workload.
 *
 * @param session The performance hint session instance to update.
 * @param hint The hint to send to the session.
 * @return 0 on success
 *         EPIPE if communication with the system service has failed.
 */
int APerformanceHint_sendHint(void* session, SessionHint hint);

/**
 * Return the list of thread ids, this API should only be used for testing only.
 */
int APerformanceHint_getThreadIds(void* aPerformanceHintSession,
                                  int32_t* const threadIds, size_t* const size);

__END_DECLS

#endif // ANDROID_PRIVATE_NATIVE_PERFORMANCE_HINT_PRIVATE_H
