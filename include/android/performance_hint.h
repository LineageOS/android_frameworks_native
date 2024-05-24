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

 /**
 * @defgroup APerformanceHint Performance Hint Manager
 *
 * APerformanceHint allows apps to create performance hint sessions for groups
 * of threads, and provide hints to the system about the workload of those threads,
 * to help the system more accurately allocate power for them. It is the NDK
 * counterpart to the Java PerformanceHintManager SDK API.
 *
 * @{
 */

/**
 * @file performance_hint.h
 * @brief API for creating and managing a hint session.
 */


#ifndef ANDROID_NATIVE_PERFORMANCE_HINT_H
#define ANDROID_NATIVE_PERFORMANCE_HINT_H

#include <sys/cdefs.h>

/******************************************************************
 *
 * IMPORTANT NOTICE:
 *
 *   This file is part of Android's set of stable system headers
 *   exposed by the Android NDK (Native Development Kit).
 *
 *   Third-party source AND binary code relies on the definitions
 *   here to be FROZEN ON ALL UPCOMING PLATFORM RELEASES.
 *
 *   - DO NOT MODIFY ENUMS (EXCEPT IF YOU ADD NEW 32-BIT VALUES)
 *   - DO NOT MODIFY CONSTANTS OR FUNCTIONAL MACROS
 *   - DO NOT CHANGE THE SIGNATURE OF FUNCTIONS IN ANY WAY
 *   - DO NOT CHANGE THE LAYOUT OR SIZE OF STRUCTURES
 */

#include <android/api-level.h>
#include <stdint.h>
#include <unistd.h>

__BEGIN_DECLS

struct APerformanceHintManager;
struct APerformanceHintSession;
struct AWorkDuration;

/**
 * {@link AWorkDuration} is an opaque type that represents the breakdown of the
 * actual workload duration in each component internally.
 *
 * A new {@link AWorkDuration} can be obtained using
 * {@link AWorkDuration_create()}, when the client finishes using
 * {@link AWorkDuration}, {@link AWorkDuration_release()} must be
 * called to destroy and free up the resources associated with
 * {@link AWorkDuration}.
 *
 * This file provides a set of functions to allow clients to set the measured
 * work duration of each component on {@link AWorkDuration}.
 *
 * - AWorkDuration_setWorkPeriodStartTimestampNanos()
 * - AWorkDuration_setActualTotalDurationNanos()
 * - AWorkDuration_setActualCpuDurationNanos()
 * - AWorkDuration_setActualGpuDurationNanos()
 */
typedef struct AWorkDuration AWorkDuration;

/**
 * An opaque type representing a handle to a performance hint manager.
 * It must be released after use.
 *
 * To use:<ul>
 *    <li>Obtain the performance hint manager instance by calling
 *        {@link APerformanceHint_getManager} function.</li>
 *    <li>Create an {@link APerformanceHintSession} with
 *        {@link APerformanceHint_createSession}.</li>
 *    <li>Get the preferred update rate in nanoseconds with
 *        {@link APerformanceHint_getPreferredUpdateRateNanos}.</li>
 */
typedef struct APerformanceHintManager APerformanceHintManager;

/**
 * An opaque type representing a handle to a performance hint session.
 * A session can only be acquired from a {@link APerformanceHintManager}
 * with {@link APerformanceHint_createSession}. It must be
 * freed with {@link APerformanceHint_closeSession} after use.
 *
 * A Session represents a group of threads with an inter-related workload such that hints for
 * their performance should be considered as a unit. The threads in a given session should be
 * long-lived and not created or destroyed dynamically.
 *
 * The work duration API can be used with periodic workloads to dynamically adjust thread
 * performance and keep the work on schedule while optimizing the available power budget.
 * When using the work duration API, the starting target duration should be specified
 * while creating the session, and can later be adjusted with
 * {@link APerformanceHint_updateTargetWorkDuration}. While using the work duration
 * API, the client is expected to call {@link APerformanceHint_reportActualWorkDuration} each
 * cycle to report the actual time taken to complete to the system.
 *
 * All timings should be from `std::chrono::steady_clock` or `clock_gettime(CLOCK_MONOTONIC, ...)`
 */
typedef struct APerformanceHintSession APerformanceHintSession;

/**
  * Acquire an instance of the performance hint manager.
  *
  * @return APerformanceHintManager instance on success, nullptr on failure.
  */
APerformanceHintManager* _Nullable APerformanceHint_getManager()
                         __INTRODUCED_IN(__ANDROID_API_T__);

/**
 * Creates a session for the given set of threads and sets their initial target work
 * duration.
 *
 * @param manager The performance hint manager instance.
 * @param threadIds The list of threads to be associated with this session. They must be part of
 *     this process' thread group.
 * @param size The size of the list of threadIds.
 * @param initialTargetWorkDurationNanos The target duration in nanoseconds for the new session.
 *     This must be positive if using the work duration API, or 0 otherwise.
 * @return APerformanceHintManager instance on success, nullptr on failure.
 */
APerformanceHintSession* _Nullable APerformanceHint_createSession(
        APerformanceHintManager* _Nonnull manager,
        const int32_t* _Nonnull threadIds, size_t size,
        int64_t initialTargetWorkDurationNanos) __INTRODUCED_IN(__ANDROID_API_T__);

/**
 * Get preferred update rate information for this device.
 *
 * @param manager The performance hint manager instance.
 * @return the preferred update rate supported by device software.
 */
int64_t APerformanceHint_getPreferredUpdateRateNanos(
        APerformanceHintManager* _Nonnull manager) __INTRODUCED_IN(__ANDROID_API_T__);

/**
 * Updates this session's target duration for each cycle of work.
 *
 * @param session The performance hint session instance to update.
 * @param targetDurationNanos The new desired duration in nanoseconds. This must be positive.
 * @return 0 on success.
 *         EINVAL if targetDurationNanos is not positive.
 *         EPIPE if communication with the system service has failed.
 */
int APerformanceHint_updateTargetWorkDuration(
        APerformanceHintSession* _Nonnull session,
        int64_t targetDurationNanos) __INTRODUCED_IN(__ANDROID_API_T__);

/**
 * Reports the actual duration for the last cycle of work.
 *
 * The system will attempt to adjust the scheduling and performance of the
 * threads within the thread group to bring the actual duration close to the target duration.
 *
 * @param session The performance hint session instance to update.
 * @param actualDurationNanos The duration of time the thread group took to complete its last
 *     task in nanoseconds. This must be positive.
 * @return 0 on success.
 *         EINVAL if actualDurationNanos is not positive.
 *         EPIPE if communication with the system service has failed.
 */
int APerformanceHint_reportActualWorkDuration(
        APerformanceHintSession* _Nonnull session,
        int64_t actualDurationNanos) __INTRODUCED_IN(__ANDROID_API_T__);

/**
 * Release the performance hint manager pointer acquired via
 * {@link APerformanceHint_createSession}.
 *
 * @param session The performance hint session instance to release.
 */
void APerformanceHint_closeSession(
        APerformanceHintSession* _Nonnull session) __INTRODUCED_IN(__ANDROID_API_T__);

/**
 * Set a list of threads to the performance hint session. This operation will replace
 * the current list of threads with the given list of threads.
 *
 * @param session The performance hint session instance to update.
 * @param threadIds The list of threads to be associated with this session. They must be part of
 *     this app's thread group.
 * @param size The size of the list of threadIds.
 * @return 0 on success.
 *         EINVAL if the list of thread ids is empty or if any of the thread ids are not part of
               the thread group.
 *         EPIPE if communication with the system service has failed.
 *         EPERM if any thread id doesn't belong to the application.
 */
int APerformanceHint_setThreads(
        APerformanceHintSession* _Nonnull session,
        const pid_t* _Nonnull threadIds,
        size_t size) __INTRODUCED_IN(__ANDROID_API_U__);

/**
 * This tells the session that these threads can be
 * safely scheduled to prefer power efficiency over performance.
 *
 * @param session The performance hint session instance to update.
 * @param enabled The flag which sets whether this session will use power-efficient scheduling.
 * @return 0 on success.
 *         EPIPE if communication with the system service has failed.
 */
int APerformanceHint_setPreferPowerEfficiency(
        APerformanceHintSession* _Nonnull session,
        bool enabled) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Reports the durations for the last cycle of work.
 *
 * The system will attempt to adjust the scheduling and performance of the
 * threads within the thread group to bring the actual duration close to the target duration.
 *
 * @param session The {@link APerformanceHintSession} instance to update.
 * @param workDuration The {@link AWorkDuration} structure of times the thread group took to
 *     complete its last task in nanoseconds breaking down into different components.
 *
 *     The work period start timestamp and actual total duration must be greater than zero.
 *
 *     The actual CPU and GPU durations must be greater than or equal to zero, and at least one
 *     of them must be greater than zero. When one of them is equal to zero, it means that type
 *     of work was not measured for this workload.
 *
 * @return 0 on success.
 *         EINVAL if any duration is an invalid number.
 *         EPIPE if communication with the system service has failed.
 */
int APerformanceHint_reportActualWorkDuration2(
        APerformanceHintSession* _Nonnull session,
        AWorkDuration* _Nonnull workDuration) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Creates a new AWorkDuration. When the client finishes using {@link AWorkDuration}, it should
 * call {@link AWorkDuration_release()} to destroy {@link AWorkDuration} and release all resources
 * associated with it.
 *
 * @return AWorkDuration on success and nullptr otherwise.
 */
AWorkDuration* _Nonnull AWorkDuration_create() __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Destroys {@link AWorkDuration} and free all resources associated to it.
 *
 * @param aWorkDuration The {@link AWorkDuration} created by calling {@link AWorkDuration_create()}
 */
void AWorkDuration_release(AWorkDuration* _Nonnull aWorkDuration)
     __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Sets the work period start timestamp in nanoseconds.
 *
 * @param aWorkDuration The {@link AWorkDuration} created by calling {@link AWorkDuration_create()}
 * @param workPeriodStartTimestampNanos The work period start timestamp in nanoseconds based on
 *        CLOCK_MONOTONIC about when the work starts. This timestamp must be greater than zero.
 */
void AWorkDuration_setWorkPeriodStartTimestampNanos(AWorkDuration* _Nonnull aWorkDuration,
        int64_t workPeriodStartTimestampNanos) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Sets the actual total work duration in nanoseconds.
 *
 * @param aWorkDuration The {@link AWorkDuration} created by calling {@link AWorkDuration_create()}
 * @param actualTotalDurationNanos The actual total work duration in nanoseconds. This number must
 *        be greater than zero.
 */
void AWorkDuration_setActualTotalDurationNanos(AWorkDuration* _Nonnull aWorkDuration,
        int64_t actualTotalDurationNanos) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Sets the actual CPU work duration in nanoseconds.
 *
 * @param aWorkDuration The {@link AWorkDuration} created by calling {@link AWorkDuration_create()}
 * @param actualCpuDurationNanos The actual CPU work duration in nanoseconds. This number must be
 *        greater than or equal to zero. If it is equal to zero, that means the CPU was not
 *        measured.
 */
void AWorkDuration_setActualCpuDurationNanos(AWorkDuration* _Nonnull aWorkDuration,
        int64_t actualCpuDurationNanos) __INTRODUCED_IN(__ANDROID_API_V__);

/**
 * Sets the actual GPU work duration in nanoseconds.
 *
 * @param aWorkDuration The {@link AWorkDuration} created by calling {@link AWorkDuration_create()}.
 * @param actualGpuDurationNanos The actual GPU work duration in nanoseconds, the number must be
 *        greater than or equal to zero. If it is equal to zero, that means the GPU was not
 *        measured.
 */
void AWorkDuration_setActualGpuDurationNanos(AWorkDuration* _Nonnull aWorkDuration,
        int64_t actualGpuDurationNanos) __INTRODUCED_IN(__ANDROID_API_V__);

__END_DECLS

#endif // ANDROID_NATIVE_PERFORMANCE_HINT_H

/** @} */
