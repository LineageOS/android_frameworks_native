/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "PowerHalHidlBenchmarks"

#include <android/hardware/power/1.1/IPower.h>
#include <android/hardware/power/Boost.h>
#include <android/hardware/power/IPower.h>
#include <android/hardware/power/Mode.h>

#include <benchmark/benchmark.h>

#include <hardware/power.h>
#include <hardware_legacy/power.h>

using android::hardware::power::Boost;
using android::hardware::power::Mode;
using android::hardware::power::V1_0::Feature;
using android::hardware::power::V1_0::PowerHint;
using IPower1_0 = android::hardware::power::V1_0::IPower;
using IPower1_1 = android::hardware::power::V1_1::IPower;

using namespace android;

template <class R, class I, class... Args0, class... Args1>
static void runBenchmark(benchmark::State& state, R (I::*fn)(Args0...), Args1&&... args1) {
    sp<I> hal = I::getService();

    if (hal == nullptr) {
        ALOGI("Power HAL HIDL not available, skipping test...");
        return;
    }

    while (state.KeepRunning()) {
        (*hal.*fn)(std::forward<Args1>(args1)...);
    }
}

static void BM_PowerHalHidlBenchmarks_setFeature(benchmark::State& state) {
    runBenchmark(state, &IPower1_0::setFeature, Feature::POWER_FEATURE_DOUBLE_TAP_TO_WAKE, false);
}

static void BM_PowerHalHidlBenchmarks_setInteractive(benchmark::State& state) {
    runBenchmark(state, &IPower1_0::setInteractive, false);
}

static void BM_PowerHalHidlBenchmarks_powerHint(benchmark::State& state) {
    runBenchmark(state, &IPower1_0::powerHint, PowerHint::INTERACTION, 0);
}

static void BM_PowerHalHidlBenchmarks_powerHintAsync(benchmark::State& state) {
    runBenchmark(state, &IPower1_1::powerHintAsync, PowerHint::INTERACTION, 0);
}

BENCHMARK(BM_PowerHalHidlBenchmarks_setFeature);
BENCHMARK(BM_PowerHalHidlBenchmarks_setInteractive);
BENCHMARK(BM_PowerHalHidlBenchmarks_powerHint);
BENCHMARK(BM_PowerHalHidlBenchmarks_powerHintAsync);
