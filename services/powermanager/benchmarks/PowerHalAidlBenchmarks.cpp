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

#define LOG_TAG "PowerHalAidlBenchmarks"

#include <android/hardware/power/Boost.h>
#include <android/hardware/power/IPower.h>
#include <android/hardware/power/Mode.h>

#include <benchmark/benchmark.h>

#include <binder/IServiceManager.h>

using android::hardware::power::Boost;
using android::hardware::power::IPower;
using android::hardware::power::Mode;

using namespace android;

template <class R, class... Args0, class... Args1>
static void runBenchmark(benchmark::State& state, R (IPower::*fn)(Args0...), Args1&&... args1) {
    sp<IPower> hal = waitForVintfService<IPower>();

    if (hal == nullptr) {
        ALOGI("Power HAL AIDL not available, skipping test...");
        return;
    }

    while (state.KeepRunning()) {
        (*hal.*fn)(std::forward<Args1>(args1)...);
    }
}

static void BM_PowerHalAidlBenchmarks_isBoostSupported(benchmark::State& state) {
    bool isSupported;
    runBenchmark(state, &IPower::isBoostSupported, Boost::INTERACTION, &isSupported);
}

static void BM_PowerHalAidlBenchmarks_isModeSupported(benchmark::State& state) {
    bool isSupported;
    runBenchmark(state, &IPower::isModeSupported, Mode::INTERACTIVE, &isSupported);
}

static void BM_PowerHalAidlBenchmarks_setBoost(benchmark::State& state) {
    runBenchmark(state, &IPower::setBoost, Boost::INTERACTION, 0);
}

static void BM_PowerHalAidlBenchmarks_setMode(benchmark::State& state) {
    runBenchmark(state, &IPower::setMode, Mode::INTERACTIVE, false);
}

BENCHMARK(BM_PowerHalAidlBenchmarks_isBoostSupported);
BENCHMARK(BM_PowerHalAidlBenchmarks_isModeSupported);
BENCHMARK(BM_PowerHalAidlBenchmarks_setBoost);
BENCHMARK(BM_PowerHalAidlBenchmarks_setMode);
