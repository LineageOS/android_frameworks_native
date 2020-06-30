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

#define LOG_TAG "PowerHalControllerBenchmarks"

#include <android/hardware/power/Boost.h>
#include <android/hardware/power/Mode.h>

#include <benchmark/benchmark.h>

#include <powermanager/PowerHalController.h>

using android::hardware::power::Boost;
using android::hardware::power::Mode;
using android::power::PowerHalController;

using namespace android;

static void BM_PowerHalControllerBenchmarks_init(benchmark::State& state) {
    while (state.KeepRunning()) {
        PowerHalController controller;
        controller.init();
    }
}

static void BM_PowerHalControllerBenchmarks_initCached(benchmark::State& state) {
    PowerHalController controller;
    // First connection out of test.
    controller.init();

    while (state.KeepRunning()) {
        controller.init();
    }
}

static void BM_PowerHalControllerBenchmarks_setBoost(benchmark::State& state) {
    while (state.KeepRunning()) {
        PowerHalController controller;
        controller.setBoost(Boost::INTERACTION, 0);
    }
}

static void BM_PowerHalControllerBenchmarks_setBoostCached(benchmark::State& state) {
    PowerHalController controller;
    // First call out of test, to cache supported boost.
    controller.setBoost(Boost::INTERACTION, 0);

    while (state.KeepRunning()) {
        controller.setBoost(Boost::INTERACTION, 0);
    }
}

static void BM_PowerHalControllerBenchmarks_setMode(benchmark::State& state) {
    while (state.KeepRunning()) {
        PowerHalController controller;
        controller.setMode(Mode::INTERACTIVE, false);
    }
}

static void BM_PowerHalControllerBenchmarks_setModeCached(benchmark::State& state) {
    PowerHalController controller;
    // First call out of test, to cache supported mode.
    controller.setMode(Mode::INTERACTIVE, false);

    while (state.KeepRunning()) {
        controller.setMode(Mode::INTERACTIVE, false);
    }
}

BENCHMARK(BM_PowerHalControllerBenchmarks_init);
BENCHMARK(BM_PowerHalControllerBenchmarks_initCached);
BENCHMARK(BM_PowerHalControllerBenchmarks_setBoost);
BENCHMARK(BM_PowerHalControllerBenchmarks_setBoostCached);
BENCHMARK(BM_PowerHalControllerBenchmarks_setMode);
BENCHMARK(BM_PowerHalControllerBenchmarks_setModeCached);
