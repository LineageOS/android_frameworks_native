/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "PowerHalControllerBenchmarks"

#include <benchmark/benchmark.h>
#include <vibratorservice/VibratorHalController.h>

using ::android::enum_range;
using ::benchmark::Counter;
using ::benchmark::Fixture;
using ::benchmark::kMicrosecond;
using ::benchmark::State;
using ::benchmark::internal::Benchmark;

using namespace android;
using namespace std::chrono_literals;

class VibratorBench : public Fixture {
public:
    void SetUp(State& /*state*/) override { mController.init(); }

    void TearDown(State& /*state*/) override { mController.off(); }

    static void DefaultConfig(Benchmark* b) { b->Unit(kMicrosecond); }

    static void DefaultArgs(Benchmark* /*b*/) {
        // none
    }

protected:
    vibrator::HalController mController;

    auto getOtherArg(const State& state, std::size_t index) const { return state.range(index + 0); }

    bool hasCapabilities(vibrator::HalResult<vibrator::Capabilities> result,
                         vibrator::Capabilities query) {
        if (!result.isOk()) {
            return false;
        }
        return (result.value() | query) == query;
    }
};

#define BENCHMARK_WRAPPER(fixt, test, code)                \
    BENCHMARK_DEFINE_F(fixt, test)                         \
    /* NOLINTNEXTLINE */                                   \
    (State& state){code} BENCHMARK_REGISTER_F(fixt, test) \
            ->Apply(fixt::DefaultConfig)                   \
            ->Apply(fixt::DefaultArgs)

BENCHMARK_WRAPPER(VibratorBench, init, {
    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        state.ResumeTiming();
        controller.init();
    }
});

BENCHMARK_WRAPPER(VibratorBench, initCached, {
    for (auto _ : state) {
        mController.init();
    }
});

BENCHMARK_WRAPPER(VibratorBench, ping, {
    for (auto _ : state) {
        mController.ping();
    }
});

BENCHMARK_WRAPPER(VibratorBench, tryReconnect, {
    for (auto _ : state) {
        mController.tryReconnect();
    }
});

BENCHMARK_WRAPPER(VibratorBench, on, {
    auto duration = 60s;
    auto callback = []() {};

    for (auto _ : state) {
        state.ResumeTiming();
        mController.on(duration, callback);
        state.PauseTiming();
        mController.off();
    }
});

BENCHMARK_WRAPPER(VibratorBench, off, {
    auto duration = 60s;
    auto callback = []() {};

    for (auto _ : state) {
        state.PauseTiming();
        mController.on(duration, callback);
        state.ResumeTiming();
        mController.off();
    }
});

BENCHMARK_WRAPPER(VibratorBench, setAmplitude, {
    auto capabilitiesResult = mController.getCapabilities();

    if (!hasCapabilities(capabilitiesResult, vibrator::Capabilities::AMPLITUDE_CONTROL)) {
        return;
    }

    auto duration = 60s;
    auto callback = []() {};
    auto amplitude = UINT8_MAX;

    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        controller.on(duration, callback);
        state.ResumeTiming();
        controller.setAmplitude(amplitude);
        state.PauseTiming();
        controller.off();
    }
});

BENCHMARK_WRAPPER(VibratorBench, setAmplitudeCached, {
    auto capabilitiesResult = mController.getCapabilities();

    if (!hasCapabilities(capabilitiesResult, vibrator::Capabilities::AMPLITUDE_CONTROL)) {
        return;
    }

    auto duration = 6000s;
    auto callback = []() {};
    auto amplitude = UINT8_MAX;

    mController.on(duration, callback);

    for (auto _ : state) {
        mController.setAmplitude(amplitude);
    }

    mController.off();
});

BENCHMARK_WRAPPER(VibratorBench, setExternalControl, {
    auto capabilitiesResult = mController.getCapabilities();

    if (!hasCapabilities(capabilitiesResult, vibrator::Capabilities::EXTERNAL_CONTROL)) {
        return;
    }

    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        state.ResumeTiming();
        controller.setExternalControl(true);
        state.PauseTiming();
        controller.setExternalControl(false);
    }
});

BENCHMARK_WRAPPER(VibratorBench, setExternalControlCached, {
    auto capabilitiesResult = mController.getCapabilities();

    if (!hasCapabilities(capabilitiesResult, vibrator::Capabilities::EXTERNAL_CONTROL)) {
        return;
    }

    for (auto _ : state) {
        state.ResumeTiming();
        mController.setExternalControl(true);
        state.PauseTiming();
        mController.setExternalControl(false);
    }
});

BENCHMARK_WRAPPER(VibratorBench, setExternalAmplitudeCached, {
    auto capabilitiesResult = mController.getCapabilities();

    if (!hasCapabilities(capabilitiesResult, vibrator::Capabilities::EXTERNAL_AMPLITUDE_CONTROL)) {
        return;
    }

    auto amplitude = UINT8_MAX;

    mController.setExternalControl(true);

    for (auto _ : state) {
        mController.setAmplitude(amplitude);
    }

    mController.setExternalControl(false);
});

BENCHMARK_WRAPPER(VibratorBench, getCapabilities, {
    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        state.ResumeTiming();
        controller.getCapabilities();
    }
});

BENCHMARK_WRAPPER(VibratorBench, getCapabilitiesCached, {
    // First call to cache values.
    mController.getCapabilities();

    for (auto _ : state) {
        mController.getCapabilities();
    }
});

BENCHMARK_WRAPPER(VibratorBench, getSupportedEffects, {
    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        state.ResumeTiming();
        controller.getSupportedEffects();
    }
});

BENCHMARK_WRAPPER(VibratorBench, getSupportedEffectsCached, {
    // First call to cache values.
    mController.getSupportedEffects();

    for (auto _ : state) {
        mController.getSupportedEffects();
    }
});

BENCHMARK_WRAPPER(VibratorBench, getSupportedPrimitives, {
    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        state.ResumeTiming();
        controller.getSupportedPrimitives();
    }
});

BENCHMARK_WRAPPER(VibratorBench, getSupportedPrimitivesCached, {
    // First call to cache values.
    mController.getSupportedPrimitives();

    for (auto _ : state) {
        mController.getSupportedPrimitives();
    }
});

class VibratorEffectsBench : public VibratorBench {
public:
    static void DefaultArgs(Benchmark* b) {
        vibrator::HalController controller;
        auto effectsResult = controller.getSupportedEffects();
        if (!effectsResult.isOk()) {
            return;
        }

        std::vector<hardware::vibrator::Effect> supported = effectsResult.value();
        b->ArgNames({"Effect", "Strength"});
        for (const auto& effect : enum_range<hardware::vibrator::Effect>()) {
            if (std::find(supported.begin(), supported.end(), effect) == supported.end()) {
                continue;
            }
            for (const auto& strength : enum_range<hardware::vibrator::EffectStrength>()) {
                b->Args({static_cast<long>(effect), static_cast<long>(strength)});
            }
        }
    }

protected:
    auto getEffect(const State& state) const {
        return static_cast<hardware::vibrator::Effect>(this->getOtherArg(state, 0));
    }

    auto getStrength(const State& state) const {
        return static_cast<hardware::vibrator::EffectStrength>(this->getOtherArg(state, 1));
    }
};

BENCHMARK_WRAPPER(VibratorEffectsBench, alwaysOnEnable, {
    auto capabilitiesResult = mController.getCapabilities();

    if (!hasCapabilities(capabilitiesResult, vibrator::Capabilities::ALWAYS_ON_CONTROL)) {
        return;
    }

    int32_t id = 1;
    auto effect = getEffect(state);
    auto strength = getStrength(state);

    for (auto _ : state) {
        state.ResumeTiming();
        mController.alwaysOnEnable(id, effect, strength);
        state.PauseTiming();
        mController.alwaysOnDisable(id);
    }
});

BENCHMARK_WRAPPER(VibratorEffectsBench, alwaysOnDisable, {
    auto capabilitiesResult = mController.getCapabilities();

    if (!hasCapabilities(capabilitiesResult, vibrator::Capabilities::ALWAYS_ON_CONTROL)) {
        return;
    }

    int32_t id = 1;
    auto effect = getEffect(state);
    auto strength = getStrength(state);

    for (auto _ : state) {
        state.PauseTiming();
        mController.alwaysOnEnable(id, effect, strength);
        state.ResumeTiming();
        mController.alwaysOnDisable(id);
    }
});

BENCHMARK_WRAPPER(VibratorEffectsBench, performEffect, {
    auto effect = getEffect(state);
    auto strength = getStrength(state);
    auto callback = []() {};

    for (auto _ : state) {
        state.ResumeTiming();
        mController.performEffect(effect, strength, callback);
        state.PauseTiming();
        mController.off();
    }
});

class VibratorPrimitivesBench : public VibratorBench {
public:
    static void DefaultArgs(Benchmark* b) {
        vibrator::HalController controller;
        auto primitivesResult = controller.getSupportedPrimitives();
        if (!primitivesResult.isOk()) {
            return;
        }

        std::vector<hardware::vibrator::CompositePrimitive> supported = primitivesResult.value();
        b->ArgNames({"Primitive"});
        for (const auto& primitive : enum_range<hardware::vibrator::CompositePrimitive>()) {
            if (std::find(supported.begin(), supported.end(), primitive) == supported.end()) {
                continue;
            }
            b->Args({static_cast<long>(primitive)});
        }
    }

protected:
    auto getPrimitive(const State& state) const {
        return static_cast<hardware::vibrator::CompositePrimitive>(this->getOtherArg(state, 0));
    }
};

BENCHMARK_WRAPPER(VibratorPrimitivesBench, performComposedEffect, {
    auto capabilitiesResult = mController.getCapabilities();

    if (!hasCapabilities(capabilitiesResult, vibrator::Capabilities::COMPOSE_EFFECTS)) {
        return;
    }

    hardware::vibrator::CompositeEffect effect;
    effect.primitive = getPrimitive(state);
    effect.scale = 1.0f;
    effect.delayMs = 0;

    std::vector<hardware::vibrator::CompositeEffect> effects;
    effects.push_back(effect);
    auto callback = []() {};

    for (auto _ : state) {
        state.ResumeTiming();
        mController.performComposedEffect(effects, callback);
        state.PauseTiming();
        mController.off();
    }
});

BENCHMARK_MAIN();