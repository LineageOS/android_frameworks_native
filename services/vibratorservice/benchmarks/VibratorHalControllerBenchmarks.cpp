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

    bool hasCapabilities(const vibrator::HalResult<vibrator::Capabilities>& result,
                         vibrator::Capabilities&& query, State& state) {
        if (result.isFailed()) {
            state.SkipWithError(result.errorMessage());
            return false;
        }
        if (!result.isOk()) {
            return false;
        }
        return (result.value() & query) == query;
    }

    template <class R>
    bool checkHalResult(const vibrator::HalResult<R>& result, State& state) {
        if (result.isFailed()) {
            state.SkipWithError(result.errorMessage());
            return false;
        }
        return true;
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
        state.ResumeTiming();
        auto ret = mController.ping();
        state.PauseTiming();
        checkHalResult(ret, state);
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
        auto ret = mController.on(duration, callback);
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            checkHalResult(mController.off(), state);
        }
    }
});

BENCHMARK_WRAPPER(VibratorBench, off, {
    auto duration = 60s;
    auto callback = []() {};

    for (auto _ : state) {
        state.PauseTiming();
        if (!checkHalResult(mController.on(duration, callback), state)) {
            continue;
        }
        state.ResumeTiming();
        checkHalResult(mController.off(), state);
    }
});

BENCHMARK_WRAPPER(VibratorBench, setAmplitude, {
    auto result = mController.getCapabilities();

    if (!hasCapabilities(result, vibrator::Capabilities::AMPLITUDE_CONTROL, state)) {
        return;
    }

    auto duration = 60s;
    auto callback = []() {};
    auto amplitude = 1.0f;

    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        if (!checkHalResult(controller.on(duration, callback), state)) {
            continue;
        }
        state.ResumeTiming();
        auto ret = controller.setAmplitude(amplitude);
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            checkHalResult(controller.off(), state);
        }
    }
});

BENCHMARK_WRAPPER(VibratorBench, setAmplitudeCached, {
    auto result = mController.getCapabilities();

    if (!hasCapabilities(result, vibrator::Capabilities::AMPLITUDE_CONTROL, state)) {
        return;
    }

    auto duration = 6000s;
    auto callback = []() {};
    auto amplitude = 1.0f;

    checkHalResult(mController.on(duration, callback), state);

    for (auto _ : state) {
        checkHalResult(mController.setAmplitude(amplitude), state);
    }

    checkHalResult(mController.off(), state);
});

BENCHMARK_WRAPPER(VibratorBench, setExternalControl, {
    auto result = mController.getCapabilities();

    if (!hasCapabilities(result, vibrator::Capabilities::EXTERNAL_CONTROL, state)) {
        return;
    }

    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        state.ResumeTiming();
        auto ret = controller.setExternalControl(true);
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            checkHalResult(controller.setExternalControl(false), state);
        }
    }
});

BENCHMARK_WRAPPER(VibratorBench, setExternalControlCached, {
    auto result = mController.getCapabilities();

    if (!hasCapabilities(result, vibrator::Capabilities::EXTERNAL_CONTROL, state)) {
        return;
    }

    for (auto _ : state) {
        state.ResumeTiming();
        auto ret = mController.setExternalControl(true);
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            checkHalResult(mController.setExternalControl(false), state);
        }
    }
});

BENCHMARK_WRAPPER(VibratorBench, setExternalAmplitudeCached, {
    auto result = mController.getCapabilities();

    if (!hasCapabilities(result, vibrator::Capabilities::EXTERNAL_AMPLITUDE_CONTROL, state)) {
        return;
    }

    auto amplitude = 1.0f;

    checkHalResult(mController.setExternalControl(true), state);

    for (auto _ : state) {
        checkHalResult(mController.setAmplitude(amplitude), state);
    }

    checkHalResult(mController.setExternalControl(false), state);
});

BENCHMARK_WRAPPER(VibratorBench, getCapabilities, {
    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        state.ResumeTiming();
        checkHalResult(controller.getCapabilities(), state);
    }
});

BENCHMARK_WRAPPER(VibratorBench, getCapabilitiesCached, {
    // First call to cache values.
    checkHalResult(mController.getCapabilities(), state);

    for (auto _ : state) {
        checkHalResult(mController.getCapabilities(), state);
    }
});

BENCHMARK_WRAPPER(VibratorBench, getSupportedEffects, {
    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        state.ResumeTiming();
        checkHalResult(controller.getSupportedEffects(), state);
    }
});

BENCHMARK_WRAPPER(VibratorBench, getSupportedEffectsCached, {
    // First call to cache values.
    checkHalResult(mController.getSupportedEffects(), state);

    for (auto _ : state) {
        checkHalResult(mController.getSupportedEffects(), state);
    }
});

BENCHMARK_WRAPPER(VibratorBench, getSupportedPrimitives, {
    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        state.ResumeTiming();
        checkHalResult(controller.getSupportedPrimitives(), state);
    }
});

BENCHMARK_WRAPPER(VibratorBench, getSupportedPrimitivesCached, {
    // First call to cache values.
    checkHalResult(mController.getSupportedPrimitives(), state);

    for (auto _ : state) {
        checkHalResult(mController.getSupportedPrimitives(), state);
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

        if (supported.empty()) {
            b->Args({static_cast<long>(-1), static_cast<long>(-1)});
            return;
        }

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
    bool hasArgs(const State& state) const { return this->getOtherArg(state, 0) >= 0; }

    auto getEffect(const State& state) const {
        return static_cast<hardware::vibrator::Effect>(this->getOtherArg(state, 0));
    }

    auto getStrength(const State& state) const {
        return static_cast<hardware::vibrator::EffectStrength>(this->getOtherArg(state, 1));
    }
};

BENCHMARK_WRAPPER(VibratorEffectsBench, alwaysOnEnable, {
    auto result = mController.getCapabilities();

    if (!hasCapabilities(result, vibrator::Capabilities::ALWAYS_ON_CONTROL, state)) {
        return;
    }
    if (!hasArgs(state)) {
        return;
    }

    int32_t id = 1;
    auto effect = getEffect(state);
    auto strength = getStrength(state);

    for (auto _ : state) {
        state.ResumeTiming();
        auto ret = mController.alwaysOnEnable(id, effect, strength);
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            checkHalResult(mController.alwaysOnDisable(id), state);
        }
    }
});

BENCHMARK_WRAPPER(VibratorEffectsBench, alwaysOnDisable, {
    auto result = mController.getCapabilities();

    if (!hasCapabilities(result, vibrator::Capabilities::ALWAYS_ON_CONTROL, state)) {
        return;
    }
    if (!hasArgs(state)) {
        return;
    }

    int32_t id = 1;
    auto effect = getEffect(state);
    auto strength = getStrength(state);

    for (auto _ : state) {
        state.PauseTiming();
        if (!checkHalResult(mController.alwaysOnEnable(id, effect, strength), state)) {
            continue;
        }
        state.ResumeTiming();
        checkHalResult(mController.alwaysOnDisable(id), state);
    }
});

BENCHMARK_WRAPPER(VibratorEffectsBench, performEffect, {
    if (!hasArgs(state)) {
        return;
    }

    auto effect = getEffect(state);
    auto strength = getStrength(state);
    auto callback = []() {};

    for (auto _ : state) {
        state.ResumeTiming();
        auto ret = mController.performEffect(effect, strength, callback);
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            checkHalResult(mController.off(), state);
        }
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

        if (supported.empty()) {
            b->Args({static_cast<long>(-1)});
            return;
        }

        for (const auto& primitive : enum_range<hardware::vibrator::CompositePrimitive>()) {
            if (std::find(supported.begin(), supported.end(), primitive) == supported.end()) {
                continue;
            }
            if (primitive == hardware::vibrator::CompositePrimitive::NOOP) {
                continue;
            }
            b->Args({static_cast<long>(primitive)});
        }
    }

protected:
    bool hasArgs(const State& state) const { return this->getOtherArg(state, 0) >= 0; }

    auto getPrimitive(const State& state) const {
        return static_cast<hardware::vibrator::CompositePrimitive>(this->getOtherArg(state, 0));
    }
};

BENCHMARK_WRAPPER(VibratorPrimitivesBench, performComposedEffect, {
    auto result = mController.getCapabilities();

    if (!hasCapabilities(result, vibrator::Capabilities::COMPOSE_EFFECTS, state)) {
        return;
    }
    if (!hasArgs(state)) {
        return;
    }

    hardware::vibrator::CompositeEffect effect;
    effect.primitive = getPrimitive(state);
    effect.scale = 1.0f;
    effect.delayMs = static_cast<int32_t>(0);

    std::vector<hardware::vibrator::CompositeEffect> effects;
    effects.push_back(effect);
    auto callback = []() {};

    for (auto _ : state) {
        state.ResumeTiming();
        auto ret = mController.performComposedEffect(effects, callback);
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            checkHalResult(mController.off(), state);
        }
    }
});

BENCHMARK_MAIN();