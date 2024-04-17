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

#define LOG_TAG "VibratorHalControllerBenchmarks"

#include <benchmark/benchmark.h>
#include <binder/ProcessState.h>
#include <vibratorservice/VibratorHalController.h>
#include <future>

using ::android::enum_range;
using ::android::hardware::vibrator::CompositeEffect;
using ::android::hardware::vibrator::CompositePrimitive;
using ::android::hardware::vibrator::Effect;
using ::android::hardware::vibrator::EffectStrength;
using ::benchmark::Counter;
using ::benchmark::Fixture;
using ::benchmark::kMicrosecond;
using ::benchmark::State;
using ::benchmark::internal::Benchmark;

using std::chrono::milliseconds;

using namespace android;
using namespace std::chrono_literals;

// Fixed number of iterations for benchmarks that trigger a vibration on the loop.
// They require slow cleanup to ensure a stable state on each run and less noisy metrics.
static constexpr auto VIBRATION_ITERATIONS = 500;

// Timeout to wait for vibration callback completion.
static constexpr auto VIBRATION_CALLBACK_TIMEOUT = 100ms;

// Max duration the vibrator can be turned on, in milliseconds.
static constexpr auto MAX_ON_DURATION_MS = milliseconds(UINT16_MAX);

// Helper to wait for the vibrator to become idle between vibrate bench iterations.
class HalCallback {
public:
    HalCallback(std::function<void()>&& waitFn, std::function<void()>&& completeFn)
          : mWaitFn(std::move(waitFn)), mCompleteFn(std::move(completeFn)) {}
    ~HalCallback() = default;

    std::function<void()> completeFn() const { return mCompleteFn; }

    void waitForComplete() const { mWaitFn(); }

private:
    std::function<void()> mWaitFn;
    std::function<void()> mCompleteFn;
};

// Helper for vibration callbacks, kept by the Fixture until all pending callbacks are done.
class HalCallbacks {
public:
    HalCallback next() {
        std::unique_lock<std::mutex> lock(mMutex);
        auto id = mCurrentId++;
        mPendingPromises[id] = std::promise<void>();
        mPendingFutures[id] = mPendingPromises[id].get_future(); // Can only be called once.
        return HalCallback([&, id]() { waitForComplete(id); }, [&, id]() { onComplete(id); });
    }

    void onComplete(int32_t id) {
        std::unique_lock<std::mutex> lock(mMutex);
        auto promise = mPendingPromises.find(id);
        if (promise != mPendingPromises.end()) {
            promise->second.set_value();
            mPendingPromises.erase(promise);
        }
    }

    void waitForComplete(int32_t id) {
        // Wait until the HAL has finished processing previous vibration before starting a new one,
        // so the HAL state is consistent on each run and metrics are less noisy. Some of the newest
        // HAL implementations are waiting on previous vibration cleanup and might be significantly
        // slower, so make sure we measure vibrations on a clean slate.
        if (mPendingFutures[id].wait_for(VIBRATION_CALLBACK_TIMEOUT) == std::future_status::ready) {
            mPendingFutures.erase(id);
        }
    }

    void waitForPending() {
        // Wait for pending callbacks from the test, possibly skipped with error.
        for (auto& [id, future] : mPendingFutures) {
            future.wait_for(VIBRATION_CALLBACK_TIMEOUT);
        }
        mPendingFutures.clear();
        {
            std::unique_lock<std::mutex> lock(mMutex);
            mPendingPromises.clear();
        }
    }

private:
    std::mutex mMutex;
    std::map<int32_t, std::promise<void>> mPendingPromises GUARDED_BY(mMutex);
    std::map<int32_t, std::future<void>> mPendingFutures;
    int32_t mCurrentId;
};

class VibratorBench : public Fixture {
public:
    void SetUp(State& /*state*/) override {
        android::ProcessState::self()->setThreadPoolMaxThreadCount(1);
        android::ProcessState::self()->startThreadPool();
        mController.init();
    }

    void TearDown(State& /*state*/) override {
        turnVibratorOff();
        disableExternalControl();
        mCallbacks.waitForPending();
    }

    static void DefaultConfig(Benchmark* b) { b->Unit(kMicrosecond); }

    static void DefaultArgs(Benchmark* /*b*/) {
        // none
    }

protected:
    vibrator::HalController mController;
    HalCallbacks mCallbacks;

    static void SlowBenchConfig(Benchmark* b) { b->Iterations(VIBRATION_ITERATIONS); }

    auto getOtherArg(const State& state, std::size_t index) const { return state.range(index + 0); }

    vibrator::HalResult<void> turnVibratorOff() {
        return mController.doWithRetry<void>([](auto hal) { return hal->off(); }, "off");
    }

    vibrator::HalResult<void> disableExternalControl() {
        auto disableExternalControlFn = [](auto hal) { return hal->setExternalControl(false); };
        return mController.doWithRetry<void>(disableExternalControlFn, "setExternalControl false");
    }

    bool shouldSkipWithMissingCapabilityMessage(vibrator::Capabilities query, State& state) {
        auto result = mController.getInfo().capabilities;
        if (result.isFailed()) {
            state.SkipWithError(result.errorMessage());
            return true;
        }
        if (!result.isOk()) {
            state.SkipWithMessage("capability result is unsupported");
            return true;
        }
        if ((result.value() & query) != query) {
            state.SkipWithMessage("missing capability");
            return true;
        }
        return false;
    }

    template <class R>
    bool shouldSkipWithError(const vibrator::HalFunction<vibrator::HalResult<R>>& halFn,
                             const char* label, State& state) {
        return shouldSkipWithError(mController.doWithRetry<R>(halFn, label), state);
    }

    template <class R>
    bool shouldSkipWithError(const vibrator::HalResult<R>& result, State& state) {
        if (result.isFailed()) {
            state.SkipWithError(result.errorMessage());
            return true;
        }
        return false;
    }
};

class SlowVibratorBench : public VibratorBench {
public:
    static void DefaultConfig(Benchmark* b) {
        VibratorBench::DefaultConfig(b);
        SlowBenchConfig(b);
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
        // Setup
        state.PauseTiming();
        vibrator::HalController controller;
        state.ResumeTiming();

        // Test
        controller.init();
    }
});

BENCHMARK_WRAPPER(VibratorBench, initCached, {
    // First call to cache values.
    mController.init();

    for (auto _ : state) {
        mController.init();
    }
});

BENCHMARK_WRAPPER(VibratorBench, ping, {
    auto pingFn = [](auto hal) { return hal->ping(); };

    for (auto _ : state) {
        if (shouldSkipWithError<void>(pingFn, "ping", state)) {
            return;
        }
    }
});

BENCHMARK_WRAPPER(VibratorBench, tryReconnect, {
    for (auto _ : state) {
        mController.tryReconnect();
    }
});

BENCHMARK_WRAPPER(SlowVibratorBench, on, {
    auto duration = MAX_ON_DURATION_MS;

    for (auto _ : state) {
        // Setup
        state.PauseTiming();
        auto cb = mCallbacks.next();
        auto onFn = [&](auto hal) { return hal->on(duration, cb.completeFn()); };
        state.ResumeTiming();

        // Test
        if (shouldSkipWithError<void>(onFn, "on", state)) {
            return;
        }

        // Cleanup
        state.PauseTiming();
        if (shouldSkipWithError(turnVibratorOff(), state)) {
            return;
        }
        cb.waitForComplete();
        state.ResumeTiming();
    }
});

BENCHMARK_WRAPPER(SlowVibratorBench, off, {
    auto duration = MAX_ON_DURATION_MS;

    for (auto _ : state) {
        // Setup
        state.PauseTiming();
        auto cb = mCallbacks.next();
        auto onFn = [&](auto hal) { return hal->on(duration, cb.completeFn()); };
        if (shouldSkipWithError<void>(onFn, "on", state)) {
            return;
        }
        auto offFn = [&](auto hal) { return hal->off(); };
        state.ResumeTiming();

        // Test
        if (shouldSkipWithError<void>(offFn, "off", state)) {
            return;
        }

        // Cleanup
        state.PauseTiming();
        cb.waitForComplete();
        state.ResumeTiming();
    }
});

BENCHMARK_WRAPPER(VibratorBench, setAmplitude, {
    if (shouldSkipWithMissingCapabilityMessage(vibrator::Capabilities::AMPLITUDE_CONTROL, state)) {
        return;
    }

    auto duration = MAX_ON_DURATION_MS;
    auto amplitude = 1.0f;
    auto setAmplitudeFn = [&](auto hal) { return hal->setAmplitude(amplitude); };

    auto onFn = [&](auto hal) { return hal->on(duration, [&]() {}); };
    if (shouldSkipWithError<void>(onFn, "on", state)) {
        return;
    }

    for (auto _ : state) {
        if (shouldSkipWithError<void>(setAmplitudeFn, "setAmplitude", state)) {
            return;
        }
    }
});

BENCHMARK_WRAPPER(VibratorBench, setExternalControl, {
    if (shouldSkipWithMissingCapabilityMessage(vibrator::Capabilities::EXTERNAL_CONTROL, state)) {
        return;
    }

    auto enableExternalControlFn = [](auto hal) { return hal->setExternalControl(true); };

    for (auto _ : state) {
        // Test
        if (shouldSkipWithError<void>(enableExternalControlFn, "setExternalControl true", state)) {
            return;
        }

        // Cleanup
        state.PauseTiming();
        if (shouldSkipWithError(disableExternalControl(), state)) {
            return;
        }
        state.ResumeTiming();
    }
});

BENCHMARK_WRAPPER(VibratorBench, setExternalAmplitude, {
    auto externalAmplitudeControl = vibrator::Capabilities::EXTERNAL_CONTROL &
            vibrator::Capabilities::EXTERNAL_AMPLITUDE_CONTROL;
    if (shouldSkipWithMissingCapabilityMessage(externalAmplitudeControl, state)) {
        return;
    }

    auto amplitude = 1.0f;
    auto setAmplitudeFn = [&](auto hal) { return hal->setAmplitude(amplitude); };
    auto enableExternalControlFn = [](auto hal) { return hal->setExternalControl(true); };

    if (shouldSkipWithError<void>(enableExternalControlFn, "setExternalControl true", state)) {
        return;
    }

    for (auto _ : state) {
        if (shouldSkipWithError<void>(setAmplitudeFn, "setExternalAmplitude", state)) {
            return;
        }
    }
});

BENCHMARK_WRAPPER(VibratorBench, getInfo, {
    for (auto _ : state) {
        // Setup
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        state.ResumeTiming();

        controller.getInfo();
    }
});

BENCHMARK_WRAPPER(VibratorBench, getInfoCached, {
    // First call to cache values.
    mController.getInfo();

    for (auto _ : state) {
        mController.getInfo();
    }
});

class VibratorEffectsBench : public VibratorBench {
public:
    static void DefaultArgs(Benchmark* b) {
        vibrator::HalController controller;
        auto effectsResult = controller.getInfo().supportedEffects;
        if (!effectsResult.isOk()) {
            return;
        }

        std::vector<Effect> supported = effectsResult.value();
        b->ArgNames({"Effect", "Strength"});

        if (supported.empty()) {
            b->Args({static_cast<long>(-1), static_cast<long>(-1)});
            return;
        }

        for (const auto& effect : enum_range<Effect>()) {
            if (std::find(supported.begin(), supported.end(), effect) == supported.end()) {
                continue;
            }
            for (const auto& strength : enum_range<EffectStrength>()) {
                b->Args({static_cast<long>(effect), static_cast<long>(strength)});
            }
        }
    }

protected:
    bool hasArgs(const State& state) const { return this->getOtherArg(state, 0) >= 0; }

    auto getEffect(const State& state) const {
        return static_cast<Effect>(this->getOtherArg(state, 0));
    }

    auto getStrength(const State& state) const {
        return static_cast<EffectStrength>(this->getOtherArg(state, 1));
    }
};

class SlowVibratorEffectsBench : public VibratorEffectsBench {
public:
    static void DefaultConfig(Benchmark* b) {
        VibratorBench::DefaultConfig(b);
        SlowBenchConfig(b);
    }
};

BENCHMARK_WRAPPER(VibratorEffectsBench, alwaysOnEnable, {
    if (shouldSkipWithMissingCapabilityMessage(vibrator::Capabilities::ALWAYS_ON_CONTROL, state)) {
        return;
    }
    if (!hasArgs(state)) {
        state.SkipWithMessage("missing args");
        return;
    }

    int32_t id = 1;
    auto effect = getEffect(state);
    auto strength = getStrength(state);
    auto enableFn = [&](auto hal) { return hal->alwaysOnEnable(id, effect, strength); };
    auto disableFn = [&](auto hal) { return hal->alwaysOnDisable(id); };

    for (auto _ : state) {
        // Test
        if (shouldSkipWithError<void>(enableFn, "alwaysOnEnable", state)) {
            return;
        }

        // Cleanup
        state.PauseTiming();
        if (shouldSkipWithError<void>(disableFn, "alwaysOnDisable", state)) {
            return;
        }
        state.ResumeTiming();
    }
});

BENCHMARK_WRAPPER(VibratorEffectsBench, alwaysOnDisable, {
    if (shouldSkipWithMissingCapabilityMessage(vibrator::Capabilities::ALWAYS_ON_CONTROL, state)) {
        return;
    }
    if (!hasArgs(state)) {
        state.SkipWithMessage("missing args");
        return;
    }

    int32_t id = 1;
    auto effect = getEffect(state);
    auto strength = getStrength(state);
    auto enableFn = [&](auto hal) { return hal->alwaysOnEnable(id, effect, strength); };
    auto disableFn = [&](auto hal) { return hal->alwaysOnDisable(id); };

    for (auto _ : state) {
        // Setup
        state.PauseTiming();
        if (shouldSkipWithError<void>(enableFn, "alwaysOnEnable", state)) {
            return;
        }
        state.ResumeTiming();

        // Test
        if (shouldSkipWithError<void>(disableFn, "alwaysOnDisable", state)) {
            return;
        }
    }
});

BENCHMARK_WRAPPER(SlowVibratorEffectsBench, performEffect, {
    if (!hasArgs(state)) {
        state.SkipWithMessage("missing args");
        return;
    }

    auto effect = getEffect(state);
    auto strength = getStrength(state);

    for (auto _ : state) {
        // Setup
        state.PauseTiming();
        auto cb = mCallbacks.next();
        auto performFn = [&](auto hal) {
            return hal->performEffect(effect, strength, cb.completeFn());
        };
        state.ResumeTiming();

        // Test
        if (shouldSkipWithError<milliseconds>(performFn, "performEffect", state)) {
            return;
        }

        // Cleanup
        state.PauseTiming();
        if (shouldSkipWithError(turnVibratorOff(), state)) {
            return;
        }
        cb.waitForComplete();
        state.ResumeTiming();
    }
});

class SlowVibratorPrimitivesBench : public VibratorBench {
public:
    static void DefaultConfig(Benchmark* b) {
        VibratorBench::DefaultConfig(b);
        SlowBenchConfig(b);
    }

    static void DefaultArgs(Benchmark* b) {
        vibrator::HalController controller;
        auto primitivesResult = controller.getInfo().supportedPrimitives;
        if (!primitivesResult.isOk()) {
            return;
        }

        std::vector<CompositePrimitive> supported = primitivesResult.value();
        b->ArgNames({"Primitive"});

        if (supported.empty()) {
            b->Args({static_cast<long>(-1)});
            return;
        }

        for (const auto& primitive : enum_range<CompositePrimitive>()) {
            if (std::find(supported.begin(), supported.end(), primitive) == supported.end()) {
                continue;
            }
            if (primitive == CompositePrimitive::NOOP) {
                continue;
            }
            b->Args({static_cast<long>(primitive)});
        }
    }

protected:
    bool hasArgs(const State& state) const { return this->getOtherArg(state, 0) >= 0; }

    auto getPrimitive(const State& state) const {
        return static_cast<CompositePrimitive>(this->getOtherArg(state, 0));
    }
};

BENCHMARK_WRAPPER(SlowVibratorPrimitivesBench, performComposedEffect, {
    if (shouldSkipWithMissingCapabilityMessage(vibrator::Capabilities::COMPOSE_EFFECTS, state)) {
        return;
    }
    if (!hasArgs(state)) {
        state.SkipWithMessage("missing args");
        return;
    }

    CompositeEffect effect;
    effect.primitive = getPrimitive(state);
    effect.scale = 1.0f;
    effect.delayMs = static_cast<int32_t>(0);

    std::vector<CompositeEffect> effects = {effect};

    for (auto _ : state) {
        // Setup
        state.PauseTiming();
        auto cb = mCallbacks.next();
        auto performFn = [&](auto hal) {
            return hal->performComposedEffect(effects, cb.completeFn());
        };
        state.ResumeTiming();

        // Test
        if (shouldSkipWithError<milliseconds>(performFn, "performComposedEffect", state)) {
            return;
        }

        // Cleanup
        state.PauseTiming();
        if (shouldSkipWithError(turnVibratorOff(), state)) {
            return;
        }
        cb.waitForComplete();
        state.ResumeTiming();
    }
});

BENCHMARK_MAIN();
