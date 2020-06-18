/*
 * Copyright 2020 The Android Open Source Project
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

#include <perfetto/tracing.h>

#include <mutex>

namespace android {

class GpuMem;

class GpuMemTracer {
public:
    class GpuMemDataSource : public perfetto::DataSource<GpuMemDataSource> {
        virtual void OnSetup(const SetupArgs&) override{};
        virtual void OnStart(const StartArgs&) override {
            std::unique_lock<std::mutex> lock(GpuMemTracer::sTraceMutex);
            sTraceStarted = true;
            sCondition.notify_all();
        }
        virtual void OnStop(const StopArgs&) override{};
    };

    ~GpuMemTracer() = default;

    // Sets up the perfetto tracing backend and data source.
    void initialize(std::shared_ptr<GpuMem>);
    // Registers the data source with the perfetto backend. Called as part of initialize()
    // and should not be called manually outside of tests. Public to allow for substituting a
    // perfetto::kInProcessBackend in tests.
    void registerDataSource();

    static constexpr char kGpuMemDataSource[] = "android.gpu.memory";
    static std::condition_variable sCondition;
    static std::mutex sTraceMutex;
    static bool sTraceStarted;

private:
    void traceInitialCounters();
    void threadLoop();

    std::shared_ptr<GpuMem> mGpuMem;
};

} // namespace android
