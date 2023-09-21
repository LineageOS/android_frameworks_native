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

#include "TransactionTracing.h"

#include <perfetto/tracing.h>

namespace android {

/*
 * Thread local storage used for fast (lock free) read of data source's properties.
 *
 */
struct TransactionDataSourceTlsState {
    template <typename TraceContext>
    explicit TransactionDataSourceTlsState(const TraceContext& trace_context) {
        auto dataSource = trace_context.GetDataSourceLocked();
        mMode = dataSource.valid() ? dataSource->GetMode()
                                   : TransactionTracing::Mode::MODE_CONTINUOUS;
    }

    TransactionTracing::Mode mMode;
};

struct TransactionDataSourceTraits : public perfetto::DefaultDataSourceTraits {
    using TlsStateType = TransactionDataSourceTlsState;
};

/*
 * Defines the Perfetto custom data source 'android.surfaceflinger.transactions'.
 *
 * Registers the data source with Perfetto, listens to Perfetto events (setup/start/flush/stop)
 * and writes trace packets to Perfetto.
 *
 */
class TransactionDataSource
      : public perfetto::DataSource<TransactionDataSource, TransactionDataSourceTraits> {
public:
    static void Initialize(TransactionTracing&);
    static void UnregisterTransactionTracing();
    void OnSetup(const SetupArgs&) override;
    void OnStart(const StartArgs&) override;
    void OnFlush(const FlushArgs&) override;
    void OnStop(const StopArgs&) override;
    TransactionTracing::Mode GetMode() const;

    static constexpr auto* kName = "android.surfaceflinger.transactions";
    static constexpr perfetto::BufferExhaustedPolicy kBufferExhaustedPolicy =
            perfetto::BufferExhaustedPolicy::kStall;
    static constexpr bool kRequiresCallbacksUnderLock = false;

private:
    static std::atomic<TransactionTracing*> mTransactionTracing;
    TransactionTracing::Mode mMode;
};

} // namespace android

PERFETTO_DECLARE_DATA_SOURCE_STATIC_MEMBERS(android::TransactionDataSource);
