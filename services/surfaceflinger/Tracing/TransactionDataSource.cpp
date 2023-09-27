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

#include "TransactionDataSource.h"
#include "TransactionTracing.h"

#undef LOG_TAG
#define LOG_TAG "TransactionTracing"

#include <log/log.h>

namespace android {

void TransactionDataSource::Initialize(TransactionTracing& transactionTracing) {
    mTransactionTracing.store(&transactionTracing);

    auto args = perfetto::TracingInitArgs{};
    args.backends = perfetto::kSystemBackend;
    perfetto::Tracing::Initialize(args);

    perfetto::DataSourceDescriptor descriptor;
    descriptor.set_name(kName);
    TransactionDataSource::Register(descriptor);
}

void TransactionDataSource::UnregisterTransactionTracing() {
    mTransactionTracing.store(nullptr);
}

void TransactionDataSource::OnSetup(const TransactionDataSource::SetupArgs& args) {
    const auto configRaw = args.config->surfaceflinger_transactions_config_raw();
    const auto config =
            perfetto::protos::pbzero::SurfaceFlingerTransactionsConfig::Decoder{configRaw};

    if (config.has_mode() && config.mode() != TransactionTracing::Mode::MODE_UNSPECIFIED) {
        mMode = static_cast<TransactionTracing::Mode>(config.mode());
    } else {
        mMode = TransactionTracing::Mode::MODE_CONTINUOUS;
        ALOGD("Received config with unspecified 'mode'. Using 'CONTINUOUS' as default");
    }
}

void TransactionDataSource::OnStart(const StartArgs&) {
    ALOGD("Received OnStart event");
    if (auto* p = mTransactionTracing.load()) {
        p->onStart(mMode);
    }
}

void TransactionDataSource::OnFlush(const FlushArgs&) {
    ALOGD("Received OnFlush event");
    if (auto* p = mTransactionTracing.load()) {
        p->onFlush(mMode);
    }
}

void TransactionDataSource::OnStop(const StopArgs&) {
    ALOGD("Received OnStop event");
}

TransactionTracing::Mode TransactionDataSource::GetMode() const {
    return mMode;
}

std::atomic<TransactionTracing*> TransactionDataSource::mTransactionTracing = nullptr;

} // namespace android

PERFETTO_DEFINE_DATA_SOURCE_STATIC_MEMBERS(android::TransactionDataSource);
