/*
 * Copyright (C) 2022 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "LayerTraceGenerator"

#include <fstream>
#include <iostream>
#include <string>

#include <Tracing/LayerTracing.h>
#include "LayerTraceGenerator.h"

using namespace android;

int main(int argc, char** argv) {
    if (argc > 4) {
        std::cout << "Usage: " << argv[0]
                  << " [transaction-trace-path] [output-layers-trace-path] [--last-entry-only]\n";
        return -1;
    }

    const char* transactionTracePath =
            (argc > 1) ? argv[1] : "/data/misc/wmtrace/transactions_trace.winscope";
    std::cout << "Parsing " << transactionTracePath << "\n";
    std::fstream input(transactionTracePath, std::ios::in | std::ios::binary);
    if (!input) {
        std::cout << "Error: Could not open " << transactionTracePath;
        return -1;
    }

    perfetto::protos::TransactionTraceFile transactionTraceFile;
    if (!transactionTraceFile.ParseFromIstream(&input)) {
        std::cout << "Error: Failed to parse " << transactionTracePath;
        return -1;
    }

    const auto* outputLayersTracePath =
            (argc == 3) ? argv[2] : "/data/misc/wmtrace/layers_trace.winscope";
    auto outStream = std::ofstream{outputLayersTracePath, std::ios::binary | std::ios::out};

    auto layerTracing = LayerTracing{outStream};

    const bool generateLastEntryOnly =
            argc >= 4 && std::string_view(argv[3]) == "--last-entry-only";

    auto traceFlags = LayerTracing::Flag::TRACE_INPUT | LayerTracing::Flag::TRACE_BUFFERS;

    ALOGD("Generating %s...", outputLayersTracePath);
    std::cout << "Generating " << outputLayersTracePath << "\n";

    if (!LayerTraceGenerator().generate(transactionTraceFile, traceFlags, layerTracing,
                                        generateLastEntryOnly)) {
        std::cout << "Error: Failed to generate layers trace " << outputLayersTracePath << "\n";
        return -1;
    }

    // Set output file permissions (-rw-r--r--)
    outStream.close();
    const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (chmod(outputLayersTracePath, mode) != 0) {
        std::cout << "Error: Failed to set permissions of " << outputLayersTracePath << "\n";
        return -1;
    }

    return 0;
}
