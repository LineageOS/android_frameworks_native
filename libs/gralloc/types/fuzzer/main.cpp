/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define FUZZ_LOG_TAG "main"

#include "gralloctypes.h"
#include "util.h"

#include <android-base/logging.h>
#include <log/log.h>

#include <cstdlib>
#include <ctime>

void doFuzz(
        const std::vector<GrallocTypesDecode>& decodes,
        const std::vector<uint8_t>& input,
        const std::vector<uint8_t>& instructions) {

    ::android::hardware::hidl_vec<uint8_t> vec;
    vec.setToExternal(const_cast<uint8_t*>(input.data()), input.size(), false /*shouldOwn*/);

    // since we are only using a byte to index
    CHECK(decodes.size() <= 255) << decodes.size();

    for (size_t i = 0; i < instructions.size() - 1; i += 2) {
        uint8_t a = instructions[i];
        uint8_t decodeIdx = a % decodes.size();

        uint8_t b = instructions[i + 1];

        FUZZ_LOG() << "Instruction: " << (i / 2) + 1 << "/" << instructions.size() / 2
                   << " cmd: " << static_cast<size_t>(a) << " (" << static_cast<size_t>(decodeIdx)
                   << ") arg: " << static_cast<size_t>(b) << " size: " << vec.size();

        decodes[decodeIdx](vec, b);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size <= 1) return 0;  // no use

    // data to fill out parcel
    size_t inputLen = size / 2;
    std::vector<uint8_t> input(data, data + inputLen);
    data += inputLen;
    size -= inputLen;

    // data to use to determine what to do
    size_t instructionLen = size;
    std::vector<uint8_t> instructions(data, data + instructionLen);
    data += instructionLen;
    size -= instructionLen;

    CHECK(size == 0) << "size: " << size;

    FUZZ_LOG() << "inputLen: " << inputLen << " instructionLen: " << instructionLen;
    FUZZ_LOG() << "input: " << hexString(input);
    FUZZ_LOG() << "instructions: " << hexString(instructions);

    doFuzz(GRALLOCTYPES_DECODE_FUNCTIONS, input, instructions);
    return 0;
}
