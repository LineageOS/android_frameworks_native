/*
 * Copyright 2021 The Android Open Source Project
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

#include <fuzzbinder/libbinder_driver.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <libgui_fuzzer_utils.h>

using namespace android;

class SurfaceComposerFuzzer {
public:
    SurfaceComposerFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

private:
    FuzzedDataProvider mFdp;
};

void SurfaceComposerFuzzer::process() {
    sp<FakeBnSurfaceComposer> composer(new FakeBnSurfaceComposer());
    fuzzService(composer.get(), std::move(mFdp));
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    SurfaceComposerFuzzer surfaceComposerFuzzer(data, size);
    surfaceComposerFuzzer.process();
    return 0;
}
