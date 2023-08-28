/*
 * Copyright 2022 The Android Open Source Project
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
#include <gui/BufferQueueConsumer.h>
#include <gui/BufferQueueCore.h>
#include <gui/BufferQueueProducer.h>
#include <gui/GLConsumer.h>
#include <libgui_fuzzer_utils.h>

using namespace android;

constexpr int32_t kMinBuffer = 0;
constexpr int32_t kMaxBuffer = 100000;

class ConsumerFuzzer {
public:
    ConsumerFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

private:
    FuzzedDataProvider mFdp;
};

void ConsumerFuzzer::process() {
    sp<BufferQueueCore> core(new BufferQueueCore());
    sp<IGraphicBufferConsumer> consumer(new BufferQueueConsumer(core));

    uint64_t maxBuffers = mFdp.ConsumeIntegralInRange<uint64_t>(kMinBuffer, kMaxBuffer);
    sp<CpuConsumer> cpu(
            new CpuConsumer(consumer, maxBuffers, mFdp.ConsumeBool() /*controlledByApp*/));
    CpuConsumer::LockedBuffer lockBuffer;
    cpu->lockNextBuffer(&lockBuffer);
    cpu->unlockBuffer(lockBuffer);
    cpu->abandon();

    uint32_t tex = mFdp.ConsumeIntegral<uint32_t>();
    sp<GLConsumer> glComsumer(new GLConsumer(consumer, tex, GLConsumer::TEXTURE_EXTERNAL,
                                             mFdp.ConsumeBool() /*useFenceSync*/,
                                             mFdp.ConsumeBool() /*isControlledByApp*/));
    sp<Fence> releaseFence = new Fence(memfd_create("rfd", MFD_ALLOW_SEALING));
    glComsumer->setReleaseFence(releaseFence);
    glComsumer->updateTexImage();
    glComsumer->releaseTexImage();

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(mFdp.ConsumeIntegral<uint32_t>(), mFdp.ConsumeIntegral<uint32_t>(),
                              mFdp.ConsumeIntegral<int32_t>(), mFdp.ConsumeIntegral<uint32_t>(),
                              mFdp.ConsumeIntegral<uint64_t>());
    float mtx[16];
    glComsumer->getTransformMatrix(mtx);
    glComsumer->computeTransformMatrix(mtx, buffer, getRect(&mFdp),
                                       mFdp.ConsumeIntegral<uint32_t>(),
                                       mFdp.ConsumeBool() /*filtering*/);
    glComsumer->scaleDownCrop(getRect(&mFdp), mFdp.ConsumeIntegral<uint32_t>(),
                              mFdp.ConsumeIntegral<uint32_t>());

    glComsumer->setDefaultBufferSize(mFdp.ConsumeIntegral<uint32_t>(),
                                     mFdp.ConsumeIntegral<uint32_t>());
    glComsumer->setFilteringEnabled(mFdp.ConsumeBool() /*enabled*/);

    glComsumer->setConsumerUsageBits(mFdp.ConsumeIntegral<uint64_t>());
    glComsumer->attachToContext(tex);
    glComsumer->abandon();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ConsumerFuzzer consumerFuzzer(data, size);
    consumerFuzzer.process();
    return 0;
}
