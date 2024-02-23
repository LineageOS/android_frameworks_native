/*
 * Copyright 2024 The Android Open Source Project
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

#include "InputThread.h"
#include "InputTracingPerfettoBackend.h"

#include <android-base/thread_annotations.h>
#include <mutex>
#include <variant>
#include <vector>

namespace android::inputdispatcher::trace::impl {

/**
 * A wrapper around an InputTracingBackend implementation that writes to the inner tracing backend
 * from a single new thread that it creates. The new tracing thread is started when the
 * ThreadedBackend is created, and is stopped when it is destroyed. The ThreadedBackend is
 * thread-safe.
 */
template <typename Backend>
class ThreadedBackend : public InputTracingBackendInterface {
public:
    ThreadedBackend(Backend&& innerBackend);
    ~ThreadedBackend() override;

    void traceKeyEvent(const TracedKeyEvent&) override;
    void traceMotionEvent(const TracedMotionEvent&) override;
    void traceWindowDispatch(const WindowDispatchArgs&) override;

private:
    std::mutex mLock;
    InputThread mTracerThread;
    bool mThreadExit GUARDED_BY(mLock){false};
    std::condition_variable mThreadWakeCondition;
    Backend mBackend;
    using TraceEntry = std::variant<TracedKeyEvent, TracedMotionEvent, WindowDispatchArgs>;
    std::vector<TraceEntry> mQueue GUARDED_BY(mLock);

    using WindowDispatchArgs = InputTracingBackendInterface::WindowDispatchArgs;

    void threadLoop();
};

} // namespace android::inputdispatcher::trace::impl
