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

#include "../dispatcher/trace/InputTracingBackendInterface.h"

#include <android-base/result.h>
#include <android-base/thread_annotations.h>
#include <gtest/gtest.h>
#include <input/Input.h>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace android::inputdispatcher {

/**
 * A class representing an input trace, used to make assertions on what was traced by
 * InputDispatcher in tests. This class is thread-safe.
 */
class VerifyingTrace {
public:
    VerifyingTrace() = default;

    /** Add an expectation for a key event to be traced. */
    void expectKeyDispatchTraced(const KeyEvent& event, int32_t windowId);

    /** Add an expectation for a motion event to be traced. */
    void expectMotionDispatchTraced(const MotionEvent& event, int32_t windowId);

    /**
     * Wait and verify that all expected events are traced.
     * This is a lenient verifier that does not expect the events to be traced in the order
     * that the events were expected, and does not fail if there are events that are traced that
     * were not expected. Verifying does not clear the expectations.
     */
    void verifyExpectedEventsTraced();

    /** Reset the trace and clear all expectations. */
    void reset();

private:
    std::mutex mLock;
    std::condition_variable mEventTracedCondition;
    std::unordered_map<uint32_t /*eventId*/, trace::TracedEvent> mTracedEvents GUARDED_BY(mLock);
    std::vector<trace::WindowDispatchArgs> mTracedWindowDispatches GUARDED_BY(mLock);
    std::vector<std::pair<std::variant<KeyEvent, MotionEvent>, int32_t /*windowId*/>>
            mExpectedEvents GUARDED_BY(mLock);

    friend class FakeInputTracingBackend;

    // Helper to verify that the given event appears as expected in the trace. If the verification
    // fails, the error message describes why.
    template <typename Event>
    base::Result<void> verifyEventTraced(const Event&, int32_t windowId) const REQUIRES(mLock);
};

/**
 * A backend implementation for input tracing that records events to the provided
 * VerifyingTrace used for testing.
 */
class FakeInputTracingBackend : public trace::InputTracingBackendInterface {
public:
    FakeInputTracingBackend(std::shared_ptr<VerifyingTrace> trace) : mTrace(trace) {}

private:
    std::shared_ptr<VerifyingTrace> mTrace;

    void traceKeyEvent(const trace::TracedKeyEvent& entry,
                       const trace::TracedEventMetadata&) override;
    void traceMotionEvent(const trace::TracedMotionEvent& entry,
                          const trace::TracedEventMetadata&) override;
    void traceWindowDispatch(const trace::WindowDispatchArgs& entry,
                             const trace::TracedEventMetadata&) override;
};

} // namespace android::inputdispatcher
