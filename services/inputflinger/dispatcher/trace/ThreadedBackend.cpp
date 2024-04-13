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

#define LOG_TAG "InputTracer"

#include "ThreadedBackend.h"

#include "InputTracingPerfettoBackend.h"

#include <android-base/logging.h>

namespace android::inputdispatcher::trace::impl {

namespace {

// Helper to std::visit with lambdas.
template <typename... V>
struct Visitor : V... {
    using V::operator()...;
};

} // namespace

// --- ThreadedBackend ---

template <typename Backend>
ThreadedBackend<Backend>::ThreadedBackend(Backend&& innerBackend)
      : mBackend(std::move(innerBackend)),
        mTracerThread(
                "InputTracer", [this]() { threadLoop(); },
                [this]() { mThreadWakeCondition.notify_all(); }) {}

template <typename Backend>
ThreadedBackend<Backend>::~ThreadedBackend() {
    {
        std::scoped_lock lock(mLock);
        mThreadExit = true;
    }
    mThreadWakeCondition.notify_all();
}

template <typename Backend>
void ThreadedBackend<Backend>::traceMotionEvent(const TracedMotionEvent& event,
                                                const TracedEventMetadata& metadata) {
    std::scoped_lock lock(mLock);
    mQueue.emplace_back(event, metadata);
    setIdleStatus(false);
    mThreadWakeCondition.notify_all();
}

template <typename Backend>
void ThreadedBackend<Backend>::traceKeyEvent(const TracedKeyEvent& event,
                                             const TracedEventMetadata& metadata) {
    std::scoped_lock lock(mLock);
    mQueue.emplace_back(event, metadata);
    setIdleStatus(false);
    mThreadWakeCondition.notify_all();
}

template <typename Backend>
void ThreadedBackend<Backend>::traceWindowDispatch(const WindowDispatchArgs& dispatchArgs,
                                                   const TracedEventMetadata& metadata) {
    std::scoped_lock lock(mLock);
    mQueue.emplace_back(dispatchArgs, metadata);
    setIdleStatus(false);
    mThreadWakeCondition.notify_all();
}

template <typename Backend>
void ThreadedBackend<Backend>::threadLoop() {
    std::vector<TraceEntry> entries;

    { // acquire lock
        std::unique_lock lock(mLock);
        base::ScopedLockAssertion assumeLocked(mLock);

        if (mQueue.empty()) {
            setIdleStatus(true);
        }

        // Wait until we need to process more events or exit.
        mThreadWakeCondition.wait(lock,
                                  [&]() REQUIRES(mLock) { return mThreadExit || !mQueue.empty(); });
        if (mThreadExit) {
            setIdleStatus(true);
            return;
        }

        mQueue.swap(entries);
    } // release lock

    // Trace the events into the backend without holding the lock to reduce the amount of
    // work performed in the critical section.
    for (const auto& [entry, traceArgs] : entries) {
        std::visit(Visitor{[&](const TracedMotionEvent& e) {
                               mBackend.traceMotionEvent(e, traceArgs);
                           },
                           [&](const TracedKeyEvent& e) { mBackend.traceKeyEvent(e, traceArgs); },
                           [&](const WindowDispatchArgs& args) {
                               mBackend.traceWindowDispatch(args, traceArgs);
                           }},
                   entry);
    }
    entries.clear();
}

template <typename Backend>
std::function<void()> ThreadedBackend<Backend>::getIdleWaiterForTesting() {
    std::scoped_lock lock(mLock);
    if (!mIdleWaiter) {
        mIdleWaiter = std::make_shared<IdleWaiter>();
    }

    // Return a lambda that holds a strong reference to the idle waiter, whose lifetime can extend
    // beyond this threaded backend object.
    return [idleWaiter = mIdleWaiter]() {
        std::unique_lock idleLock(idleWaiter->idleLock);
        base::ScopedLockAssertion assumeLocked(idleWaiter->idleLock);
        idleWaiter->threadIdleCondition.wait(idleLock, [&]() REQUIRES(idleWaiter->idleLock) {
            return idleWaiter->isIdle;
        });
    };
}

template <typename Backend>
void ThreadedBackend<Backend>::setIdleStatus(bool isIdle) {
    if (!mIdleWaiter) {
        return;
    }
    std::scoped_lock idleLock(mIdleWaiter->idleLock);
    mIdleWaiter->isIdle = isIdle;
    if (isIdle) {
        mIdleWaiter->threadIdleCondition.notify_all();
    }
}

// Explicit template instantiation for the PerfettoBackend.
template class ThreadedBackend<PerfettoBackend>;

} // namespace android::inputdispatcher::trace::impl
