/*
 * Copyright (C) 2009 The Android Open Source Project
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

#include <cstdint>
#include <future>
#include <type_traits>
#include <utility>

#include <utils/Looper.h>
#include <utils/Timers.h>
#include <utils/threads.h>

#include <gui/IDisplayEventConnection.h>
#include <private/gui/BitTube.h>

#include "EventThread.h"
#include "TracedOrdinal.h"
#include "VSyncDispatch.h"

namespace android {

class SurfaceFlinger;

template <typename F>
class Task : public MessageHandler {
    template <typename G>
    friend auto makeTask(G&&);

    explicit Task(F&& f) : mTask(std::move(f)) {}

    void handleMessage(const Message&) override { mTask(); }

    using T = std::invoke_result_t<F>;
    std::packaged_task<T()> mTask;
};

template <typename F>
inline auto makeTask(F&& f) {
    sp<Task<F>> task = new Task<F>(std::move(f));
    return std::make_pair(task, task->mTask.get_future());
}

class MessageQueue {
public:
    enum {
        INVALIDATE = 0,
        REFRESH = 1,
    };

    virtual ~MessageQueue() = default;

    virtual void init(const sp<SurfaceFlinger>& flinger) = 0;
    virtual void initVsync(scheduler::VSyncDispatch&, frametimeline::TokenManager&,
                           std::chrono::nanoseconds workDuration) = 0;
    virtual void setDuration(std::chrono::nanoseconds workDuration) = 0;
    virtual void setEventConnection(const sp<EventThreadConnection>& connection) = 0;
    virtual void waitMessage() = 0;
    virtual void postMessage(sp<MessageHandler>&&) = 0;
    virtual void invalidate() = 0;
    virtual void refresh() = 0;
};

// ---------------------------------------------------------------------------

namespace impl {

class MessageQueue : public android::MessageQueue {
protected:
    class Handler : public MessageHandler {
        enum { eventMaskInvalidate = 0x1, eventMaskRefresh = 0x2, eventMaskTransaction = 0x4 };
        MessageQueue& mQueue;
        int32_t mEventMask;
        std::atomic<int64_t> mVsyncId;
        std::atomic<nsecs_t> mExpectedVSyncTime;

    public:
        explicit Handler(MessageQueue& queue) : mQueue(queue), mEventMask(0) {}
        void handleMessage(const Message& message) override;
        virtual void dispatchRefresh();
        virtual void dispatchInvalidate(int64_t vsyncId, nsecs_t expectedVSyncTimestamp);
    };

    friend class Handler;

    sp<SurfaceFlinger> mFlinger;
    sp<Looper> mLooper;
    sp<EventThreadConnection> mEvents;

    struct Vsync {
        frametimeline::TokenManager* tokenManager = nullptr;
        std::unique_ptr<scheduler::VSyncCallbackRegistration> registration;

        std::mutex mutex;
        TracedOrdinal<std::chrono::nanoseconds> workDuration
                GUARDED_BY(mutex) = {"VsyncWorkDuration-sf", std::chrono::nanoseconds(0)};
        std::chrono::nanoseconds lastCallbackTime GUARDED_BY(mutex) = std::chrono::nanoseconds{0};
        bool mScheduled GUARDED_BY(mutex) = false;
        TracedOrdinal<int> value = {"VSYNC-sf", 0};
    };

    Vsync mVsync;

    gui::BitTube mEventTube;
    sp<Handler> mHandler;

    static int cb_eventReceiver(int fd, int events, void* data);
    int eventReceiver(int fd, int events);
    void vsyncCallback(nsecs_t vsyncTime, nsecs_t targetWakeupTime, nsecs_t readyTime);

public:
    ~MessageQueue() override = default;
    void init(const sp<SurfaceFlinger>& flinger) override;
    void initVsync(scheduler::VSyncDispatch&, frametimeline::TokenManager&,
                   std::chrono::nanoseconds workDuration) override;
    void setDuration(std::chrono::nanoseconds workDuration) override;
    void setEventConnection(const sp<EventThreadConnection>& connection) override;

    void waitMessage() override;
    void postMessage(sp<MessageHandler>&&) override;

    // sends INVALIDATE message at next VSYNC
    void invalidate() override;

    // sends REFRESH message at next VSYNC
    void refresh() override;
};

} // namespace impl
} // namespace android