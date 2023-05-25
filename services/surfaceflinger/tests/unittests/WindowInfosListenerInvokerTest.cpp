#include <android/gui/BnWindowInfosListener.h>
#include <gtest/gtest.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/WindowInfosUpdate.h>
#include <condition_variable>

#include "BackgroundExecutor.h"
#include "WindowInfosListenerInvoker.h"
#include "android/gui/IWindowInfosReportedListener.h"

namespace android {

class WindowInfosListenerInvokerTest : public testing::Test {
protected:
    WindowInfosListenerInvokerTest() : mInvoker(sp<WindowInfosListenerInvoker>::make()) {}

    ~WindowInfosListenerInvokerTest() {
        std::mutex mutex;
        std::condition_variable cv;
        bool flushComplete = false;
        // Flush the BackgroundExecutor thread to ensure any scheduled tasks are complete.
        // Otherwise, references those tasks hold may go out of scope before they are done
        // executing.
        BackgroundExecutor::getInstance().sendCallbacks({[&]() {
            std::scoped_lock lock{mutex};
            flushComplete = true;
            cv.notify_one();
        }});
        std::unique_lock<std::mutex> lock{mutex};
        cv.wait(lock, [&]() { return flushComplete; });
    }

    sp<WindowInfosListenerInvoker> mInvoker;
};

using WindowInfosUpdateConsumer = std::function<void(const gui::WindowInfosUpdate&,
                                                     const sp<gui::IWindowInfosReportedListener>&)>;

class Listener : public gui::BnWindowInfosListener {
public:
    Listener(WindowInfosUpdateConsumer consumer) : mConsumer(std::move(consumer)) {}

    binder::Status onWindowInfosChanged(
            const gui::WindowInfosUpdate& update,
            const sp<gui::IWindowInfosReportedListener>& reportedListener) override {
        mConsumer(update, reportedListener);
        return binder::Status::ok();
    }

private:
    WindowInfosUpdateConsumer mConsumer;
};

// Test that WindowInfosListenerInvoker#windowInfosChanged calls a single window infos listener.
TEST_F(WindowInfosListenerInvokerTest, callsSingleListener) {
    std::mutex mutex;
    std::condition_variable cv;

    int callCount = 0;

    mInvoker->addWindowInfosListener(
            sp<Listener>::make([&](const gui::WindowInfosUpdate&,
                                   const sp<gui::IWindowInfosReportedListener>& reportedListener) {
                std::scoped_lock lock{mutex};
                callCount++;
                cv.notify_one();

                reportedListener->onWindowInfosReported();
            }));

    BackgroundExecutor::getInstance().sendCallbacks(
            {[this]() { mInvoker->windowInfosChanged({}, {}, false); }});

    std::unique_lock<std::mutex> lock{mutex};
    cv.wait(lock, [&]() { return callCount == 1; });
    EXPECT_EQ(callCount, 1);
}

// Test that WindowInfosListenerInvoker#windowInfosChanged calls multiple window infos listeners.
TEST_F(WindowInfosListenerInvokerTest, callsMultipleListeners) {
    std::mutex mutex;
    std::condition_variable cv;

    int callCount = 0;
    const int expectedCallCount = 3;

    for (int i = 0; i < expectedCallCount; i++) {
        mInvoker->addWindowInfosListener(sp<Listener>::make(
                [&](const gui::WindowInfosUpdate&,
                    const sp<gui::IWindowInfosReportedListener>& reportedListener) {
                    std::scoped_lock lock{mutex};
                    callCount++;
                    if (callCount == expectedCallCount) {
                        cv.notify_one();
                    }

                    reportedListener->onWindowInfosReported();
                }));
    }

    BackgroundExecutor::getInstance().sendCallbacks(
            {[&]() { mInvoker->windowInfosChanged({}, {}, false); }});

    std::unique_lock<std::mutex> lock{mutex};
    cv.wait(lock, [&]() { return callCount == expectedCallCount; });
    EXPECT_EQ(callCount, expectedCallCount);
}

// Test that WindowInfosListenerInvoker#windowInfosChanged delays sending a second message until
// after the WindowInfosReportedListener is called.
TEST_F(WindowInfosListenerInvokerTest, delaysUnackedCall) {
    std::mutex mutex;
    std::condition_variable cv;

    int callCount = 0;

    // Simulate a slow ack by not calling the WindowInfosReportedListener.
    mInvoker->addWindowInfosListener(sp<Listener>::make(
            [&](const gui::WindowInfosUpdate&, const sp<gui::IWindowInfosReportedListener>&) {
                std::scoped_lock lock{mutex};
                callCount++;
                cv.notify_one();
            }));

    BackgroundExecutor::getInstance().sendCallbacks({[&]() {
        mInvoker->windowInfosChanged({}, {}, false);
        mInvoker->windowInfosChanged({}, {}, false);
    }});

    {
        std::unique_lock lock{mutex};
        cv.wait(lock, [&]() { return callCount == 1; });
    }
    EXPECT_EQ(callCount, 1);

    // Ack the first message.
    mInvoker->onWindowInfosReported();

    {
        std::unique_lock lock{mutex};
        cv.wait(lock, [&]() { return callCount == 2; });
    }
    EXPECT_EQ(callCount, 2);
}

// Test that WindowInfosListenerInvoker#windowInfosChanged immediately sends a second message when
// forceImmediateCall is true.
TEST_F(WindowInfosListenerInvokerTest, sendsForcedMessage) {
    std::mutex mutex;
    std::condition_variable cv;

    int callCount = 0;
    const int expectedCallCount = 2;

    // Simulate a slow ack by not calling the WindowInfosReportedListener.
    mInvoker->addWindowInfosListener(sp<Listener>::make(
            [&](const gui::WindowInfosUpdate&, const sp<gui::IWindowInfosReportedListener>&) {
                std::scoped_lock lock{mutex};
                callCount++;
                if (callCount == expectedCallCount) {
                    cv.notify_one();
                }
            }));

    BackgroundExecutor::getInstance().sendCallbacks({[&]() {
        mInvoker->windowInfosChanged({}, {}, false);
        mInvoker->windowInfosChanged({}, {}, true);
    }});

    {
        std::unique_lock lock{mutex};
        cv.wait(lock, [&]() { return callCount == expectedCallCount; });
    }
    EXPECT_EQ(callCount, expectedCallCount);
}

// Test that WindowInfosListenerInvoker#windowInfosChanged skips old messages when more than one
// message is delayed.
TEST_F(WindowInfosListenerInvokerTest, skipsDelayedMessage) {
    std::mutex mutex;
    std::condition_variable cv;

    int64_t lastUpdateId = -1;

    // Simulate a slow ack by not calling the WindowInfosReportedListener.
    mInvoker->addWindowInfosListener(
            sp<Listener>::make([&](const gui::WindowInfosUpdate& update,
                                   const sp<gui::IWindowInfosReportedListener>&) {
                std::scoped_lock lock{mutex};
                lastUpdateId = update.vsyncId;
                cv.notify_one();
            }));

    BackgroundExecutor::getInstance().sendCallbacks({[&]() {
        mInvoker->windowInfosChanged({{}, {}, /* vsyncId= */ 1, 0}, {}, false);
        mInvoker->windowInfosChanged({{}, {}, /* vsyncId= */ 2, 0}, {}, false);
        mInvoker->windowInfosChanged({{}, {}, /* vsyncId= */ 3, 0}, {}, false);
    }});

    {
        std::unique_lock lock{mutex};
        cv.wait(lock, [&]() { return lastUpdateId == 1; });
    }
    EXPECT_EQ(lastUpdateId, 1);

    // Ack the first message. The third update should be sent.
    mInvoker->onWindowInfosReported();

    {
        std::unique_lock lock{mutex};
        cv.wait(lock, [&]() { return lastUpdateId == 3; });
    }
    EXPECT_EQ(lastUpdateId, 3);
}

// Test that WindowInfosListenerInvoker#windowInfosChanged immediately calls listener after a call
// where no listeners were configured.
TEST_F(WindowInfosListenerInvokerTest, noListeners) {
    std::mutex mutex;
    std::condition_variable cv;

    int callCount = 0;

    // Test that calling windowInfosChanged without any listeners doesn't cause the next call to be
    // delayed.
    BackgroundExecutor::getInstance().sendCallbacks({[&]() {
        mInvoker->windowInfosChanged({}, {}, false);
        mInvoker->addWindowInfosListener(sp<Listener>::make(
                [&](const gui::WindowInfosUpdate&, const sp<gui::IWindowInfosReportedListener>&) {
                    std::scoped_lock lock{mutex};
                    callCount++;
                    cv.notify_one();
                }));
        mInvoker->windowInfosChanged({}, {}, false);
    }});

    {
        std::unique_lock lock{mutex};
        cv.wait(lock, [&]() { return callCount == 1; });
    }
    EXPECT_EQ(callCount, 1);
}

} // namespace android
