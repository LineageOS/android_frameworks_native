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
        // Flush the BackgroundExecutor thread to ensure any scheduled tasks are complete.
        // Otherwise, references those tasks hold may go out of scope before they are done
        // executing.
        BackgroundExecutor::getInstance().flushQueue();
    }

    sp<WindowInfosListenerInvoker> mInvoker;
};

using WindowInfosUpdateConsumer = std::function<void(const gui::WindowInfosUpdate&)>;

class Listener : public gui::BnWindowInfosListener {
public:
    Listener(WindowInfosUpdateConsumer consumer) : mConsumer(std::move(consumer)) {}

    binder::Status onWindowInfosChanged(const gui::WindowInfosUpdate& update) override {
        mConsumer(update);
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

    gui::WindowInfosListenerInfo listenerInfo;
    mInvoker->addWindowInfosListener(sp<Listener>::make([&](const gui::WindowInfosUpdate& update) {
                                         std::scoped_lock lock{mutex};
                                         callCount++;
                                         cv.notify_one();

                                         listenerInfo.windowInfosPublisher
                                                 ->ackWindowInfosReceived(update.vsyncId,
                                                                          listenerInfo.listenerId);
                                     }),
                                     &listenerInfo);

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

    size_t callCount = 0;
    const size_t expectedCallCount = 3;
    std::vector<gui::WindowInfosListenerInfo> listenerInfos{expectedCallCount,
                                                            gui::WindowInfosListenerInfo{}};

    for (size_t i = 0; i < expectedCallCount; i++) {
        mInvoker->addWindowInfosListener(sp<Listener>::make([&, &listenerInfo = listenerInfos[i]](
                                                                    const gui::WindowInfosUpdate&
                                                                            update) {
                                             std::scoped_lock lock{mutex};
                                             callCount++;
                                             if (callCount == expectedCallCount) {
                                                 cv.notify_one();
                                             }

                                             listenerInfo.windowInfosPublisher
                                                     ->ackWindowInfosReceived(update.vsyncId,
                                                                              listenerInfo
                                                                                      .listenerId);
                                         }),
                                         &listenerInfos[i]);
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

    // Simulate a slow ack by not calling IWindowInfosPublisher.ackWindowInfosReceived
    gui::WindowInfosListenerInfo listenerInfo;
    mInvoker->addWindowInfosListener(sp<Listener>::make([&](const gui::WindowInfosUpdate&) {
                                         std::scoped_lock lock{mutex};
                                         callCount++;
                                         cv.notify_one();
                                     }),
                                     &listenerInfo);

    BackgroundExecutor::getInstance().sendCallbacks({[&]() {
        mInvoker->windowInfosChanged(gui::WindowInfosUpdate{{}, {}, /* vsyncId= */ 0, 0}, {},
                                     false);
        mInvoker->windowInfosChanged(gui::WindowInfosUpdate{{}, {}, /* vsyncId= */ 1, 0}, {},
                                     false);
    }});

    {
        std::unique_lock lock{mutex};
        cv.wait(lock, [&]() { return callCount == 1; });
    }
    EXPECT_EQ(callCount, 1);

    // Ack the first message.
    listenerInfo.windowInfosPublisher->ackWindowInfosReceived(0, listenerInfo.listenerId);

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

    // Simulate a slow ack by not calling IWindowInfosPublisher.ackWindowInfosReceived
    gui::WindowInfosListenerInfo listenerInfo;
    mInvoker->addWindowInfosListener(sp<Listener>::make([&](const gui::WindowInfosUpdate&) {
                                         std::scoped_lock lock{mutex};
                                         callCount++;
                                         if (callCount == expectedCallCount) {
                                             cv.notify_one();
                                         }
                                     }),
                                     &listenerInfo);

    BackgroundExecutor::getInstance().sendCallbacks({[&]() {
        mInvoker->windowInfosChanged(gui::WindowInfosUpdate{{}, {}, /* vsyncId= */ 0, 0}, {},
                                     false);
        mInvoker->windowInfosChanged(gui::WindowInfosUpdate{{}, {}, /* vsyncId= */ 1, 0}, {}, true);
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

    // Simulate a slow ack by not calling IWindowInfosPublisher.ackWindowInfosReceived
    gui::WindowInfosListenerInfo listenerInfo;
    mInvoker->addWindowInfosListener(sp<Listener>::make([&](const gui::WindowInfosUpdate& update) {
                                         std::scoped_lock lock{mutex};
                                         lastUpdateId = update.vsyncId;
                                         cv.notify_one();
                                     }),
                                     &listenerInfo);

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
    listenerInfo.windowInfosPublisher->ackWindowInfosReceived(1, listenerInfo.listenerId);

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
        gui::WindowInfosListenerInfo listenerInfo;
        mInvoker->addWindowInfosListener(sp<Listener>::make([&](const gui::WindowInfosUpdate&) {
                                             std::scoped_lock lock{mutex};
                                             callCount++;
                                             cv.notify_one();
                                         }),
                                         &listenerInfo);
    }});
    BackgroundExecutor::getInstance().flushQueue();
    BackgroundExecutor::getInstance().sendCallbacks(
            {[&]() { mInvoker->windowInfosChanged({}, {}, false); }});

    {
        std::unique_lock lock{mutex};
        cv.wait(lock, [&]() { return callCount == 1; });
    }
    EXPECT_EQ(callCount, 1);
}

// Test that WindowInfosListenerInvoker#removeWindowInfosListener acks any unacked messages for
// the removed listener.
TEST_F(WindowInfosListenerInvokerTest, removeListenerAcks) {
    // Don't ack in this listener to ensure there's an unacked message when the listener is later
    // removed.
    gui::WindowInfosListenerInfo listenerToBeRemovedInfo;
    auto listenerToBeRemoved = sp<Listener>::make([](const gui::WindowInfosUpdate&) {});
    mInvoker->addWindowInfosListener(listenerToBeRemoved, &listenerToBeRemovedInfo);

    std::mutex mutex;
    std::condition_variable cv;
    int callCount = 0;
    gui::WindowInfosListenerInfo listenerInfo;
    mInvoker->addWindowInfosListener(sp<Listener>::make([&](const gui::WindowInfosUpdate& update) {
                                         std::scoped_lock lock{mutex};
                                         callCount++;
                                         cv.notify_one();
                                         listenerInfo.windowInfosPublisher
                                                 ->ackWindowInfosReceived(update.vsyncId,
                                                                          listenerInfo.listenerId);
                                     }),
                                     &listenerInfo);

    BackgroundExecutor::getInstance().sendCallbacks(
            {[&]() { mInvoker->windowInfosChanged({}, {}, false); }});
    mInvoker->removeWindowInfosListener(listenerToBeRemoved);
    BackgroundExecutor::getInstance().sendCallbacks(
            {[&]() { mInvoker->windowInfosChanged({}, {}, false); }});

    // Verify that the second listener is called twice. If unacked messages aren't removed when the
    // first listener is removed, this will fail.
    {
        std::unique_lock lock{mutex};
        cv.wait(lock, [&]() { return callCount == 2; });
    }
    EXPECT_EQ(callCount, 2);
}

} // namespace android
