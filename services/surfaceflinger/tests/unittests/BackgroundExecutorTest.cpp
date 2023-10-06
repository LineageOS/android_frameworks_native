#include <gtest/gtest.h>
#include <condition_variable>

#include "BackgroundExecutor.h"

namespace android {

class BackgroundExecutorTest : public testing::Test {};

namespace {

TEST_F(BackgroundExecutorTest, singleProducer) {
    std::mutex mutex;
    std::condition_variable condition_variable;
    bool backgroundTaskComplete = false;

    BackgroundExecutor::getInstance().sendCallbacks(
            {[&mutex, &condition_variable, &backgroundTaskComplete]() {
                std::lock_guard<std::mutex> lock{mutex};
                condition_variable.notify_one();
                backgroundTaskComplete = true;
            }});

    std::unique_lock<std::mutex> lock{mutex};
    condition_variable.wait(lock, [&backgroundTaskComplete]() { return backgroundTaskComplete; });
    ASSERT_TRUE(backgroundTaskComplete);
}

TEST_F(BackgroundExecutorTest, multipleProducers) {
    std::mutex mutex;
    std::condition_variable condition_variable;
    const int backgroundTaskCount = 10;
    int backgroundTaskCompleteCount = 0;

    for (int i = 0; i < backgroundTaskCount; i++) {
        std::thread([&mutex, &condition_variable, &backgroundTaskCompleteCount]() {
            BackgroundExecutor::getInstance().sendCallbacks(
                    {[&mutex, &condition_variable, &backgroundTaskCompleteCount]() {
                        std::lock_guard<std::mutex> lock{mutex};
                        backgroundTaskCompleteCount++;
                        if (backgroundTaskCompleteCount == backgroundTaskCount) {
                            condition_variable.notify_one();
                        }
                    }});
        }).detach();
    }

    std::unique_lock<std::mutex> lock{mutex};
    condition_variable.wait(lock, [&backgroundTaskCompleteCount]() {
        return backgroundTaskCompleteCount == backgroundTaskCount;
    });
    ASSERT_EQ(backgroundTaskCount, backgroundTaskCompleteCount);
}

} // namespace

} // namespace android
