#undef LOG_TAG
#define LOG_TAG "gpuservice_unittest"

#include "gpuservice/GpuService.h"

#include <gtest/gtest.h>
#include <log/log_main.h>

#include <chrono>
#include <thread>

namespace android {
namespace {

class GpuServiceTest : public testing::Test {
public:
    GpuServiceTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~GpuServiceTest() {
        const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

};


/*
* The behaviour before this test + fixes was UB caused by threads accessing deallocated memory.
*
* This test creates the service (which initializes the culprit threads),
* deallocates it immediately and sleeps.
*
* GpuService's destructor gets called and joins the threads.
* If we haven't crashed by the time the sleep time has elapsed, we're good
* Let the test pass.
*/
TEST_F(GpuServiceTest, onInitializeShouldNotCauseUseAfterFree) {
    sp<GpuService> service = new GpuService();
    service.clear();
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // If we haven't crashed yet due to threads accessing freed up memory, let the test pass
    EXPECT_TRUE(true);
}

} // namespace
} // namespace android
