/*
 * Copyright 2018 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <TimeStats/TimeStats.h>
#include <android/util/ProtoOutputStream.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include <chrono>
#include <random>
#include <unordered_set>

#include "libsurfaceflinger_unittest_main.h"

using namespace android::surfaceflinger;
using namespace google::protobuf;
using namespace std::chrono_literals;

namespace android {
namespace {

using testing::_;
using testing::AnyNumber;
using testing::Contains;
using testing::HasSubstr;
using testing::InSequence;
using testing::SizeIs;
using testing::StrEq;
using testing::UnorderedElementsAre;

using PowerMode = hardware::graphics::composer::V2_4::IComposerClient::PowerMode;

// clang-format off
#define FMT_PROTO          true
#define FMT_STRING         false
#define LAYER_ID_0         0
#define LAYER_ID_1         1
#define UID_0              123
#define LAYER_ID_INVALID   -1
#define NUM_LAYERS         1
#define NUM_LAYERS_INVALID "INVALID"

enum InputCommand : int32_t {
    ENABLE                 = 0,
    DISABLE                = 1,
    CLEAR                  = 2,
    DUMP_ALL               = 3,
    DUMP_MAXLAYERS_1       = 4,
    DUMP_MAXLAYERS_INVALID = 5,
    INPUT_COMMAND_BEGIN    = ENABLE,
    INPUT_COMMAND_END      = DUMP_MAXLAYERS_INVALID,
    INPUT_COMMAND_RANGE    = INPUT_COMMAND_END - INPUT_COMMAND_BEGIN + 1,
};

enum TimeStamp : int32_t {
    POST                   = 0,
    ACQUIRE                = 1,
    ACQUIRE_FENCE          = 2,
    LATCH                  = 3,
    DESIRED                = 4,
    PRESENT                = 5,
    PRESENT_FENCE          = 6,
    TIME_STAMP_BEGIN       = POST,
    TIME_STAMP_END         = PRESENT,
    TIME_STAMP_RANGE       = TIME_STAMP_END - TIME_STAMP_BEGIN + 1,
};

static const TimeStamp NORMAL_SEQUENCE[] = {
        TimeStamp::POST,
        TimeStamp::ACQUIRE,
        TimeStamp::LATCH,
        TimeStamp::DESIRED,
        TimeStamp::PRESENT,
};

static const TimeStamp NORMAL_SEQUENCE_2[] = {
        TimeStamp::POST,
        TimeStamp::ACQUIRE_FENCE,
        TimeStamp::LATCH,
        TimeStamp::DESIRED,
        TimeStamp::PRESENT_FENCE,
};

static const TimeStamp UNORDERED_SEQUENCE[] = {
        TimeStamp::ACQUIRE,
        TimeStamp::LATCH,
        TimeStamp::POST,
        TimeStamp::DESIRED,
        TimeStamp::PRESENT,
};

static const TimeStamp INCOMPLETE_SEQUENCE[] = {
        TimeStamp::POST,
};
// clang-format on

class TimeStatsTest : public testing::Test {
public:
    TimeStatsTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~TimeStatsTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    std::string inputCommand(InputCommand cmd, bool useProto);

    void setTimeStamp(TimeStamp type, int32_t id, uint64_t frameNumber, nsecs_t ts);

    int32_t genRandomInt32(int32_t begin, int32_t end);

    template <size_t N>
    void insertTimeRecord(const TimeStamp (&sequence)[N], int32_t id, uint64_t frameNumber,
                          nsecs_t ts) {
        for (size_t i = 0; i < N; i++, ts += 1000000) {
            setTimeStamp(sequence[i], id, frameNumber, ts);
        }
    }

    std::mt19937 mRandomEngine = std::mt19937(std::random_device()());

    class FakeStatsEventDelegate : public impl::TimeStats::StatsEventDelegate {
    public:
        FakeStatsEventDelegate() = default;
        ~FakeStatsEventDelegate() override = default;

        struct AStatsEvent* addStatsEventToPullData(AStatsEventList*) override {
            return mEvent;
        }
        void setStatsPullAtomCallback(int32_t atom_tag, AStatsManager_PullAtomMetadata*,
                                      AStatsManager_PullAtomCallback callback,
                                      void* cookie) override {
            mAtomTags.push_back(atom_tag);
            mCallback = callback;
            mCookie = cookie;
        }

        AStatsManager_PullAtomCallbackReturn makePullAtomCallback(int32_t atom_tag, void* cookie) {
            return (*mCallback)(atom_tag, nullptr, cookie);
        }

        MOCK_METHOD1(clearStatsPullAtomCallback, void(int32_t));
        MOCK_METHOD2(statsEventSetAtomId, void(AStatsEvent*, uint32_t));
        MOCK_METHOD2(statsEventWriteInt32, void(AStatsEvent*, int32_t));
        MOCK_METHOD2(statsEventWriteInt64, void(AStatsEvent*, int64_t));
        MOCK_METHOD2(statsEventWriteString8, void(AStatsEvent*, const char*));
        MOCK_METHOD3(statsEventWriteByteArray, void(AStatsEvent*, const uint8_t*, size_t));
        MOCK_METHOD1(statsEventBuild, void(AStatsEvent*));

        AStatsEvent* mEvent = AStatsEvent_obtain();
        std::vector<int32_t> mAtomTags;
        AStatsManager_PullAtomCallback mCallback = nullptr;
        void* mCookie = nullptr;
    };
    FakeStatsEventDelegate* mDelegate = new FakeStatsEventDelegate;
    std::unique_ptr<TimeStats> mTimeStats =
            std::make_unique<impl::TimeStats>(std::unique_ptr<FakeStatsEventDelegate>(mDelegate),
                                              std::nullopt, std::nullopt);
};

std::string TimeStatsTest::inputCommand(InputCommand cmd, bool useProto) {
    std::string result;
    Vector<String16> args;

    switch (cmd) {
        case InputCommand::ENABLE:
            args.push_back(String16("-enable"));
            break;
        case InputCommand::DISABLE:
            args.push_back(String16("-disable"));
            break;
        case InputCommand::CLEAR:
            args.push_back(String16("-clear"));
            break;
        case InputCommand::DUMP_ALL:
            args.push_back(String16("-dump"));
            break;
        case InputCommand::DUMP_MAXLAYERS_1:
            args.push_back(String16("-dump"));
            args.push_back(String16("-maxlayers"));
            args.push_back(String16(std::to_string(NUM_LAYERS).c_str()));
            break;
        case InputCommand::DUMP_MAXLAYERS_INVALID:
            args.push_back(String16("-dump"));
            args.push_back(String16("-maxlayers"));
            args.push_back(String16(NUM_LAYERS_INVALID));
            break;
        default:
            ALOGD("Invalid control command");
    }

    EXPECT_NO_FATAL_FAILURE(mTimeStats->parseArgs(useProto, args, result));
    return result;
}

static std::string genLayerName(int32_t layerId) {
    return (layerId < 0 ? "PopupWindow:b54fcd1#0" : "com.example.fake#") + std::to_string(layerId);
}

void TimeStatsTest::setTimeStamp(TimeStamp type, int32_t id, uint64_t frameNumber, nsecs_t ts) {
    switch (type) {
        case TimeStamp::POST:
            ASSERT_NO_FATAL_FAILURE(
                    mTimeStats->setPostTime(id, frameNumber, genLayerName(id), UID_0, ts));
            break;
        case TimeStamp::ACQUIRE:
            ASSERT_NO_FATAL_FAILURE(mTimeStats->setAcquireTime(id, frameNumber, ts));
            break;
        case TimeStamp::ACQUIRE_FENCE:
            ASSERT_NO_FATAL_FAILURE(
                    mTimeStats->setAcquireFence(id, frameNumber, std::make_shared<FenceTime>(ts)));
            break;
        case TimeStamp::LATCH:
            ASSERT_NO_FATAL_FAILURE(mTimeStats->setLatchTime(id, frameNumber, ts));
            break;
        case TimeStamp::DESIRED:
            ASSERT_NO_FATAL_FAILURE(mTimeStats->setDesiredTime(id, frameNumber, ts));
            break;
        case TimeStamp::PRESENT:
            ASSERT_NO_FATAL_FAILURE(mTimeStats->setPresentTime(id, frameNumber, ts));
            break;
        case TimeStamp::PRESENT_FENCE:
            ASSERT_NO_FATAL_FAILURE(
                    mTimeStats->setPresentFence(id, frameNumber, std::make_shared<FenceTime>(ts)));
            break;
        default:
            ALOGD("Invalid timestamp type");
    }
}

int32_t TimeStatsTest::genRandomInt32(int32_t begin, int32_t end) {
    std::uniform_int_distribution<int32_t> distr(begin, end);
    return distr(mRandomEngine);
}

TEST_F(TimeStatsTest, disabledByDefault) {
    ASSERT_FALSE(mTimeStats->isEnabled());
}

TEST_F(TimeStatsTest, setsCallbacksAfterBoot) {
    mTimeStats->onBootFinished();
    EXPECT_THAT(mDelegate->mAtomTags,
                UnorderedElementsAre(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO,
                                     android::util::SURFACEFLINGER_STATS_LAYER_INFO));
}

TEST_F(TimeStatsTest, clearsCallbacksOnDestruction) {
    EXPECT_CALL(*mDelegate,
                clearStatsPullAtomCallback(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO));
    EXPECT_CALL(*mDelegate,
                clearStatsPullAtomCallback(android::util::SURFACEFLINGER_STATS_LAYER_INFO));
    mTimeStats.reset();
}

TEST_F(TimeStatsTest, canEnableAndDisableTimeStats) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());
    ASSERT_TRUE(mTimeStats->isEnabled());

    EXPECT_TRUE(inputCommand(InputCommand::DISABLE, FMT_STRING).empty());
    ASSERT_FALSE(mTimeStats->isEnabled());
}

TEST_F(TimeStatsTest, canIncreaseGlobalStats) {
    constexpr size_t TOTAL_FRAMES = 5;
    constexpr size_t MISSED_FRAMES = 4;
    constexpr size_t CLIENT_COMPOSITION_FRAMES = 3;

    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    for (size_t i = 0; i < TOTAL_FRAMES; i++) {
        ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementTotalFrames());
    }
    for (size_t i = 0; i < MISSED_FRAMES; i++) {
        ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementMissedFrames());
    }
    for (size_t i = 0; i < CLIENT_COMPOSITION_FRAMES; i++) {
        ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementClientCompositionFrames());
    }

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    ASSERT_TRUE(globalProto.has_total_frames());
    EXPECT_EQ(TOTAL_FRAMES, globalProto.total_frames());
    ASSERT_TRUE(globalProto.has_missed_frames());
    EXPECT_EQ(MISSED_FRAMES, globalProto.missed_frames());
    ASSERT_TRUE(globalProto.has_client_composition_frames());
    EXPECT_EQ(CLIENT_COMPOSITION_FRAMES, globalProto.client_composition_frames());
}

TEST_F(TimeStatsTest, canIncreaseLateAcquireFrames) {
    // this stat is not in the proto so verify by checking the string dump
    constexpr size_t LATE_ACQUIRE_FRAMES = 2;

    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    for (size_t i = 0; i < LATE_ACQUIRE_FRAMES; i++) {
        mTimeStats->incrementLatchSkipped(LAYER_ID_0, TimeStats::LatchSkipReason::LateAcquire);
    }
    insertTimeRecord(NORMAL_SEQUENCE_2, LAYER_ID_0, 2, 2000000);

    const std::string result(inputCommand(InputCommand::DUMP_ALL, FMT_STRING));
    const std::string expectedResult = "lateAcquireFrames = " + std::to_string(LATE_ACQUIRE_FRAMES);
    EXPECT_THAT(result, HasSubstr(expectedResult));
}

TEST_F(TimeStatsTest, canIncreaseBadDesiredPresent) {
    // this stat is not in the proto so verify by checking the string dump
    constexpr size_t BAD_DESIRED_PRESENT_FRAMES = 2;

    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    for (size_t i = 0; i < BAD_DESIRED_PRESENT_FRAMES; i++) {
        mTimeStats->incrementBadDesiredPresent(LAYER_ID_0);
    }
    insertTimeRecord(NORMAL_SEQUENCE_2, LAYER_ID_0, 2, 2000000);

    const std::string result(inputCommand(InputCommand::DUMP_ALL, FMT_STRING));
    const std::string expectedResult =
            "badDesiredPresentFrames = " + std::to_string(BAD_DESIRED_PRESENT_FRAMES);
    EXPECT_THAT(result, HasSubstr(expectedResult));
}

TEST_F(TimeStatsTest, canIncreaseJankyFrames) {
    // this stat is not in the proto so verify by checking the string dump
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    mTimeStats->incrementJankyFrames(JankType::SurfaceFlingerCpuDeadlineMissed);
    mTimeStats->incrementJankyFrames(JankType::SurfaceFlingerGpuDeadlineMissed);
    mTimeStats->incrementJankyFrames(JankType::DisplayHAL);
    mTimeStats->incrementJankyFrames(JankType::AppDeadlineMissed);
    mTimeStats->incrementJankyFrames(JankType::None);

    const std::string result(inputCommand(InputCommand::DUMP_ALL, FMT_STRING));
    std::string expectedResult = "totalTimelineFrames = " + std::to_string(5);
    EXPECT_THAT(result, HasSubstr(expectedResult));
    expectedResult = "jankyFrames = " + std::to_string(4);
    EXPECT_THAT(result, HasSubstr(expectedResult));
    expectedResult = "sfLongCpuJankyFrames = " + std::to_string(1);
    EXPECT_THAT(result, HasSubstr(expectedResult));
    expectedResult = "sfLongGpuJankyFrames = " + std::to_string(1);
    EXPECT_THAT(result, HasSubstr(expectedResult));
    expectedResult = "sfUnattributedJankyFrame = " + std::to_string(1);
    EXPECT_THAT(result, HasSubstr(expectedResult));
    expectedResult = "appUnattributedJankyFrame = " + std::to_string(1);
    EXPECT_THAT(result, HasSubstr(expectedResult));
}

TEST_F(TimeStatsTest, canIncreaseJankyFramesForLayer) {
    // this stat is not in the proto so verify by checking the string dump
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0),
                                     JankType::SurfaceFlingerCpuDeadlineMissed);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0),
                                     JankType::SurfaceFlingerGpuDeadlineMissed);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0), JankType::DisplayHAL);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0),
                                     JankType::AppDeadlineMissed);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0), JankType::None);

    const std::string result(inputCommand(InputCommand::DUMP_ALL, FMT_STRING));
    std::string expectedResult = "totalTimelineFrames = " + std::to_string(5);
    EXPECT_THAT(result, HasSubstr(expectedResult));
    expectedResult = "jankyFrames = " + std::to_string(4);
    EXPECT_THAT(result, HasSubstr(expectedResult));
    expectedResult = "sfLongCpuJankyFrames = " + std::to_string(1);
    EXPECT_THAT(result, HasSubstr(expectedResult));
    expectedResult = "sfLongGpuJankyFrames = " + std::to_string(1);
    EXPECT_THAT(result, HasSubstr(expectedResult));
    expectedResult = "sfUnattributedJankyFrame = " + std::to_string(1);
    EXPECT_THAT(result, HasSubstr(expectedResult));
    expectedResult = "appUnattributedJankyFrame = " + std::to_string(1);
    EXPECT_THAT(result, HasSubstr(expectedResult));
}

TEST_F(TimeStatsTest, canIncreaseClientCompositionReusedFrames) {
    // this stat is not in the proto so verify by checking the string dump
    constexpr size_t CLIENT_COMPOSITION_REUSED_FRAMES = 2;

    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());
    for (size_t i = 0; i < CLIENT_COMPOSITION_REUSED_FRAMES; i++) {
        ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementClientCompositionReusedFrames());
    }

    const std::string result(inputCommand(InputCommand::DUMP_ALL, FMT_STRING));
    const std::string expectedResult =
            "clientCompositionReusedFrames = " + std::to_string(CLIENT_COMPOSITION_REUSED_FRAMES);
    EXPECT_THAT(result, HasSubstr(expectedResult));
}

TEST_F(TimeStatsTest, canIncreaseRefreshRateSwitches) {
    // this stat is not in the proto so verify by checking the string dump
    constexpr size_t REFRESH_RATE_SWITCHES = 2;

    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());
    for (size_t i = 0; i < REFRESH_RATE_SWITCHES; i++) {
        ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementRefreshRateSwitches());
    }

    const std::string result(inputCommand(InputCommand::DUMP_ALL, FMT_STRING));
    const std::string expectedResult =
            "refreshRateSwitches = " + std::to_string(REFRESH_RATE_SWITCHES);
    EXPECT_THAT(result, HasSubstr(expectedResult));
}

TEST_F(TimeStatsTest, canIncreaseCompositionStrategyChanges) {
    // this stat is not in the proto so verify by checking the string dump
    constexpr size_t COMPOSITION_STRATEGY_CHANGES = 2;

    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());
    for (size_t i = 0; i < COMPOSITION_STRATEGY_CHANGES; i++) {
        ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementCompositionStrategyChanges());
    }

    const std::string result(inputCommand(InputCommand::DUMP_ALL, FMT_STRING));
    const std::string expectedResult =
            "compositionStrategyChanges = " + std::to_string(COMPOSITION_STRATEGY_CHANGES);
    EXPECT_THAT(result, HasSubstr(expectedResult));
}

TEST_F(TimeStatsTest, canAverageFrameDuration) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());
    mTimeStats->setPowerMode(PowerMode::ON);
    mTimeStats
            ->recordFrameDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(1ms).count(),
                                  std::chrono::duration_cast<std::chrono::nanoseconds>(6ms)
                                          .count());
    mTimeStats
            ->recordFrameDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(1ms).count(),
                                  std::chrono::duration_cast<std::chrono::nanoseconds>(16ms)
                                          .count());

    const std::string result(inputCommand(InputCommand::DUMP_ALL, FMT_STRING));
    EXPECT_THAT(result, HasSubstr("averageFrameDuration = 10.000 ms"));
}

TEST_F(TimeStatsTest, canAverageRenderEngineTimings) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());
    mTimeStats->recordRenderEngineDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(1ms)
                                                   .count(),
                                           std::make_shared<FenceTime>(
                                                   std::chrono::duration_cast<
                                                           std::chrono::nanoseconds>(3ms)
                                                           .count()));

    mTimeStats->recordRenderEngineDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(4ms)
                                                   .count(),
                                           std::chrono::duration_cast<std::chrono::nanoseconds>(8ms)
                                                   .count());

    // Push a fake present fence to trigger flushing the RenderEngine timings.
    mTimeStats->setPowerMode(PowerMode::ON);
    mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(1ms).count()));

    const std::string result(inputCommand(InputCommand::DUMP_ALL, FMT_STRING));
    EXPECT_THAT(result, HasSubstr("averageRenderEngineTiming = 3.000 ms"));
}

TEST_F(TimeStatsTest, canInsertGlobalPresentToPresent) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    ASSERT_NO_FATAL_FAILURE(
            mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(1000000)));
    ASSERT_NO_FATAL_FAILURE(
            mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(2000000)));

    ASSERT_NO_FATAL_FAILURE(mTimeStats->setPowerMode(PowerMode::ON));
    ASSERT_NO_FATAL_FAILURE(
            mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(3000000)));
    ASSERT_NO_FATAL_FAILURE(
            mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(5000000)));

    ASSERT_NO_FATAL_FAILURE(mTimeStats->setPowerMode(PowerMode::OFF));
    ASSERT_NO_FATAL_FAILURE(
            mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(6000000)));
    ASSERT_NO_FATAL_FAILURE(
            mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(8000000)));

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    ASSERT_EQ(1, globalProto.present_to_present_size());
    const SFTimeStatsHistogramBucketProto& histogramProto = globalProto.present_to_present().Get(0);
    EXPECT_EQ(1, histogramProto.frame_count());
    EXPECT_EQ(2, histogramProto.time_millis());
}

TEST_F(TimeStatsTest, canInsertGlobalFrameDuration) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    mTimeStats->setPowerMode(PowerMode::OFF);
    mTimeStats
            ->recordFrameDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(1ms).count(),
                                  std::chrono::duration_cast<std::chrono::nanoseconds>(5ms)
                                          .count());
    mTimeStats->setPowerMode(PowerMode::ON);
    mTimeStats
            ->recordFrameDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(3ms).count(),
                                  std::chrono::duration_cast<std::chrono::nanoseconds>(6ms)
                                          .count());

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    ASSERT_EQ(1, globalProto.frame_duration_size());
    const SFTimeStatsHistogramBucketProto& histogramProto = globalProto.frame_duration().Get(0);
    EXPECT_EQ(1, histogramProto.frame_count());
    EXPECT_EQ(3, histogramProto.time_millis());
}

TEST_F(TimeStatsTest, canInsertGlobalRenderEngineTiming) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    mTimeStats->recordRenderEngineDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(1ms)
                                                   .count(),
                                           std::make_shared<FenceTime>(
                                                   std::chrono::duration_cast<
                                                           std::chrono::nanoseconds>(3ms)
                                                           .count()));

    mTimeStats->recordRenderEngineDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(4ms)
                                                   .count(),
                                           std::chrono::duration_cast<std::chrono::nanoseconds>(6ms)
                                                   .count());

    // First verify that flushing RenderEngine durations did not occur yet.
    SFTimeStatsGlobalProto preFlushProto;
    ASSERT_TRUE(preFlushProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));
    ASSERT_EQ(0, preFlushProto.render_engine_timing_size());

    // Push a fake present fence to trigger flushing the RenderEngine timings.
    mTimeStats->setPowerMode(PowerMode::ON);
    mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(1ms).count()));

    // Now we can verify that RenderEngine durations were flushed now.
    SFTimeStatsGlobalProto postFlushProto;
    ASSERT_TRUE(postFlushProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    ASSERT_EQ(1, postFlushProto.render_engine_timing_size());
    const SFTimeStatsHistogramBucketProto& histogramProto =
            postFlushProto.render_engine_timing().Get(0);
    EXPECT_EQ(2, histogramProto.frame_count());
    EXPECT_EQ(2, histogramProto.time_millis());
}

TEST_F(TimeStatsTest, canInsertOneLayerTimeStats) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE_2, LAYER_ID_0, 2, 2000000);

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    ASSERT_EQ(1, globalProto.stats_size());
    const SFTimeStatsLayerProto& layerProto = globalProto.stats().Get(0);
    ASSERT_TRUE(layerProto.has_layer_name());
    EXPECT_EQ(genLayerName(LAYER_ID_0), layerProto.layer_name());
    ASSERT_TRUE(layerProto.has_total_frames());
    EXPECT_EQ(1, layerProto.total_frames());
    ASSERT_EQ(6, layerProto.deltas_size());
    for (const SFTimeStatsDeltaProto& deltaProto : layerProto.deltas()) {
        ASSERT_EQ(1, deltaProto.histograms_size());
        const SFTimeStatsHistogramBucketProto& histogramProto = deltaProto.histograms().Get(0);
        EXPECT_EQ(1, histogramProto.frame_count());
        if ("post2acquire" == deltaProto.delta_name()) {
            EXPECT_EQ(1, histogramProto.time_millis());
        } else if ("post2present" == deltaProto.delta_name()) {
            EXPECT_EQ(4, histogramProto.time_millis());
        } else if ("acquire2present" == deltaProto.delta_name()) {
            EXPECT_EQ(3, histogramProto.time_millis());
        } else if ("latch2present" == deltaProto.delta_name()) {
            EXPECT_EQ(2, histogramProto.time_millis());
        } else if ("desired2present" == deltaProto.delta_name()) {
            EXPECT_EQ(1, histogramProto.time_millis());
        } else if ("present2present" == deltaProto.delta_name()) {
            EXPECT_EQ(1, histogramProto.time_millis());
        } else {
            FAIL() << "Unknown delta_name: " << deltaProto.delta_name();
        }
    }
}

TEST_F(TimeStatsTest, canNotInsertInvalidLayerNameTimeStats) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_INVALID, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE_2, LAYER_ID_INVALID, 2, 2000000);

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    ASSERT_EQ(0, globalProto.stats_size());
}

TEST_F(TimeStatsTest, canInsertMultipleLayersTimeStats) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_1, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 2, 2000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_1, 2, 2000000);

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    EXPECT_EQ(2, globalProto.stats_size());
}

TEST_F(TimeStatsTest, canInsertUnorderedLayerTimeStats) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(UNORDERED_SEQUENCE, LAYER_ID_0, 2, 2000000);

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    ASSERT_EQ(1, globalProto.stats_size());
    const SFTimeStatsLayerProto& layerProto = globalProto.stats().Get(0);
    ASSERT_TRUE(layerProto.has_layer_name());
    EXPECT_EQ(genLayerName(LAYER_ID_0), layerProto.layer_name());
    ASSERT_TRUE(layerProto.has_total_frames());
    EXPECT_EQ(1, layerProto.total_frames());
    ASSERT_EQ(6, layerProto.deltas_size());
    for (const SFTimeStatsDeltaProto& deltaProto : layerProto.deltas()) {
        ASSERT_EQ(1, deltaProto.histograms_size());
        const SFTimeStatsHistogramBucketProto& histogramProto = deltaProto.histograms().Get(0);
        EXPECT_EQ(1, histogramProto.frame_count());
        if ("post2acquire" == deltaProto.delta_name()) {
            EXPECT_EQ(0, histogramProto.time_millis());
        } else if ("post2present" == deltaProto.delta_name()) {
            EXPECT_EQ(2, histogramProto.time_millis());
        } else if ("acquire2present" == deltaProto.delta_name()) {
            EXPECT_EQ(2, histogramProto.time_millis());
        } else if ("latch2present" == deltaProto.delta_name()) {
            EXPECT_EQ(2, histogramProto.time_millis());
        } else if ("desired2present" == deltaProto.delta_name()) {
            EXPECT_EQ(1, histogramProto.time_millis());
        } else if ("present2present" == deltaProto.delta_name()) {
            EXPECT_EQ(1, histogramProto.time_millis());
        } else {
            FAIL() << "Unknown delta_name: " << deltaProto.delta_name();
        }
    }
}

TEST_F(TimeStatsTest, recordRefreshRateNewConfigs) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    uint32_t fpsOne = 30;
    uint32_t fpsTwo = 90;
    uint64_t millisOne = 5000;
    uint64_t millisTwo = 7000;

    mTimeStats->recordRefreshRate(fpsOne, ms2ns(millisOne));
    mTimeStats->recordRefreshRate(fpsTwo, ms2ns(millisTwo));

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    SFTimeStatsDisplayConfigBucketProto expectedBucketOne;
    SFTimeStatsDisplayConfigProto* expectedConfigOne = expectedBucketOne.mutable_config();
    expectedConfigOne->set_fps(fpsOne);
    expectedBucketOne.set_duration_millis(millisOne);

    SFTimeStatsDisplayConfigBucketProto expectedBucketTwo;
    SFTimeStatsDisplayConfigProto* expectedConfigTwo = expectedBucketTwo.mutable_config();
    expectedConfigTwo->set_fps(fpsTwo);
    expectedBucketTwo.set_duration_millis(millisTwo);

    EXPECT_THAT(globalProto.display_config_stats(), SizeIs(2));

    std::unordered_set<uint32_t> seen_fps;
    for (const auto& bucket : globalProto.display_config_stats()) {
        seen_fps.emplace(bucket.config().fps());
        if (fpsOne == bucket.config().fps()) {
            EXPECT_EQ(millisOne, bucket.duration_millis());
        } else if (fpsTwo == bucket.config().fps()) {
            EXPECT_EQ(millisTwo, bucket.duration_millis());
        } else {
            FAIL() << "Unknown fps: " << bucket.config().fps();
        }
    }
    EXPECT_THAT(seen_fps, UnorderedElementsAre(fpsOne, fpsTwo));
}

TEST_F(TimeStatsTest, recordRefreshRateUpdatesConfig) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    uint32_t fps = 30;
    uint64_t millisOne = 5000;
    uint64_t millisTwo = 7000;

    mTimeStats->recordRefreshRate(fps, ms2ns(millisOne));
    mTimeStats->recordRefreshRate(fps, ms2ns(millisTwo));

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));
    EXPECT_THAT(globalProto.display_config_stats(), SizeIs(1));
    EXPECT_EQ(fps, globalProto.display_config_stats().Get(0).config().fps());
    EXPECT_EQ(millisOne + millisTwo, globalProto.display_config_stats().Get(0).duration_millis());
}

TEST_F(TimeStatsTest, canRemoveTimeRecord) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(INCOMPLETE_SEQUENCE, LAYER_ID_0, 2, 2000000);
    ASSERT_NO_FATAL_FAILURE(mTimeStats->removeTimeRecord(0, 2));
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 3, 3000000);

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    ASSERT_EQ(1, globalProto.stats_size());
    const SFTimeStatsLayerProto& layerProto = globalProto.stats().Get(0);
    ASSERT_TRUE(layerProto.has_total_frames());
    EXPECT_EQ(1, layerProto.total_frames());
}

TEST_F(TimeStatsTest, canRecoverFromIncompleteTimeRecordError) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    uint64_t frameNumber = 1;
    nsecs_t ts = 1000000;
    insertTimeRecord(INCOMPLETE_SEQUENCE, LAYER_ID_0, 1, 1000000);
    for (size_t i = 0; i < impl::TimeStats::MAX_NUM_TIME_RECORDS + 2; i++) {
        frameNumber++;
        ts += 1000000;
        insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, frameNumber, ts);
    }

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    ASSERT_EQ(1, globalProto.stats_size());
    const SFTimeStatsLayerProto& layerProto = globalProto.stats().Get(0);
    ASSERT_TRUE(layerProto.has_total_frames());
    EXPECT_EQ(1, layerProto.total_frames());
}

TEST_F(TimeStatsTest, layerTimeStatsOnDestroy) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 2, 2000000);
    ASSERT_NO_FATAL_FAILURE(mTimeStats->onDestroy(0));
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 3, 3000000);

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    ASSERT_EQ(1, globalProto.stats_size());
    const SFTimeStatsLayerProto& layerProto = globalProto.stats().Get(0);
    ASSERT_TRUE(layerProto.has_total_frames());
    EXPECT_EQ(1, layerProto.total_frames());
}

TEST_F(TimeStatsTest, canClearTimeStats) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementTotalFrames());
    ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementMissedFrames());
    ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementClientCompositionFrames());
    ASSERT_NO_FATAL_FAILURE(mTimeStats->setPowerMode(PowerMode::ON));

    mTimeStats
            ->recordFrameDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(3ms).count(),
                                  std::chrono::duration_cast<std::chrono::nanoseconds>(6ms)
                                          .count());
    mTimeStats->recordRenderEngineDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(4ms)
                                                   .count(),
                                           std::chrono::duration_cast<std::chrono::nanoseconds>(6ms)
                                                   .count());
    ASSERT_NO_FATAL_FAILURE(
            mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(1000000)));
    ASSERT_NO_FATAL_FAILURE(
            mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(2000000)));
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 2, 2000000);

    EXPECT_TRUE(inputCommand(InputCommand::CLEAR, FMT_STRING).empty());

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    EXPECT_EQ(0, globalProto.total_frames());
    EXPECT_EQ(0, globalProto.missed_frames());
    EXPECT_EQ(0, globalProto.client_composition_frames());
    EXPECT_EQ(0, globalProto.present_to_present_size());
    EXPECT_EQ(0, globalProto.frame_duration_size());
    EXPECT_EQ(0, globalProto.render_engine_timing_size());
    EXPECT_EQ(0, globalProto.stats_size());
}

TEST_F(TimeStatsTest, canClearDumpOnlyTimeStats) {
    // These stats are not in the proto so verify by checking the string dump.
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());
    ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementClientCompositionReusedFrames());
    ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementRefreshRateSwitches());
    ASSERT_NO_FATAL_FAILURE(mTimeStats->incrementCompositionStrategyChanges());
    mTimeStats->setPowerMode(PowerMode::ON);
    mTimeStats
            ->recordFrameDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(1ms).count(),
                                  std::chrono::duration_cast<std::chrono::nanoseconds>(5ms)
                                          .count());
    mTimeStats->recordRenderEngineDuration(std::chrono::duration_cast<std::chrono::nanoseconds>(4ms)
                                                   .count(),
                                           std::chrono::duration_cast<std::chrono::nanoseconds>(6ms)
                                                   .count());
    mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(1ms).count()));

    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0),
                                     JankType::SurfaceFlingerCpuDeadlineMissed);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0),
                                     JankType::SurfaceFlingerGpuDeadlineMissed);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0), JankType::DisplayHAL);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0),
                                     JankType::AppDeadlineMissed);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0), JankType::None);

    EXPECT_TRUE(inputCommand(InputCommand::CLEAR, FMT_STRING).empty());

    const std::string result(inputCommand(InputCommand::DUMP_ALL, FMT_STRING));
    EXPECT_THAT(result, HasSubstr("clientCompositionReusedFrames = 0"));
    EXPECT_THAT(result, HasSubstr("refreshRateSwitches = 0"));
    EXPECT_THAT(result, HasSubstr("compositionStrategyChanges = 0"));
    EXPECT_THAT(result, HasSubstr("averageFrameDuration = 0.000 ms"));
    EXPECT_THAT(result, HasSubstr("averageRenderEngineTiming = 0.000 ms"));
    EXPECT_THAT(result, HasSubstr("jankyFrames = 0"));
    EXPECT_THAT(result, HasSubstr("sfLongCpuJankyFrames = 0"));
    EXPECT_THAT(result, HasSubstr("sfLongGpuJankyFrames = 0"));
    EXPECT_THAT(result, HasSubstr("sfUnattributedJankyFrame = 0"));
    EXPECT_THAT(result, HasSubstr("appUnattributedJankyFrame = 0"));
}

TEST_F(TimeStatsTest, canDumpWithMaxLayers) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_1, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 2, 2000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_1, 2, 2000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_1, 3, 2000000);

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(
            globalProto.ParseFromString(inputCommand(InputCommand::DUMP_MAXLAYERS_1, FMT_PROTO)));

    ASSERT_EQ(1, globalProto.stats_size());
    const SFTimeStatsLayerProto& layerProto = globalProto.stats().Get(0);
    ASSERT_TRUE(layerProto.has_layer_name());
    EXPECT_EQ(genLayerName(LAYER_ID_1), layerProto.layer_name());
    ASSERT_TRUE(layerProto.has_total_frames());
    EXPECT_EQ(2, layerProto.total_frames());
}

TEST_F(TimeStatsTest, canDumpWithInvalidMaxLayers) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 2, 2000000);

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(
            inputCommand(InputCommand::DUMP_MAXLAYERS_INVALID, FMT_PROTO)));

    ASSERT_EQ(0, globalProto.stats_size());
}

TEST_F(TimeStatsTest, noInfInAverageFPS) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 2, 1000000);

    const std::string result(inputCommand(InputCommand::DUMP_ALL, FMT_STRING));
    EXPECT_THAT(result, HasSubstr("averageFPS = 0.000"));
}

namespace {
std::string buildExpectedHistogramBytestring(const std::vector<int32_t>& times,
                                             const std::vector<int32_t>& frameCounts) {
    util::ProtoOutputStream proto;
    for (int i = 0; i < times.size(); i++) {
        ALOGE("Writing time: %d", times[i]);
        proto.write(util::FIELD_TYPE_INT32 | util::FIELD_COUNT_REPEATED | 1 /* field id */,
                    (int32_t)times[i]);
        ALOGE("Writing count: %d", frameCounts[i]);
        proto.write(util::FIELD_TYPE_INT64 | util::FIELD_COUNT_REPEATED | 2 /* field id */,
                    (int64_t)frameCounts[i]);
    }
    std::string byteString;
    proto.serializeToString(&byteString);
    return byteString;
}

std::string dumpByteStringHex(const std::string& str) {
    std::stringstream ss;
    ss << std::hex;
    for (const char& c : str) {
        ss << (int)c << " ";
    }

    return ss.str();
}

} // namespace

MATCHER_P2(BytesEq, bytes, size, "") {
    std::string expected;
    expected.append((const char*)bytes, size);
    std::string actual;
    actual.append((const char*)arg, size);

    *result_listener << "Bytes are not equal! \n";
    *result_listener << "size: " << size << "\n";
    *result_listener << "expected: " << dumpByteStringHex(expected).c_str() << "\n";
    *result_listener << "actual: " << dumpByteStringHex(actual).c_str() << "\n";

    return expected == actual;
}

TEST_F(TimeStatsTest, globalStatsCallback) {
    constexpr size_t TOTAL_FRAMES = 5;
    constexpr size_t MISSED_FRAMES = 4;
    constexpr size_t CLIENT_COMPOSITION_FRAMES = 3;
    constexpr size_t DISPLAY_EVENT_CONNECTIONS = 14;

    mTimeStats->onBootFinished();
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    for (size_t i = 0; i < TOTAL_FRAMES; i++) {
        mTimeStats->incrementTotalFrames();
    }
    for (size_t i = 0; i < MISSED_FRAMES; i++) {
        mTimeStats->incrementMissedFrames();
    }
    for (size_t i = 0; i < CLIENT_COMPOSITION_FRAMES; i++) {
        mTimeStats->incrementClientCompositionFrames();
    }

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);

    mTimeStats->recordDisplayEventConnectionCount(DISPLAY_EVENT_CONNECTIONS);
    mTimeStats->setPowerMode(PowerMode::ON);
    mTimeStats->recordFrameDuration(1000000, 3000000);
    mTimeStats->recordRenderEngineDuration(2000000, 4000000);
    mTimeStats->recordRenderEngineDuration(2000000, std::make_shared<FenceTime>(3000000));

    mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(3000000));
    mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(5000000));

    mTimeStats->incrementJankyFrames(JankType::SurfaceFlingerCpuDeadlineMissed);
    mTimeStats->incrementJankyFrames(JankType::SurfaceFlingerGpuDeadlineMissed);
    mTimeStats->incrementJankyFrames(JankType::DisplayHAL);
    mTimeStats->incrementJankyFrames(JankType::AppDeadlineMissed);
    mTimeStats->incrementJankyFrames(JankType::None);

    EXPECT_THAT(mDelegate->mAtomTags,
                UnorderedElementsAre(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO,
                                     android::util::SURFACEFLINGER_STATS_LAYER_INFO));
    EXPECT_NE(nullptr, mDelegate->mCallback);
    EXPECT_EQ(mTimeStats.get(), mDelegate->mCookie);

    std::string expectedFrameDuration = buildExpectedHistogramBytestring({2}, {1});
    std::string expectedRenderEngineTiming = buildExpectedHistogramBytestring({1, 2}, {1, 1});

    {
        InSequence seq;
        EXPECT_CALL(*mDelegate,
                    statsEventSetAtomId(mDelegate->mEvent,
                                        android::util::SURFACEFLINGER_STATS_GLOBAL_INFO));
        EXPECT_CALL(*mDelegate, statsEventWriteInt64(mDelegate->mEvent, TOTAL_FRAMES));
        EXPECT_CALL(*mDelegate, statsEventWriteInt64(mDelegate->mEvent, MISSED_FRAMES));
        EXPECT_CALL(*mDelegate, statsEventWriteInt64(mDelegate->mEvent, CLIENT_COMPOSITION_FRAMES));
        EXPECT_CALL(*mDelegate, statsEventWriteInt64(mDelegate->mEvent, _));
        EXPECT_CALL(*mDelegate, statsEventWriteInt64(mDelegate->mEvent, 2));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, DISPLAY_EVENT_CONNECTIONS));
        EXPECT_CALL(*mDelegate,
                    statsEventWriteByteArray(mDelegate->mEvent,
                                             BytesEq((const uint8_t*)expectedFrameDuration.c_str(),
                                                     expectedFrameDuration.size()),
                                             expectedFrameDuration.size()));
        EXPECT_CALL(*mDelegate,
                    statsEventWriteByteArray(mDelegate->mEvent,
                                             BytesEq((const uint8_t*)
                                                             expectedRenderEngineTiming.c_str(),
                                                     expectedRenderEngineTiming.size()),
                                             expectedRenderEngineTiming.size()));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 5));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 4));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 1));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 1));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 1));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 1));
        EXPECT_CALL(*mDelegate, statsEventBuild(mDelegate->mEvent));
    }
    EXPECT_EQ(AStatsManager_PULL_SUCCESS,
              mDelegate->makePullAtomCallback(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO,
                                              mDelegate->mCookie));

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    EXPECT_EQ(0, globalProto.total_frames());
    EXPECT_EQ(0, globalProto.missed_frames());
    EXPECT_EQ(0, globalProto.client_composition_frames());
    EXPECT_EQ(0, globalProto.present_to_present_size());
}

TEST_F(TimeStatsTest, layerStatsCallback_pullsAllAndClears) {
    constexpr size_t LATE_ACQUIRE_FRAMES = 2;
    constexpr size_t BAD_DESIRED_PRESENT_FRAMES = 3;
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    mTimeStats->onBootFinished();

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    for (size_t i = 0; i < LATE_ACQUIRE_FRAMES; i++) {
        mTimeStats->incrementLatchSkipped(LAYER_ID_0, TimeStats::LatchSkipReason::LateAcquire);
    }
    for (size_t i = 0; i < BAD_DESIRED_PRESENT_FRAMES; i++) {
        mTimeStats->incrementBadDesiredPresent(LAYER_ID_0);
    }
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 2, 2000000);

    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0),
                                     JankType::SurfaceFlingerCpuDeadlineMissed);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0),
                                     JankType::SurfaceFlingerGpuDeadlineMissed);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0), JankType::DisplayHAL);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0),
                                     JankType::AppDeadlineMissed);
    mTimeStats->incrementJankyFrames(UID_0, genLayerName(LAYER_ID_0), JankType::None);

    EXPECT_THAT(mDelegate->mAtomTags,
                UnorderedElementsAre(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO,
                                     android::util::SURFACEFLINGER_STATS_LAYER_INFO));
    EXPECT_NE(nullptr, mDelegate->mCallback);
    EXPECT_EQ(mTimeStats.get(), mDelegate->mCookie);

    std::string expectedPresentToPresent = buildExpectedHistogramBytestring({1}, {1});
    std::string expectedPostToPresent = buildExpectedHistogramBytestring({4}, {1});
    std::string expectedAcquireToPresent = buildExpectedHistogramBytestring({3}, {1});
    std::string expectedLatchToPresent = buildExpectedHistogramBytestring({2}, {1});
    std::string expectedDesiredToPresent = buildExpectedHistogramBytestring({1}, {1});
    std::string expectedPostToAcquire = buildExpectedHistogramBytestring({1}, {1});
    {
        InSequence seq;
        EXPECT_CALL(*mDelegate,
                    statsEventSetAtomId(mDelegate->mEvent,
                                        android::util::SURFACEFLINGER_STATS_LAYER_INFO));
        EXPECT_CALL(*mDelegate,
                    statsEventWriteString8(mDelegate->mEvent,
                                           StrEq(genLayerName(LAYER_ID_0).c_str())));
        EXPECT_CALL(*mDelegate, statsEventWriteInt64(mDelegate->mEvent, 1));
        EXPECT_CALL(*mDelegate, statsEventWriteInt64(mDelegate->mEvent, 0));
        EXPECT_CALL(*mDelegate,
                    statsEventWriteByteArray(mDelegate->mEvent,
                                             BytesEq((const uint8_t*)
                                                             expectedPresentToPresent.c_str(),
                                                     expectedPresentToPresent.size()),
                                             expectedPresentToPresent.size()));
        EXPECT_CALL(*mDelegate,
                    statsEventWriteByteArray(mDelegate->mEvent,
                                             BytesEq((const uint8_t*)expectedPostToPresent.c_str(),
                                                     expectedPostToPresent.size()),
                                             expectedPostToPresent.size()));
        EXPECT_CALL(*mDelegate,
                    statsEventWriteByteArray(mDelegate->mEvent,
                                             BytesEq((const uint8_t*)
                                                             expectedAcquireToPresent.c_str(),
                                                     expectedAcquireToPresent.size()),
                                             expectedAcquireToPresent.size()));
        EXPECT_CALL(*mDelegate,
                    statsEventWriteByteArray(mDelegate->mEvent,
                                             BytesEq((const uint8_t*)expectedLatchToPresent.c_str(),
                                                     expectedLatchToPresent.size()),
                                             expectedLatchToPresent.size()));
        EXPECT_CALL(*mDelegate,
                    statsEventWriteByteArray(mDelegate->mEvent,
                                             BytesEq((const uint8_t*)
                                                             expectedDesiredToPresent.c_str(),
                                                     expectedDesiredToPresent.size()),
                                             expectedDesiredToPresent.size()));
        EXPECT_CALL(*mDelegate,
                    statsEventWriteByteArray(mDelegate->mEvent,
                                             BytesEq((const uint8_t*)expectedPostToAcquire.c_str(),
                                                     expectedPostToAcquire.size()),
                                             expectedPostToAcquire.size()));
        EXPECT_CALL(*mDelegate, statsEventWriteInt64(mDelegate->mEvent, LATE_ACQUIRE_FRAMES));
        EXPECT_CALL(*mDelegate,
                    statsEventWriteInt64(mDelegate->mEvent, BAD_DESIRED_PRESENT_FRAMES));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, UID_0));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 5));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 4));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 1));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 1));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 1));
        EXPECT_CALL(*mDelegate, statsEventWriteInt32(mDelegate->mEvent, 1));

        EXPECT_CALL(*mDelegate, statsEventBuild(mDelegate->mEvent));
    }
    EXPECT_EQ(AStatsManager_PULL_SUCCESS,
              mDelegate->makePullAtomCallback(android::util::SURFACEFLINGER_STATS_LAYER_INFO,
                                              mDelegate->mCookie));

    SFTimeStatsGlobalProto globalProto;
    ASSERT_TRUE(globalProto.ParseFromString(inputCommand(InputCommand::DUMP_ALL, FMT_PROTO)));

    EXPECT_EQ(0, globalProto.stats_size());
}

TEST_F(TimeStatsTest, layerStatsCallback_pullsMultipleLayers) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    mTimeStats->onBootFinished();

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 2, 2000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_1, 1, 2000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_1, 2, 3000000);

    EXPECT_THAT(mDelegate->mAtomTags,
                UnorderedElementsAre(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO,
                                     android::util::SURFACEFLINGER_STATS_LAYER_INFO));
    EXPECT_NE(nullptr, mDelegate->mCallback);
    EXPECT_EQ(mTimeStats.get(), mDelegate->mCookie);

    EXPECT_CALL(*mDelegate,
                statsEventSetAtomId(mDelegate->mEvent,
                                    android::util::SURFACEFLINGER_STATS_LAYER_INFO))
            .Times(2);
    EXPECT_CALL(*mDelegate,
                statsEventWriteString8(mDelegate->mEvent, StrEq(genLayerName(LAYER_ID_0).c_str())));
    EXPECT_CALL(*mDelegate,
                statsEventWriteString8(mDelegate->mEvent, StrEq(genLayerName(LAYER_ID_1).c_str())));
    EXPECT_EQ(AStatsManager_PULL_SUCCESS,
              mDelegate->makePullAtomCallback(android::util::SURFACEFLINGER_STATS_LAYER_INFO,
                                              mDelegate->mCookie));
}

TEST_F(TimeStatsTest, layerStatsCallback_pullsMultipleBuckets) {
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    mTimeStats->onBootFinished();

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 2, 2000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 3, 4000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 4, 5000000);

    // Now make sure that TimeStats flushes global stats to set the callback.
    mTimeStats->setPowerMode(PowerMode::ON);
    mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(3000000));
    mTimeStats->setPresentFenceGlobal(std::make_shared<FenceTime>(5000000));
    EXPECT_THAT(mDelegate->mAtomTags,
                UnorderedElementsAre(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO,
                                     android::util::SURFACEFLINGER_STATS_LAYER_INFO));
    EXPECT_NE(nullptr, mDelegate->mCallback);
    EXPECT_EQ(mTimeStats.get(), mDelegate->mCookie);

    EXPECT_THAT(mDelegate->mAtomTags,
                UnorderedElementsAre(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO,
                                     android::util::SURFACEFLINGER_STATS_LAYER_INFO));
    std::string expectedPresentToPresent = buildExpectedHistogramBytestring({1, 2}, {2, 1});
    {
        InSequence seq;
        EXPECT_CALL(*mDelegate,
                    statsEventWriteByteArray(mDelegate->mEvent,
                                             BytesEq((const uint8_t*)
                                                             expectedPresentToPresent.c_str(),
                                                     expectedPresentToPresent.size()),
                                             expectedPresentToPresent.size()));
        EXPECT_CALL(*mDelegate, statsEventWriteByteArray(mDelegate->mEvent, _, _))
                .Times(AnyNumber());
    }
    EXPECT_EQ(AStatsManager_PULL_SUCCESS,
              mDelegate->makePullAtomCallback(android::util::SURFACEFLINGER_STATS_LAYER_INFO,
                                              mDelegate->mCookie));
}

TEST_F(TimeStatsTest, layerStatsCallback_limitsHistogramBuckets) {
    mDelegate = new FakeStatsEventDelegate;
    mTimeStats =
            std::make_unique<impl::TimeStats>(std::unique_ptr<FakeStatsEventDelegate>(mDelegate),
                                              std::nullopt, 1);
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    mTimeStats->onBootFinished();

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 2, 2000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 3, 4000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 4, 5000000);

    EXPECT_THAT(mDelegate->mAtomTags,
                UnorderedElementsAre(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO,
                                     android::util::SURFACEFLINGER_STATS_LAYER_INFO));
    EXPECT_NE(nullptr, mDelegate->mCallback);
    EXPECT_EQ(mTimeStats.get(), mDelegate->mCookie);

    EXPECT_THAT(mDelegate->mAtomTags,
                UnorderedElementsAre(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO,
                                     android::util::SURFACEFLINGER_STATS_LAYER_INFO));
    std::string expectedPresentToPresent = buildExpectedHistogramBytestring({1}, {2});
    {
        InSequence seq;
        EXPECT_CALL(*mDelegate,
                    statsEventWriteByteArray(mDelegate->mEvent,
                                             BytesEq((const uint8_t*)
                                                             expectedPresentToPresent.c_str(),
                                                     expectedPresentToPresent.size()),
                                             expectedPresentToPresent.size()));
        EXPECT_CALL(*mDelegate, statsEventWriteByteArray(mDelegate->mEvent, _, _))
                .Times(AnyNumber());
    }
    EXPECT_EQ(AStatsManager_PULL_SUCCESS,
              mDelegate->makePullAtomCallback(android::util::SURFACEFLINGER_STATS_LAYER_INFO,
                                              mDelegate->mCookie));
}

TEST_F(TimeStatsTest, layerStatsCallback_limitsLayers) {
    mDelegate = new FakeStatsEventDelegate;
    mTimeStats =
            std::make_unique<impl::TimeStats>(std::unique_ptr<FakeStatsEventDelegate>(mDelegate), 1,
                                              std::nullopt);
    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    mTimeStats->onBootFinished();

    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 1, 1000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_0, 2, 2000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_1, 1, 2000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_1, 2, 3000000);
    insertTimeRecord(NORMAL_SEQUENCE, LAYER_ID_1, 4, 5000000);

    EXPECT_THAT(mDelegate->mAtomTags,
                UnorderedElementsAre(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO,
                                     android::util::SURFACEFLINGER_STATS_LAYER_INFO));
    EXPECT_NE(nullptr, mDelegate->mCallback);
    EXPECT_EQ(mTimeStats.get(), mDelegate->mCookie);

    EXPECT_CALL(*mDelegate,
                statsEventSetAtomId(mDelegate->mEvent,
                                    android::util::SURFACEFLINGER_STATS_LAYER_INFO))
            .Times(1);
    EXPECT_CALL(*mDelegate,
                statsEventWriteString8(mDelegate->mEvent, StrEq(genLayerName(LAYER_ID_1).c_str())));
    EXPECT_EQ(AStatsManager_PULL_SUCCESS,
              mDelegate->makePullAtomCallback(android::util::SURFACEFLINGER_STATS_LAYER_INFO,
                                              mDelegate->mCookie));
}

TEST_F(TimeStatsTest, canSurviveMonkey) {
    if (g_noSlowTests) {
        GTEST_SKIP();
    }

    EXPECT_TRUE(inputCommand(InputCommand::ENABLE, FMT_STRING).empty());

    for (size_t i = 0; i < 10000000; ++i) {
        const int32_t layerId = genRandomInt32(-1, 10);
        const int32_t frameNumber = genRandomInt32(1, 10);
        switch (genRandomInt32(0, 100)) {
            case 0:
                ALOGV("removeTimeRecord");
                ASSERT_NO_FATAL_FAILURE(mTimeStats->removeTimeRecord(layerId, frameNumber));
                continue;
            case 1:
                ALOGV("onDestroy");
                ASSERT_NO_FATAL_FAILURE(mTimeStats->onDestroy(layerId));
                continue;
        }
        TimeStamp type = static_cast<TimeStamp>(genRandomInt32(TIME_STAMP_BEGIN, TIME_STAMP_END));
        const int32_t ts = genRandomInt32(1, 1000000000);
        ALOGV("type[%d], layerId[%d], frameNumber[%d], ts[%d]", type, layerId, frameNumber, ts);
        setTimeStamp(type, layerId, frameNumber, ts);
    }
}

} // namespace
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
