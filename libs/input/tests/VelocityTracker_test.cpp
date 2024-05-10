/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "VelocityTracker_test"

#include <math.h>
#include <array>
#include <chrono>
#include <limits>

#include <android-base/stringprintf.h>
#include <attestation/HmacKeyManager.h>
#include <gtest/gtest.h>
#include <input/VelocityTracker.h>

using std::literals::chrono_literals::operator""ms;
using std::literals::chrono_literals::operator""ns;
using std::literals::chrono_literals::operator""us;
using android::base::StringPrintf;

namespace android {

constexpr ui::LogicalDisplayId DISPLAY_ID = ui::LogicalDisplayId::DEFAULT; // default display id

constexpr int32_t DEFAULT_POINTER_ID = 0; // pointer ID used for manually defined tests

// velocity must be in the range (1-tol)*EV <= velocity <= (1+tol)*EV
// here EV = expected value, tol = VELOCITY_TOLERANCE
constexpr float VELOCITY_TOLERANCE = 0.2;

// quadratic velocity must be within 0.001% of the target value
constexpr float QUADRATIC_VELOCITY_TOLERANCE = 0.00001;

// --- VelocityTrackerTest ---
class VelocityTrackerTest : public testing::Test { };

/*
 * Similar to EXPECT_NEAR, but ensures that the difference between the two float values
 * is at most a certain fraction of the target value.
 * If fraction is zero, require exact match.
 */
static void EXPECT_NEAR_BY_FRACTION(float actual, float target, float fraction) {
    float tolerance = fabsf(target * fraction);

    if (target == 0 && fraction != 0) {
        // If target is zero, this would force actual == target, which is too harsh.
        // Relax this requirement a little. The value is determined empirically from the
        // coefficients computed by the quadratic least squares algorithms.
        tolerance = 1E-6;
    }
    EXPECT_NEAR(actual, target, tolerance);
}

static void checkVelocity(std::optional<float> Vactual, std::optional<float> Vtarget) {
    if (Vactual != std::nullopt) {
        if (Vtarget == std::nullopt) {
            FAIL() << "Expected no velocity, but found " << *Vactual;
        }
        EXPECT_NEAR_BY_FRACTION(*Vactual, *Vtarget, VELOCITY_TOLERANCE);
    } else if (Vtarget != std::nullopt) {
        FAIL() << "Expected  velocity, but found no velocity";
    }
}

struct Position {
    float x;
    float y;

    bool isResampled = false;

    /**
     * If both values are NAN, then this is considered to be an empty entry (no pointer data).
     * If only one of the values is NAN, this is still a valid entry,
     * because we may only care about a single axis.
     */
    bool isValid() const {
        return !(isnan(x) && isnan(y));
    }
};

struct PlanarMotionEventEntry {
    std::chrono::nanoseconds eventTime;
    std::vector<Position> positions;
};

static BitSet32 getValidPointers(const std::vector<Position>& positions) {
    BitSet32 pointers;
    for (size_t i = 0; i < positions.size(); i++) {
        if (positions[i].isValid()) {
            pointers.markBit(i);
        }
    }
    return pointers;
}

static uint32_t getChangingPointerId(BitSet32 pointers, BitSet32 otherPointers) {
    BitSet32 difference(pointers.value ^ otherPointers.value);
    uint32_t pointerId = difference.clearFirstMarkedBit();
    EXPECT_EQ(0U, difference.value) << "Only 1 pointer can enter or leave at a time";
    return pointerId;
}

static int32_t resolveAction(const std::vector<Position>& lastPositions,
        const std::vector<Position>& currentPositions,
        const std::vector<Position>& nextPositions) {
    BitSet32 pointers = getValidPointers(currentPositions);
    const uint32_t pointerCount = pointers.count();

    BitSet32 lastPointers = getValidPointers(lastPositions);
    const uint32_t lastPointerCount = lastPointers.count();
    if (lastPointerCount < pointerCount) {
        // A new pointer is down
        uint32_t pointerId = getChangingPointerId(pointers, lastPointers);
        return AMOTION_EVENT_ACTION_POINTER_DOWN |
                (pointerId << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    }

    BitSet32 nextPointers = getValidPointers(nextPositions);
    const uint32_t nextPointerCount = nextPointers.count();
    if (pointerCount > nextPointerCount) {
        // An existing pointer is leaving
        uint32_t pointerId = getChangingPointerId(pointers, nextPointers);
        return AMOTION_EVENT_ACTION_POINTER_UP |
                (pointerId << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    }

    return AMOTION_EVENT_ACTION_MOVE;
}

static std::vector<MotionEvent> createAxisScrollMotionEventStream(
        const std::vector<std::pair<std::chrono::nanoseconds, float>>& motions) {
    std::vector<MotionEvent> events;
    for (const auto& [timeStamp, value] : motions) {
        EXPECT_TRUE(!isnan(value)) << "The entry at pointerId must be valid";

        PointerCoords coords[1];
        coords[0].setAxisValue(AMOTION_EVENT_AXIS_SCROLL, value);

        PointerProperties properties[1];
        properties[0].id = DEFAULT_POINTER_ID;

        MotionEvent event;
        ui::Transform identityTransform;
        event.initialize(InputEvent::nextId(), /*deviceId=*/5, AINPUT_SOURCE_ROTARY_ENCODER,
                         ui::LogicalDisplayId::INVALID, INVALID_HMAC, AMOTION_EVENT_ACTION_SCROLL,
                         /*actionButton=*/0, /*flags=*/0, AMOTION_EVENT_EDGE_FLAG_NONE, AMETA_NONE,
                         /*buttonState=*/0, MotionClassification::NONE, identityTransform,
                         /*xPrecision=*/0, /*yPrecision=*/0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                         AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, /*downTime=*/0,
                         timeStamp.count(), /*pointerCount=*/1, properties, coords);

        events.emplace_back(event);
    }

    return events;
}

static std::vector<MotionEvent> createTouchMotionEventStream(
        const std::vector<PlanarMotionEventEntry>& motions) {
    if (motions.empty()) {
        ADD_FAILURE() << "Need at least 1 sample to create a MotionEvent. Received empty vector.";
    }

    std::vector<MotionEvent> events;
    for (size_t i = 0; i < motions.size(); i++) {
        const PlanarMotionEventEntry& entry = motions[i];
        BitSet32 pointers = getValidPointers(entry.positions);
        const uint32_t pointerCount = pointers.count();

        int32_t action;
        if (i == 0) {
            action = AMOTION_EVENT_ACTION_DOWN;
            EXPECT_EQ(1U, pointerCount) << "First event should only have 1 pointer";
        } else if ((i == motions.size() - 1) && pointerCount == 1) {
            action = AMOTION_EVENT_ACTION_UP;
        } else {
            const PlanarMotionEventEntry& previousEntry = motions[i-1];
            const PlanarMotionEventEntry& nextEntry = motions[i+1];
            action = resolveAction(previousEntry.positions, entry.positions, nextEntry.positions);
        }

        PointerCoords coords[pointerCount];
        PointerProperties properties[pointerCount];
        uint32_t pointerIndex = 0;
        while(!pointers.isEmpty()) {
            uint32_t pointerId = pointers.clearFirstMarkedBit();

            coords[pointerIndex].clear();
            // We are treating column positions as pointerId
            const Position& position = entry.positions[pointerId];
            EXPECT_TRUE(position.isValid()) << "The entry at " << pointerId << " must be valid";
            coords[pointerIndex].setAxisValue(AMOTION_EVENT_AXIS_X, position.x);
            coords[pointerIndex].setAxisValue(AMOTION_EVENT_AXIS_Y, position.y);
            coords[pointerIndex].isResampled = position.isResampled;

            properties[pointerIndex].id = pointerId;
            properties[pointerIndex].toolType = ToolType::FINGER;
            pointerIndex++;
        }
        EXPECT_EQ(pointerIndex, pointerCount);

        MotionEvent event;
        ui::Transform identityTransform;
        event.initialize(InputEvent::nextId(), /*deviceId=*/0, AINPUT_SOURCE_TOUCHSCREEN,
                         DISPLAY_ID, INVALID_HMAC, action, /*actionButton=*/0, /*flags=*/0,
                         AMOTION_EVENT_EDGE_FLAG_NONE, AMETA_NONE, /*buttonState=*/0,
                         MotionClassification::NONE, identityTransform, /*xPrecision=*/0,
                         /*yPrecision=*/0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                         AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, /*downTime=*/0,
                         entry.eventTime.count(), pointerCount, properties, coords);

        events.emplace_back(event);
    }

    return events;
}

static std::optional<float> computeVelocity(const VelocityTracker::Strategy strategy,
                                            const std::vector<MotionEvent>& events, int32_t axis,
                                            uint32_t pointerId = DEFAULT_POINTER_ID) {
    VelocityTracker vt(strategy);

    for (const MotionEvent& event : events) {
        vt.addMovement(event);
    }

    return vt.getVelocity(axis, pointerId);
}

static std::optional<float> computePlanarVelocity(
        const VelocityTracker::Strategy strategy,
        const std::vector<PlanarMotionEventEntry>& motions, int32_t axis, uint32_t pointerId) {
    std::vector<MotionEvent> events = createTouchMotionEventStream(motions);
    return computeVelocity(strategy, events, axis, pointerId);
}

static void computeAndCheckVelocity(const VelocityTracker::Strategy strategy,
                                    const std::vector<PlanarMotionEventEntry>& motions,
                                    int32_t axis, std::optional<float> targetVelocity,
                                    uint32_t pointerId = DEFAULT_POINTER_ID) {
    checkVelocity(computePlanarVelocity(strategy, motions, axis, pointerId), targetVelocity);
}

static void computeAndCheckAxisScrollVelocity(
        const VelocityTracker::Strategy strategy,
        const std::vector<std::pair<std::chrono::nanoseconds, float>>& motions,
        std::optional<float> targetVelocity) {
    std::vector<MotionEvent> events = createAxisScrollMotionEventStream(motions);
    checkVelocity(computeVelocity(strategy, events, AMOTION_EVENT_AXIS_SCROLL), targetVelocity);
    // The strategy LSQ2 is not compatible with AXIS_SCROLL. In those situations, we should fall
    // back to a strategy that supports differential axes.
    checkVelocity(computeVelocity(VelocityTracker::Strategy::LSQ2, events,
                                  AMOTION_EVENT_AXIS_SCROLL),
                  targetVelocity);
}

static void computeAndCheckQuadraticVelocity(const std::vector<PlanarMotionEventEntry>& motions,
                                             float velocity) {
    std::optional<float> velocityX =
            computePlanarVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                                  DEFAULT_POINTER_ID);
    std::optional<float> velocityY =
            computePlanarVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                                  DEFAULT_POINTER_ID);
    ASSERT_TRUE(velocityX);
    ASSERT_TRUE(velocityY);

    EXPECT_NEAR_BY_FRACTION(*velocityX, velocity, QUADRATIC_VELOCITY_TOLERANCE);
    EXPECT_NEAR_BY_FRACTION(*velocityY, velocity, QUADRATIC_VELOCITY_TOLERANCE);
}

/*
 *================== VelocityTracker tests that do not require test motion data ====================
 */
TEST(SimpleVelocityTrackerTest, TestSupportedAxis) {
    // Note that we are testing up to the max possible axis value, plus 3 more values. We are going
    // beyond the max value to add a bit more protection. "3" is chosen arbitrarily to cover a few
    // more values beyond the max.
    for (int32_t axis = 0; axis <= AMOTION_EVENT_MAXIMUM_VALID_AXIS_VALUE + 3; axis++) {
        switch (axis) {
            case AMOTION_EVENT_AXIS_X:
            case AMOTION_EVENT_AXIS_Y:
            case AMOTION_EVENT_AXIS_SCROLL:
                EXPECT_TRUE(VelocityTracker::isAxisSupported(axis)) << axis << " is supported";
                break;
            default:
                EXPECT_FALSE(VelocityTracker::isAxisSupported(axis)) << axis << " is NOT supported";
        }
    }
}

/*
 * ================== VelocityTracker tests generated manually =====================================
 */
TEST_F(VelocityTrackerTest, TestDefaultStrategiesForPlanarAxes) {
    std::vector<PlanarMotionEventEntry> motions = {{10ms, {{2, 4}}},
                                                   {20ms, {{4, 12}}},
                                                   {30ms, {{6, 20}}},
                                                   {40ms, {{10, 30}}}};

    EXPECT_EQ(computePlanarVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                                    DEFAULT_POINTER_ID),
              computePlanarVelocity(VelocityTracker::Strategy::DEFAULT, motions,
                                    AMOTION_EVENT_AXIS_X, DEFAULT_POINTER_ID));
    EXPECT_EQ(computePlanarVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                                    DEFAULT_POINTER_ID),
              computePlanarVelocity(VelocityTracker::Strategy::DEFAULT, motions,
                                    AMOTION_EVENT_AXIS_Y, DEFAULT_POINTER_ID));
}

TEST_F(VelocityTrackerTest, TestComputedVelocity) {
    VelocityTracker::ComputedVelocity computedVelocity;

    computedVelocity.addVelocity(AMOTION_EVENT_AXIS_X, /*id=*/0, /*velocity=*/200);
    computedVelocity.addVelocity(AMOTION_EVENT_AXIS_X, /*id=*/26U, /*velocity=*/400);
    computedVelocity.addVelocity(AMOTION_EVENT_AXIS_X, /*id=*/27U, /*velocity=*/650);
    computedVelocity.addVelocity(AMOTION_EVENT_AXIS_X, MAX_POINTER_ID, /*velocity=*/750);
    computedVelocity.addVelocity(AMOTION_EVENT_AXIS_Y, /*id=*/0, /*velocity=*/1000);
    computedVelocity.addVelocity(AMOTION_EVENT_AXIS_Y, /*id=*/26U, /*velocity=*/2000);
    computedVelocity.addVelocity(AMOTION_EVENT_AXIS_Y, /*id=*/27U, /*velocity=*/3000);
    computedVelocity.addVelocity(AMOTION_EVENT_AXIS_Y, MAX_POINTER_ID, /*velocity=*/4000);

    // Check the axes/indices with velocity.
    EXPECT_EQ(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_X, /*id=*/0U)), 200);
    EXPECT_EQ(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_X, /*id=*/26U)), 400);
    EXPECT_EQ(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_X, /*id=*/27U)), 650);
    EXPECT_EQ(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_X, MAX_POINTER_ID)), 750);
    EXPECT_EQ(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_Y, /*id=*/0U)), 1000);
    EXPECT_EQ(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_Y, /*id=*/26U)), 2000);
    EXPECT_EQ(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_Y, /*id=*/27U)), 3000);
    EXPECT_EQ(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_Y, MAX_POINTER_ID)), 4000);
    for (uint32_t id = 0; id <= MAX_POINTER_ID; id++) {
        // Since no data was added for AXIS_SCROLL, expect empty value for the axis for any id.
        EXPECT_FALSE(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_SCROLL, id))
                << "Empty scroll data expected at id=" << id;
        if (id == 0 || id == 26U || id == 27U || id == MAX_POINTER_ID) {
            // Already checked above; continue.
            continue;
        }
        // No data was added to X/Y for this id, expect empty value.
        EXPECT_FALSE(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_X, id))
                << "Empty X data expected at id=" << id;
        EXPECT_FALSE(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_Y, id))
                << "Empty Y data expected at id=" << id;
    }
    // Out-of-bounds ids should given empty values.
    EXPECT_FALSE(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_X, -1));
    EXPECT_FALSE(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_X, MAX_POINTER_ID + 1));
}

/**
 * For a single pointer, the resampled data is ignored.
 */
TEST_F(VelocityTrackerTest, SinglePointerResampledData) {
    std::vector<PlanarMotionEventEntry> motions = {{10ms, {{1, 2}}},
                                                   {20ms, {{2, 4}}},
                                                   {30ms, {{3, 6}}},
                                                   {35ms, {{30, 60, .isResampled = true}}},
                                                   {40ms, {{4, 8}}}};

    computeAndCheckVelocity(VelocityTracker::Strategy::DEFAULT, motions, AMOTION_EVENT_AXIS_X, 100);
    computeAndCheckVelocity(VelocityTracker::Strategy::DEFAULT, motions, AMOTION_EVENT_AXIS_Y, 200);
}

/**
 * For multiple pointers, the resampled data is ignored on a per-pointer basis. If a certain pointer
 * does not have a resampled value, all of the points are used.
 */
TEST_F(VelocityTrackerTest, MultiPointerResampledData) {
    std::vector<PlanarMotionEventEntry> motions = {
            {0ms, {{0, 0}}},
            {10ms, {{1, 0}, {1, 0}}},
            {20ms, {{2, 0}, {2, 0}}},
            {30ms, {{3, 0}, {3, 0}}},
            {35ms, {{30, 0, .isResampled = true}, {30, 0}}},
            {40ms, {{4, 0}, {4, 0}}},
            {45ms, {{5, 0}}}, // ACTION_UP
    };

    // Sample at t=35ms breaks trend. It's marked as resampled for the first pointer, so it should
    // be ignored, and the resulting velocity should be linear. For the second pointer, it's not
    // resampled, so it should cause the velocity to be non-linear.
    computeAndCheckVelocity(VelocityTracker::Strategy::DEFAULT, motions, AMOTION_EVENT_AXIS_X, 100,
                            /*pointerId=*/0);
    computeAndCheckVelocity(VelocityTracker::Strategy::DEFAULT, motions, AMOTION_EVENT_AXIS_X, 3455,
                            /*pointerId=*/1);
}

TEST_F(VelocityTrackerTest, TestGetComputedVelocity) {
    std::vector<PlanarMotionEventEntry> motions = {
            {235089067457000ns, {{528.00, 0}}}, {235089084684000ns, {{527.00, 0}}},
            {235089093349000ns, {{527.00, 0}}}, {235089095677625ns, {{527.00, 0}}},
            {235089101859000ns, {{527.00, 0}}}, {235089110378000ns, {{528.00, 0}}},
            {235089112497111ns, {{528.25, 0}}}, {235089118760000ns, {{531.00, 0}}},
            {235089126686000ns, {{535.00, 0}}}, {235089129316820ns, {{536.33, 0}}},
            {235089135199000ns, {{540.00, 0}}}, {235089144297000ns, {{546.00, 0}}},
            {235089146136443ns, {{547.21, 0}}}, {235089152923000ns, {{553.00, 0}}},
            {235089160784000ns, {{559.00, 0}}}, {235089162955851ns, {{560.66, 0}}},
            {235089162955851ns, {{560.66, 0}}}, // ACTION_UP
    };
    VelocityTracker vt(VelocityTracker::Strategy::IMPULSE);
    std::vector<MotionEvent> events = createTouchMotionEventStream(motions);
    for (const MotionEvent& event : events) {
        vt.addMovement(event);
    }

    float maxFloat = std::numeric_limits<float>::max();
    VelocityTracker::ComputedVelocity computedVelocity;
    computedVelocity = vt.getComputedVelocity(/*units=*/1000, maxFloat);
    checkVelocity(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_X, DEFAULT_POINTER_ID)),
                  764.345703);

    // Expect X velocity to be scaled with respective to provided units.
    computedVelocity = vt.getComputedVelocity(/*units=*/1000000, maxFloat);
    checkVelocity(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_X, DEFAULT_POINTER_ID)),
                  764345.703);

    // Expect X velocity to be clamped by provided max velocity.
    computedVelocity = vt.getComputedVelocity(/*units=*/1000000, 1000);
    checkVelocity(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_X, DEFAULT_POINTER_ID)), 1000);

    // All 0 data for Y; expect 0 velocity.
    EXPECT_EQ(*(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_Y, DEFAULT_POINTER_ID)), 0);

    // No data for scroll-axis; expect empty velocity.
    EXPECT_FALSE(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_SCROLL, DEFAULT_POINTER_ID));
}

TEST_F(VelocityTrackerTest, TestApiInteractionsWithNoMotionEvents) {
    VelocityTracker vt(VelocityTracker::Strategy::DEFAULT);

    EXPECT_FALSE(vt.getVelocity(AMOTION_EVENT_AXIS_X, DEFAULT_POINTER_ID));

    VelocityTracker::ComputedVelocity computedVelocity = vt.getComputedVelocity(1000, 1000);
    for (uint32_t id = 0; id <= MAX_POINTER_ID; id++) {
        EXPECT_FALSE(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_X, id));
        EXPECT_FALSE(computedVelocity.getVelocity(AMOTION_EVENT_AXIS_Y, id));
    }

    EXPECT_EQ(-1, vt.getActivePointerId());

    // Make sure that the clearing functions execute without an issue.
    vt.clearPointer(7U);
    vt.clear();
}

TEST_F(VelocityTrackerTest, ThreePointsPositiveVelocityTest) {
    // Same coordinate is reported 2 times in a row
    // It is difficult to determine the correct answer here, but at least the direction
    // of the reported velocity should be positive.
    std::vector<PlanarMotionEventEntry> motions = {
            {0ms, {{273, 0}}},
            {12585us, {{293, 0}}},
            {14730us, {{293, 0}}},
            {14730us, {{293, 0}}}, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            1600);
}

TEST_F(VelocityTrackerTest, ThreePointsZeroVelocityTest) {
    // Same coordinate is reported 3 times in a row
    std::vector<PlanarMotionEventEntry> motions = {
            {0ms, {{293, 0}}},
            {6132us, {{293, 0}}},
            {11283us, {{293, 0}}},
            {11283us, {{293, 0}}}, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X, 0);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X, 0);
}

TEST_F(VelocityTrackerTest, ThreePointsLinearVelocityTest) {
    // Fixed velocity at 5 points per 10 milliseconds
    std::vector<PlanarMotionEventEntry> motions = {
            {0ms, {{0, 0}}}, {10ms, {{5, 0}}}, {20ms, {{10, 0}}}, {20ms, {{10, 0}}}, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X, 500);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X, 500);
}

/**
 * When the stream is terminated with ACTION_CANCEL, the resulting velocity should be 0.
 */
TEST_F(VelocityTrackerTest, ActionCancelResultsInZeroVelocity) {
    std::vector<PlanarMotionEventEntry> motions = {
            {0ms, {{0, 0}}},    // DOWN
            {10ms, {{5, 10}}},  // MOVE
            {20ms, {{10, 20}}}, // MOVE
            {20ms, {{10, 20}}}, // ACTION_UP
    };
    std::vector<MotionEvent> events = createTouchMotionEventStream(motions);
    // By default, `createTouchMotionEventStream` produces an event stream that terminates with
    // ACTION_UP. We need to manually change it to ACTION_CANCEL.
    MotionEvent& lastEvent = events.back();
    lastEvent.setAction(AMOTION_EVENT_ACTION_CANCEL);
    lastEvent.setFlags(lastEvent.getFlags() | AMOTION_EVENT_FLAG_CANCELED);
    const int32_t pointerId = lastEvent.getPointerId(0);
    checkVelocity(computeVelocity(VelocityTracker::Strategy::IMPULSE, events, AMOTION_EVENT_AXIS_X,
                                  pointerId),
                  /*targetVelocity*/ std::nullopt);
    checkVelocity(computeVelocity(VelocityTracker::Strategy::IMPULSE, events, AMOTION_EVENT_AXIS_Y,
                                  pointerId),
                  /*targetVelocity*/ std::nullopt);
    checkVelocity(computeVelocity(VelocityTracker::Strategy::LSQ2, events, AMOTION_EVENT_AXIS_X,
                                  pointerId),
                  /*targetVelocity*/ std::nullopt);
    checkVelocity(computeVelocity(VelocityTracker::Strategy::LSQ2, events, AMOTION_EVENT_AXIS_Y,
                                  pointerId),
                  /*targetVelocity*/ std::nullopt);
}

/**
 * When the stream is terminated with ACTION_CANCEL, the resulting velocity should be 0.
 */
TEST_F(VelocityTrackerTest, ActionPointerCancelResultsInZeroVelocityForThatPointer) {
    std::vector<PlanarMotionEventEntry> motions = {
            {0ms, {{0, 5}, {NAN, NAN}}},    // DOWN
            {0ms, {{0, 5}, {10, 15}}},      // POINTER_DOWN
            {10ms, {{5, 10}, {15, 20}}},    // MOVE
            {20ms, {{10, 15}, {20, 25}}},   // MOVE
            {30ms, {{10, 15}, {20, 25}}},   // POINTER_UP
            {30ms, {{10, 15}, {NAN, NAN}}}, // UP
    };
    std::vector<MotionEvent> events = createTouchMotionEventStream(motions);
    // Cancel the lifting pointer of the ACTION_POINTER_UP event
    MotionEvent& pointerUpEvent = events.rbegin()[1];
    pointerUpEvent.setFlags(pointerUpEvent.getFlags() | AMOTION_EVENT_FLAG_CANCELED);
    const int32_t pointerId = pointerUpEvent.getPointerId(pointerUpEvent.getActionIndex());
    // Double check the stream
    ASSERT_EQ(1, pointerId);
    ASSERT_EQ(AMOTION_EVENT_ACTION_POINTER_UP, pointerUpEvent.getActionMasked());
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, events.back().getActionMasked());

    // Ensure the velocity of the lifting pointer is zero
    checkVelocity(computeVelocity(VelocityTracker::Strategy::IMPULSE, events, AMOTION_EVENT_AXIS_X,
                                  pointerId),
                  /*targetVelocity*/ std::nullopt);
    checkVelocity(computeVelocity(VelocityTracker::Strategy::IMPULSE, events, AMOTION_EVENT_AXIS_Y,
                                  pointerId),
                  /*targetVelocity*/ std::nullopt);
    checkVelocity(computeVelocity(VelocityTracker::Strategy::LSQ2, events, AMOTION_EVENT_AXIS_X,
                                  pointerId),
                  /*targetVelocity*/ std::nullopt);
    checkVelocity(computeVelocity(VelocityTracker::Strategy::LSQ2, events, AMOTION_EVENT_AXIS_Y,
                                  pointerId),
                  /*targetVelocity*/ std::nullopt);

    // The remaining pointer should have the correct velocity.
    const int32_t remainingPointerId = events.back().getPointerId(0);
    ASSERT_EQ(0, remainingPointerId);
    checkVelocity(computeVelocity(VelocityTracker::Strategy::IMPULSE, events, AMOTION_EVENT_AXIS_X,
                                  remainingPointerId),
                  /*targetVelocity*/ 500);
    checkVelocity(computeVelocity(VelocityTracker::Strategy::IMPULSE, events, AMOTION_EVENT_AXIS_Y,
                                  remainingPointerId),
                  /*targetVelocity*/ 500);
    checkVelocity(computeVelocity(VelocityTracker::Strategy::LSQ2, events, AMOTION_EVENT_AXIS_X,
                                  remainingPointerId),
                  /*targetVelocity*/ 500);
    checkVelocity(computeVelocity(VelocityTracker::Strategy::LSQ2, events, AMOTION_EVENT_AXIS_Y,
                                  remainingPointerId),
                  /*targetVelocity*/ 500);
}

/**
 * ================== VelocityTracker tests generated by recording real events =====================
 *
 * To add a test, record the input coordinates and event times to all calls
 * to void VelocityTracker::addMovement(const MotionEvent* event).
 * Also record all calls to VelocityTracker::clear().
 * Finally, record the output of VelocityTracker::getVelocity(...)
 * This will give you the necessary data to create a new test.
 *
 * Another good way to generate this data is to use 'dumpsys input' just after the event has
 * occurred.
 */

// --------------- Recorded by hand on swordfish ---------------------------------------------------
TEST_F(VelocityTrackerTest, SwordfishFlingDown) {
    // Recording of a fling on Swordfish that could cause a fling in the wrong direction
    std::vector<PlanarMotionEventEntry> motions = {
        { 0ms, {{271, 96}} },
        { 16071042ns, {{269.786346, 106.922775}} },
        { 35648403ns, {{267.983063, 156.660034}} },
        { 52313925ns, {{262.638397, 220.339081}} },
        { 68976522ns, {{266.138824, 331.581116}} },
        { 85639375ns, {{274.79245, 428.113159}} },
        { 96948871ns, {{274.79245, 428.113159}} },
        { 96948871ns, {{274.79245, 428.113159}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            623.577637);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            5970.7309);
}

// --------------- Recorded by hand on sailfish, generated by a script -----------------------------
// For some of these tests, the X-direction velocity checking has been removed, because the lsq2
// and the impulse VelocityTrackerStrategies did not agree within 20%.
// Since the flings were recorded in the Y-direction, the intentional user action should only
// be relevant for the Y axis.
// There have been also cases where lsq2 and impulse disagreed more than 20% in the Y-direction.
// Those recordings have been discarded because we didn't feel one strategy's interpretation was
// more correct than another's but didn't want to increase the tolerance for the entire test suite.
//
// There are 18 tests total below: 9 in the positive Y direction and 9 in the opposite.
// The recordings were loosely binned into 3 categories - slow, faster, and fast, which roughly
// characterizes the velocity of the finger motion.
// These can be treated approximately as:
// slow - less than 1 page gets scrolled
// faster - more than 1 page gets scrolled, but less than 3
// fast - entire list is scrolled (fling is done as hard as possible)

TEST_F(VelocityTrackerTest, SailfishFlingUpSlow1) {
    // Sailfish - fling up - slow - 1
    std::vector<PlanarMotionEventEntry> motions = {
        { 235089067457000ns, {{528.00, 983.00}} },
        { 235089084684000ns, {{527.00, 981.00}} },
        { 235089093349000ns, {{527.00, 977.00}} },
        { 235089095677625ns, {{527.00, 975.93}} },
        { 235089101859000ns, {{527.00, 970.00}} },
        { 235089110378000ns, {{528.00, 960.00}} },
        { 235089112497111ns, {{528.25, 957.51}} },
        { 235089118760000ns, {{531.00, 946.00}} },
        { 235089126686000ns, {{535.00, 931.00}} },
        { 235089129316820ns, {{536.33, 926.02}} },
        { 235089135199000ns, {{540.00, 914.00}} },
        { 235089144297000ns, {{546.00, 896.00}} },
        { 235089146136443ns, {{547.21, 892.36}} },
        { 235089152923000ns, {{553.00, 877.00}} },
        { 235089160784000ns, {{559.00, 851.00}} },
        { 235089162955851ns, {{560.66, 843.82}} },
        { 235089162955851ns, {{560.66, 843.82}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            764.345703);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            951.698181);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            -3604.819336);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            -3044.966064);
}


TEST_F(VelocityTrackerTest, SailfishFlingUpSlow2) {
    // Sailfish - fling up - slow - 2
    std::vector<PlanarMotionEventEntry> motions = {
        { 235110560704000ns, {{522.00, 1107.00}} },
        { 235110575764000ns, {{522.00, 1107.00}} },
        { 235110584385000ns, {{522.00, 1107.00}} },
        { 235110588421179ns, {{521.52, 1106.52}} },
        { 235110592830000ns, {{521.00, 1106.00}} },
        { 235110601385000ns, {{520.00, 1104.00}} },
        { 235110605088160ns, {{519.14, 1102.27}} },
        { 235110609952000ns, {{518.00, 1100.00}} },
        { 235110618353000ns, {{517.00, 1093.00}} },
        { 235110621755146ns, {{516.60, 1090.17}} },
        { 235110627010000ns, {{517.00, 1081.00}} },
        { 235110634785000ns, {{518.00, 1063.00}} },
        { 235110638422450ns, {{518.87, 1052.58}} },
        { 235110643161000ns, {{520.00, 1039.00}} },
        { 235110651767000ns, {{524.00, 1011.00}} },
        { 235110655089581ns, {{525.54, 1000.19}} },
        { 235110660368000ns, {{530.00, 980.00}} },
        { 235110660368000ns, {{530.00, 980.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            -4096.583008);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            -3455.094238);
}


TEST_F(VelocityTrackerTest, SailfishFlingUpSlow3) {
    // Sailfish - fling up - slow - 3
    std::vector<PlanarMotionEventEntry> motions = {
        { 792536237000ns, {{580.00, 1317.00}} },
        { 792541538987ns, {{580.63, 1311.94}} },
        { 792544613000ns, {{581.00, 1309.00}} },
        { 792552301000ns, {{583.00, 1295.00}} },
        { 792558362309ns, {{585.13, 1282.92}} },
        { 792560828000ns, {{586.00, 1278.00}} },
        { 792569446000ns, {{589.00, 1256.00}} },
        { 792575185095ns, {{591.54, 1241.41}} },
        { 792578491000ns, {{593.00, 1233.00}} },
        { 792587044000ns, {{597.00, 1211.00}} },
        { 792592008172ns, {{600.28, 1195.92}} },
        { 792594616000ns, {{602.00, 1188.00}} },
        { 792603129000ns, {{607.00, 1167.00}} },
        { 792608831290ns, {{609.48, 1155.83}} },
        { 792612321000ns, {{611.00, 1149.00}} },
        { 792620768000ns, {{615.00, 1131.00}} },
        { 792625653873ns, {{617.32, 1121.73}} },
        { 792629200000ns, {{619.00, 1115.00}} },
        { 792629200000ns, {{619.00, 1115.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            574.33429);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            617.40564);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            -2361.982666);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            -2500.055664);
}


TEST_F(VelocityTrackerTest, SailfishFlingUpFaster1) {
    // Sailfish - fling up - faster - 1
    std::vector<PlanarMotionEventEntry> motions = {
        { 235160420675000ns, {{610.00, 1042.00}} },
        { 235160428220000ns, {{609.00, 1026.00}} },
        { 235160436544000ns, {{609.00, 1024.00}} },
        { 235160441852394ns, {{609.64, 1020.82}} },
        { 235160444878000ns, {{610.00, 1019.00}} },
        { 235160452673000ns, {{613.00, 1006.00}} },
        { 235160458519743ns, {{617.18, 992.06}} },
        { 235160461061000ns, {{619.00, 986.00}} },
        { 235160469798000ns, {{627.00, 960.00}} },
        { 235160475186713ns, {{632.22, 943.02}} },
        { 235160478051000ns, {{635.00, 934.00}} },
        { 235160486489000ns, {{644.00, 906.00}} },
        { 235160491853697ns, {{649.56, 890.56}} },
        { 235160495177000ns, {{653.00, 881.00}} },
        { 235160504148000ns, {{662.00, 858.00}} },
        { 235160509231495ns, {{666.81, 845.37}} },
        { 235160512603000ns, {{670.00, 837.00}} },
        { 235160520366000ns, {{679.00, 814.00}} },
        { 235160520366000ns, {{679.00, 814.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            1274.141724);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            1438.53186);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            -3001.4348);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            -3695.859619);
}


TEST_F(VelocityTrackerTest, SailfishFlingUpFaster2) {
    // Sailfish - fling up - faster - 2
    std::vector<PlanarMotionEventEntry> motions = {
        { 847153808000ns, {{576.00, 1264.00}} },
        { 847171174000ns, {{576.00, 1262.00}} },
        { 847179640000ns, {{576.00, 1257.00}} },
        { 847185187540ns, {{577.41, 1249.22}} },
        { 847187487000ns, {{578.00, 1246.00}} },
        { 847195710000ns, {{581.00, 1227.00}} },
        { 847202027059ns, {{583.93, 1209.40}} },
        { 847204324000ns, {{585.00, 1203.00}} },
        { 847212672000ns, {{590.00, 1176.00}} },
        { 847218861395ns, {{594.36, 1157.11}} },
        { 847221190000ns, {{596.00, 1150.00}} },
        { 847230484000ns, {{602.00, 1124.00}} },
        { 847235701400ns, {{607.56, 1103.83}} },
        { 847237986000ns, {{610.00, 1095.00}} },
        { 847237986000ns, {{610.00, 1095.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            -4280.07959);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            -4241.004395);
}


TEST_F(VelocityTrackerTest, SailfishFlingUpFaster3) {
    // Sailfish - fling up - faster - 3
    std::vector<PlanarMotionEventEntry> motions = {
        { 235200532789000ns, {{507.00, 1084.00}} },
        { 235200549221000ns, {{507.00, 1083.00}} },
        { 235200557841000ns, {{507.00, 1081.00}} },
        { 235200558051189ns, {{507.00, 1080.95}} },
        { 235200566314000ns, {{507.00, 1078.00}} },
        { 235200574876586ns, {{508.97, 1070.12}} },
        { 235200575006000ns, {{509.00, 1070.00}} },
        { 235200582900000ns, {{514.00, 1054.00}} },
        { 235200591276000ns, {{525.00, 1023.00}} },
        { 235200591701829ns, {{525.56, 1021.42}} },
        { 235200600064000ns, {{542.00, 976.00}} },
        { 235200608519000ns, {{563.00, 911.00}} },
        { 235200608527086ns, {{563.02, 910.94}} },
        { 235200616933000ns, {{590.00, 844.00}} },
        { 235200616933000ns, {{590.00, 844.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            -8715.686523);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            -7639.026367);
}


TEST_F(VelocityTrackerTest, SailfishFlingUpFast1) {
    // Sailfish - fling up - fast - 1
    std::vector<PlanarMotionEventEntry> motions = {
        { 920922149000ns, {{561.00, 1412.00}} },
        { 920930185000ns, {{559.00, 1377.00}} },
        { 920930262463ns, {{558.98, 1376.66}} },
        { 920938547000ns, {{559.00, 1371.00}} },
        { 920947096857ns, {{562.91, 1342.68}} },
        { 920947302000ns, {{563.00, 1342.00}} },
        { 920955502000ns, {{577.00, 1272.00}} },
        { 920963931021ns, {{596.87, 1190.54}} },
        { 920963987000ns, {{597.00, 1190.00}} },
        { 920972530000ns, {{631.00, 1093.00}} },
        { 920980765511ns, {{671.31, 994.68}} },
        { 920980906000ns, {{672.00, 993.00}} },
        { 920989261000ns, {{715.00, 903.00}} },
        { 920989261000ns, {{715.00, 903.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            5670.329102);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            5991.866699);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            -13021.101562);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            -15093.995117);
}


TEST_F(VelocityTrackerTest, SailfishFlingUpFast2) {
    // Sailfish - fling up - fast - 2
    std::vector<PlanarMotionEventEntry> motions = {
        { 235247153233000ns, {{518.00, 1168.00}} },
        { 235247170452000ns, {{517.00, 1167.00}} },
        { 235247178908000ns, {{515.00, 1159.00}} },
        { 235247179556213ns, {{514.85, 1158.39}} },
        { 235247186821000ns, {{515.00, 1125.00}} },
        { 235247195265000ns, {{521.00, 1051.00}} },
        { 235247196389476ns, {{521.80, 1041.15}} },
        { 235247203649000ns, {{538.00, 932.00}} },
        { 235247212253000ns, {{571.00, 794.00}} },
        { 235247213222491ns, {{574.72, 778.45}} },
        { 235247220736000ns, {{620.00, 641.00}} },
        { 235247220736000ns, {{620.00, 641.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            -20286.958984);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            -20494.587891);
}


TEST_F(VelocityTrackerTest, SailfishFlingUpFast3) {
    // Sailfish - fling up - fast - 3
    std::vector<PlanarMotionEventEntry> motions = {
        { 235302568736000ns, {{529.00, 1167.00}} },
        { 235302576644000ns, {{523.00, 1140.00}} },
        { 235302579395063ns, {{520.91, 1130.61}} },
        { 235302585140000ns, {{522.00, 1130.00}} },
        { 235302593615000ns, {{527.00, 1065.00}} },
        { 235302596207444ns, {{528.53, 1045.12}} },
        { 235302602102000ns, {{559.00, 872.00}} },
        { 235302610545000ns, {{652.00, 605.00}} },
        { 235302613019881ns, {{679.26, 526.73}} },
        { 235302613019881ns, {{679.26, 526.73}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            -39295.941406);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            -36461.421875);
}


TEST_F(VelocityTrackerTest, SailfishFlingDownSlow1) {
    // Sailfish - fling down - slow - 1
    std::vector<PlanarMotionEventEntry> motions = {
        { 235655749552755ns, {{582.00, 432.49}} },
        { 235655750638000ns, {{582.00, 433.00}} },
        { 235655758865000ns, {{582.00, 440.00}} },
        { 235655766221523ns, {{581.16, 448.43}} },
        { 235655767594000ns, {{581.00, 450.00}} },
        { 235655776044000ns, {{580.00, 462.00}} },
        { 235655782890696ns, {{579.18, 474.35}} },
        { 235655784360000ns, {{579.00, 477.00}} },
        { 235655792795000ns, {{578.00, 496.00}} },
        { 235655799559531ns, {{576.27, 515.04}} },
        { 235655800612000ns, {{576.00, 518.00}} },
        { 235655809535000ns, {{574.00, 542.00}} },
        { 235655816988015ns, {{572.17, 564.86}} },
        { 235655817685000ns, {{572.00, 567.00}} },
        { 235655825981000ns, {{569.00, 595.00}} },
        { 235655833808653ns, {{566.26, 620.60}} },
        { 235655834541000ns, {{566.00, 623.00}} },
        { 235655842893000ns, {{563.00, 649.00}} },
        { 235655842893000ns, {{563.00, 649.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            -419.749695);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            -398.303894);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            3309.016357);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            3969.099854);
}


TEST_F(VelocityTrackerTest, SailfishFlingDownSlow2) {
    // Sailfish - fling down - slow - 2
    std::vector<PlanarMotionEventEntry> motions = {
        { 235671152083370ns, {{485.24, 558.28}} },
        { 235671154126000ns, {{485.00, 559.00}} },
        { 235671162497000ns, {{484.00, 566.00}} },
        { 235671168750511ns, {{483.27, 573.29}} },
        { 235671171071000ns, {{483.00, 576.00}} },
        { 235671179390000ns, {{482.00, 588.00}} },
        { 235671185417210ns, {{481.31, 598.98}} },
        { 235671188173000ns, {{481.00, 604.00}} },
        { 235671196371000ns, {{480.00, 624.00}} },
        { 235671202084196ns, {{479.27, 639.98}} },
        { 235671204235000ns, {{479.00, 646.00}} },
        { 235671212554000ns, {{478.00, 673.00}} },
        { 235671219471011ns, {{476.39, 697.12}} },
        { 235671221159000ns, {{476.00, 703.00}} },
        { 235671229592000ns, {{474.00, 734.00}} },
        { 235671236281462ns, {{472.43, 758.38}} },
        { 235671238098000ns, {{472.00, 765.00}} },
        { 235671246532000ns, {{470.00, 799.00}} },
        { 235671246532000ns, {{470.00, 799.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            -262.80426);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            -243.665344);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            4215.682129);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            4587.986816);
}


TEST_F(VelocityTrackerTest, SailfishFlingDownSlow3) {
    // Sailfish - fling down - slow - 3
    std::vector<PlanarMotionEventEntry> motions = {
        { 170983201000ns, {{557.00, 533.00}} },
        { 171000668000ns, {{556.00, 534.00}} },
        { 171007359750ns, {{554.73, 535.27}} },
        { 171011197000ns, {{554.00, 536.00}} },
        { 171017660000ns, {{552.00, 540.00}} },
        { 171024201831ns, {{549.97, 544.73}} },
        { 171027333000ns, {{549.00, 547.00}} },
        { 171034603000ns, {{545.00, 557.00}} },
        { 171041043371ns, {{541.98, 567.55}} },
        { 171043147000ns, {{541.00, 571.00}} },
        { 171051052000ns, {{536.00, 586.00}} },
        { 171051052000ns, {{536.00, 586.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            -723.413513);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            -651.038452);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            2091.502441);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            1934.517456);
}


TEST_F(VelocityTrackerTest, SailfishFlingDownFaster1) {
    // Sailfish - fling down - faster - 1
    std::vector<PlanarMotionEventEntry> motions = {
        { 235695280333000ns, {{558.00, 451.00}} },
        { 235695283971237ns, {{558.43, 454.45}} },
        { 235695289038000ns, {{559.00, 462.00}} },
        { 235695297388000ns, {{561.00, 478.00}} },
        { 235695300638465ns, {{561.83, 486.25}} },
        { 235695305265000ns, {{563.00, 498.00}} },
        { 235695313591000ns, {{564.00, 521.00}} },
        { 235695317305492ns, {{564.43, 532.68}} },
        { 235695322181000ns, {{565.00, 548.00}} },
        { 235695330709000ns, {{565.00, 577.00}} },
        { 235695333972227ns, {{565.00, 588.10}} },
        { 235695339250000ns, {{565.00, 609.00}} },
        { 235695347839000ns, {{565.00, 642.00}} },
        { 235695351313257ns, {{565.00, 656.18}} },
        { 235695356412000ns, {{565.00, 677.00}} },
        { 235695364899000ns, {{563.00, 710.00}} },
        { 235695368118682ns, {{562.24, 722.52}} },
        { 235695373403000ns, {{564.00, 744.00}} },
        { 235695373403000ns, {{564.00, 744.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            4254.639648);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            4698.415039);
}


TEST_F(VelocityTrackerTest, SailfishFlingDownFaster2) {
    // Sailfish - fling down - faster - 2
    std::vector<PlanarMotionEventEntry> motions = {
        { 235709624766000ns, {{535.00, 579.00}} },
        { 235709642256000ns, {{534.00, 580.00}} },
        { 235709643350278ns, {{533.94, 580.06}} },
        { 235709650760000ns, {{532.00, 584.00}} },
        { 235709658615000ns, {{530.00, 593.00}} },
        { 235709660170495ns, {{529.60, 594.78}} },
        { 235709667095000ns, {{527.00, 606.00}} },
        { 235709675616000ns, {{524.00, 628.00}} },
        { 235709676983261ns, {{523.52, 631.53}} },
        { 235709684289000ns, {{521.00, 652.00}} },
        { 235709692763000ns, {{518.00, 682.00}} },
        { 235709693804993ns, {{517.63, 685.69}} },
        { 235709701438000ns, {{515.00, 709.00}} },
        { 235709709830000ns, {{512.00, 739.00}} },
        { 235709710626776ns, {{511.72, 741.85}} },
        { 235709710626776ns, {{511.72, 741.85}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            -430.440247);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            -447.600311);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            3953.859375);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            4316.155273);
}


TEST_F(VelocityTrackerTest, SailfishFlingDownFaster3) {
    // Sailfish - fling down - faster - 3
    std::vector<PlanarMotionEventEntry> motions = {
        { 235727628927000ns, {{540.00, 440.00}} },
        { 235727636810000ns, {{537.00, 454.00}} },
        { 235727646176000ns, {{536.00, 454.00}} },
        { 235727653586628ns, {{535.12, 456.65}} },
        { 235727654557000ns, {{535.00, 457.00}} },
        { 235727663024000ns, {{534.00, 465.00}} },
        { 235727670410103ns, {{533.04, 479.45}} },
        { 235727670691000ns, {{533.00, 480.00}} },
        { 235727679255000ns, {{531.00, 501.00}} },
        { 235727687233704ns, {{529.09, 526.73}} },
        { 235727687628000ns, {{529.00, 528.00}} },
        { 235727696113000ns, {{526.00, 558.00}} },
        { 235727704057546ns, {{523.18, 588.98}} },
        { 235727704576000ns, {{523.00, 591.00}} },
        { 235727713099000ns, {{520.00, 626.00}} },
        { 235727720880776ns, {{516.33, 655.36}} },
        { 235727721580000ns, {{516.00, 658.00}} },
        { 235727721580000ns, {{516.00, 658.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            4484.617676);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            4927.92627);
}


TEST_F(VelocityTrackerTest, SailfishFlingDownFast1) {
    // Sailfish - fling down - fast - 1
    std::vector<PlanarMotionEventEntry> motions = {
        { 235762352849000ns, {{467.00, 286.00}} },
        { 235762360250000ns, {{443.00, 344.00}} },
        { 235762362787412ns, {{434.77, 363.89}} },
        { 235762368807000ns, {{438.00, 359.00}} },
        { 235762377220000ns, {{425.00, 423.00}} },
        { 235762379608561ns, {{421.31, 441.17}} },
        { 235762385698000ns, {{412.00, 528.00}} },
        { 235762394133000ns, {{406.00, 648.00}} },
        { 235762396429369ns, {{404.37, 680.67}} },
        { 235762396429369ns, {{404.37, 680.67}} }, //ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            14227.0224);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            16064.685547);
}


TEST_F(VelocityTrackerTest, SailfishFlingDownFast2) {
    // Sailfish - fling down - fast - 2
    std::vector<PlanarMotionEventEntry> motions = {
        { 235772487188000ns, {{576.00, 204.00}} },
        { 235772495159000ns, {{553.00, 236.00}} },
        { 235772503568000ns, {{551.00, 240.00}} },
        { 235772508192247ns, {{545.55, 254.17}} },
        { 235772512051000ns, {{541.00, 266.00}} },
        { 235772520794000ns, {{520.00, 337.00}} },
        { 235772525015263ns, {{508.92, 394.43}} },
        { 235772529174000ns, {{498.00, 451.00}} },
        { 235772537635000ns, {{484.00, 589.00}} },
        { 235772537635000ns, {{484.00, 589.00}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            18660.048828);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            16918.439453);
}


TEST_F(VelocityTrackerTest, SailfishFlingDownFast3) {
    // Sailfish - fling down - fast - 3
    std::vector<PlanarMotionEventEntry> motions = {
        { 507650295000ns, {{628.00, 233.00}} },
        { 507658234000ns, {{605.00, 269.00}} },
        { 507666784000ns, {{601.00, 274.00}} },
        { 507669660483ns, {{599.65, 275.68}} },
        { 507675427000ns, {{582.00, 308.00}} },
        { 507683740000ns, {{541.00, 404.00}} },
        { 507686506238ns, {{527.36, 435.95}} },
        { 507692220000ns, {{487.00, 581.00}} },
        { 507700707000ns, {{454.00, 792.00}} },
        { 507703352649ns, {{443.71, 857.77}} },
        { 507703352649ns, {{443.71, 857.77}} }, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            -4111.8173);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            -6388.48877);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            29765.908203);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            28354.796875);
}

/**
 * ================== Multiple pointers ============================================================
 *
 * Three fingers quickly tap the screen. Since this is a tap, the velocities should be empty.
 * If the events with POINTER_UP or POINTER_DOWN are not handled correctly (these should not be
 * part of the fitted data), this can cause large velocity values to be reported instead.
 */
TEST_F(VelocityTrackerTest, LeastSquaresVelocityTrackerStrategy_ThreeFingerTap) {
    std::vector<PlanarMotionEventEntry> motions = {
        { 0us,      {{1063, 1128}, {NAN, NAN}, {NAN, NAN}} },
        { 10800us,  {{1063, 1128}, {682, 1318}, {NAN, NAN}} }, // POINTER_DOWN
        { 10800us,  {{1063, 1128}, {682, 1318}, {397, 1747}} }, // POINTER_DOWN
        { 267300us, {{1063, 1128}, {682, 1318}, {397, 1747}} }, // POINTER_UP
        { 267300us, {{1063, 1128}, {NAN, NAN}, {397, 1747}} }, // POINTER_UP
        { 272700us, {{1063, 1128}, {NAN, NAN}, {NAN, NAN}} },
    };

    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            std::nullopt);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_Y,
                            std::nullopt);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            std::nullopt);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_Y,
                            std::nullopt);
}

/**
 * ================= Pointer liftoff ===============================================================
 */

/**
 * The last movement of a pointer is always ACTION_POINTER_UP or ACTION_UP. If there's a short delay
 * between the last ACTION_MOVE and the next ACTION_POINTER_UP or ACTION_UP, velocity should not be
 * affected by the liftoff.
 */
TEST_F(VelocityTrackerTest, ShortDelayBeforeActionUp) {
    std::vector<PlanarMotionEventEntry> motions = {
            {0ms, {{10, 0}}}, {10ms, {{20, 0}}}, {20ms, {{30, 0}}}, {30ms, {{30, 0}}}, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            1000);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X, 1000);
}

/**
 * The last movement of a single pointer is ACTION_UP. If there's a long delay between the last
 * ACTION_MOVE and the final ACTION_UP, velocity should be reported as empty because the pointer
 * should be assumed to have stopped.
 */
TEST_F(VelocityTrackerTest, LongDelayBeforeActionUp) {
    std::vector<PlanarMotionEventEntry> motions = {
            {0ms, {{10, 0}}},
            {10ms, {{20, 0}}},
            {20ms, {{30, 0}}},
            {3000ms, {{30, 0}}}, // ACTION_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            std::nullopt);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            std::nullopt);
}

/**
 * The last movement of a pointer is always ACTION_POINTER_UP or ACTION_UP. If there's a long delay
 * before ACTION_POINTER_UP event, the movement should be assumed to have stopped.
 * The final velocity should be reported as empty for all pointers.
 */
TEST_F(VelocityTrackerTest, LongDelayBeforeActionPointerUp) {
    std::vector<PlanarMotionEventEntry> motions = {
            {0ms, {{10, 0}}},
            {10ms, {{20, 0}, {100, 0}}},
            {20ms, {{30, 0}, {200, 0}}},
            {30ms, {{30, 0}, {300, 0}}},
            {40ms, {{30, 0}, {400, 0}}},
            {3000ms, {{30, 0}}}, // ACTION_POINTER_UP
    };
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            std::nullopt,
                            /*pointerId*/ 0);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            std::nullopt,
                            /*pointerId*/ 0);
    computeAndCheckVelocity(VelocityTracker::Strategy::IMPULSE, motions, AMOTION_EVENT_AXIS_X,
                            std::nullopt,
                            /*pointerId*/ 1);
    computeAndCheckVelocity(VelocityTracker::Strategy::LSQ2, motions, AMOTION_EVENT_AXIS_X,
                            std::nullopt,
                            /*pointerId*/ 1);
}

/**
 * ================== Tests for least squares fitting ==============================================
 *
 * Special care must be taken when constructing tests for LeastSquaresVelocityTrackerStrategy
 * getVelocity function. In particular:
 * - inside the function, time gets converted from nanoseconds to seconds
 *   before being used in the fit.
 * - any values that are older than 100 ms are being discarded.
 * - the newest time gets subtracted from all of the other times before being used in the fit.
 * So these tests have to be designed with those limitations in mind.
 *
 * General approach for the tests below:
 * We only used timestamps in milliseconds, 0 ms, 1 ms, and 2 ms, to be sure that
 * we are well within the HORIZON range.
 * When specifying the expected values of the coefficients, we treat the x values as if
 * they were in ms. Then, to adjust for the time units, the coefficients get progressively
 * multiplied by powers of 1E3.
 * For example:
 * data: t(ms), x
 *        1 ms, 1
 *        2 ms, 4
 *        3 ms, 9
 * The coefficients are (0, 0, 1).
 * In the test, we would convert these coefficients to (0*(1E3)^0, 0*(1E3)^1, 1*(1E3)^2).
 */
TEST_F(VelocityTrackerTest, LeastSquaresVelocityTrackerStrategy_Constant) {
    std::vector<PlanarMotionEventEntry> motions = {
        { 0ms, {{1, 1}} }, // 0 s
        { 1ms, {{1, 1}} }, // 0.001 s
        { 2ms, {{1, 1}} }, // 0.002 s
        { 2ms, {{1, 1}} }, // ACTION_UP
    };
    // The data used for the fit will be as follows:
    // time(s), position
    // -0.002, 1
    // -0.001, 1
    // -0.ms, 1
    computeAndCheckQuadraticVelocity(motions, 0);
}

/*
 * Straight line y = x :: the constant and quadratic coefficients are zero.
 */
TEST_F(VelocityTrackerTest, LeastSquaresVelocityTrackerStrategy_Linear) {
    std::vector<PlanarMotionEventEntry> motions = {
        { 0ms, {{-2, -2}} },
        { 1ms, {{-1, -1}} },
        { 2ms, {{-0, -0}} },
        { 2ms, {{-0, -0}} }, // ACTION_UP
    };
    // The data used for the fit will be as follows:
    // time(s), position
    // -0.002, -2
    // -0.001, -1
    // -0.000,  0
    computeAndCheckQuadraticVelocity(motions, 1E3);
}

/*
 * Parabola
 */
TEST_F(VelocityTrackerTest, LeastSquaresVelocityTrackerStrategy_Parabolic) {
    std::vector<PlanarMotionEventEntry> motions = {
        { 0ms, {{1, 1}} },
        { 1ms, {{4, 4}} },
        { 2ms, {{8, 8}} },
        { 2ms, {{8, 8}} }, // ACTION_UP
    };
    // The data used for the fit will be as follows:
    // time(s), position
    // -0.002, 1
    // -0.001, 4
    // -0.000, 8
    computeAndCheckQuadraticVelocity(motions, 4.5E3);
}

/*
 * Parabola
 */
TEST_F(VelocityTrackerTest, LeastSquaresVelocityTrackerStrategy_Parabolic2) {
    std::vector<PlanarMotionEventEntry> motions = {
        { 0ms, {{1, 1}} },
        { 1ms, {{4, 4}} },
        { 2ms, {{9, 9}} },
        { 2ms, {{9, 9}} }, // ACTION_UP
    };
    // The data used for the fit will be as follows:
    // time(s), position
    // -0.002, 1
    // -0.001, 4
    // -0.000, 9
    computeAndCheckQuadraticVelocity(motions, 6E3);
}

/*
 * Parabola :: y = x^2 :: the constant and linear coefficients are zero.
 */
TEST_F(VelocityTrackerTest, LeastSquaresVelocityTrackerStrategy_Parabolic3) {
    std::vector<PlanarMotionEventEntry> motions = {
        { 0ms, {{4, 4}} },
        { 1ms, {{1, 1}} },
        { 2ms, {{0, 0}} },
        { 2ms, {{0, 0}} }, // ACTION_UP
    };
    // The data used for the fit will be as follows:
    // time(s), position
    // -0.002, 4
    // -0.001, 1
    // -0.000, 0
    computeAndCheckQuadraticVelocity(motions, 0E3);
}

// Recorded by hand on sailfish, but only the diffs are taken to test cumulative axis velocity.
TEST_F(VelocityTrackerTest, AxisScrollVelocity) {
    std::vector<std::pair<std::chrono::nanoseconds, float>> motions = {
            {235089067457000ns, 0.00}, {235089084684000ns, -1.00}, {235089093349000ns, 0.00},
            {235089095677625ns, 0.00}, {235089101859000ns, 0.00},  {235089110378000ns, 0.00},
            {235089112497111ns, 0.25}, {235089118760000ns, 1.75},  {235089126686000ns, 4.00},
            {235089129316820ns, 1.33}, {235089135199000ns, 3.67},  {235089144297000ns, 6.00},
            {235089146136443ns, 1.21}, {235089152923000ns, 5.79},  {235089160784000ns, 6.00},
            {235089162955851ns, 1.66},
    };

    computeAndCheckAxisScrollVelocity(VelocityTracker::Strategy::IMPULSE, motions, {764.345703});
}

// --------------- Recorded by hand on a Wear OS device using a rotating side button ---------------
TEST_F(VelocityTrackerTest, AxisScrollVelocity_ScrollDown) {
    std::vector<std::pair<std::chrono::nanoseconds, float>> motions = {
            {224598065152ns, -0.050100}, {224621871104ns, -0.133600}, {224645464064ns, -0.551100},
            {224669171712ns, -0.801600}, {224687063040ns, -1.035400}, {224706691072ns, -0.484300},
            {224738213888ns, -0.334000}, {224754401280ns, -0.083500},
    };

    computeAndCheckAxisScrollVelocity(VelocityTracker::Strategy::IMPULSE, motions, {-27.86});
}

TEST_F(VelocityTrackerTest, AxisScrollVelocity_ScrollUp) {
    std::vector<std::pair<std::chrono::nanoseconds, float>> motions = {
            {269606010880ns, 0.050100}, {269626064896ns, 0.217100}, {269641973760ns, 0.267200},
            {269658079232ns, 0.267200}, {269674217472ns, 0.267200}, {269690683392ns, 0.367400},
            {269706133504ns, 0.551100}, {269722173440ns, 0.501000},
    };

    computeAndCheckAxisScrollVelocity(VelocityTracker::Strategy::IMPULSE, motions, {31.92});
}

TEST_F(VelocityTrackerTest, AxisScrollVelocity_ScrollDown_ThenUp_ThenDown) {
    std::vector<std::pair<std::chrono::nanoseconds, float>> motions = {
            {2580534001664ns, -0.033400}, {2580549992448ns, -0.133600},
            {2580566769664ns, -0.250500}, {2580581974016ns, -0.183700},
            {2580597964800ns, -0.267200}, {2580613955584ns, -0.551100},
            {2580635189248ns, -0.601200}, {2580661927936ns, -0.450900},
            {2580683161600ns, -0.417500}, {2580705705984ns, -0.150300},
            {2580722745344ns, -0.016700}, {2580786446336ns, 0.050100},
            {2580801912832ns, 0.150300},  {2580822360064ns, 0.300600},
            {2580838088704ns, 0.300600},  {2580854341632ns, 0.400800},
            {2580869808128ns, 0.517700},  {2580886061056ns, 0.501000},
            {2580905984000ns, 0.350700},  {2580921974784ns, 0.350700},
            {2580937965568ns, 0.066800},  {2580974665728ns, 0.016700},
            {2581034434560ns, -0.066800}, {2581049901056ns, -0.116900},
            {2581070610432ns, -0.317300}, {2581086076928ns, -0.200400},
            {2581101805568ns, -0.233800}, {2581118058496ns, -0.417500},
            {2581134049280ns, -0.417500}, {2581150040064ns, -0.367400},
            {2581166030848ns, -0.267200}, {2581181759488ns, -0.150300},
            {2581199847424ns, -0.066800},
    };

    computeAndCheckAxisScrollVelocity(VelocityTracker::Strategy::IMPULSE, motions, {-9.73});
}

// ------------------------------- Hand generated test cases ---------------------------------------
TEST_F(VelocityTrackerTest, TestDefaultStrategyForAxisScroll) {
    std::vector<std::pair<std::chrono::nanoseconds, float>> motions = {
            {10ms, 20},
            {20ms, 25},
            {30ms, 50},
            {40ms, 100},
    };

    std::vector<MotionEvent> events = createAxisScrollMotionEventStream(motions);
    EXPECT_EQ(computeVelocity(VelocityTracker::Strategy::IMPULSE, events,
                              AMOTION_EVENT_AXIS_SCROLL),
              computeVelocity(VelocityTracker::Strategy::DEFAULT, events,
                              AMOTION_EVENT_AXIS_SCROLL));
}

TEST_F(VelocityTrackerTest, AxisScrollVelocity_SimilarDifferentialValues) {
    std::vector<std::pair<std::chrono::nanoseconds, float>> motions = {{1ns, 2.12},  {3ns, 2.12},
                                                                       {7ns, 2.12},  {8ns, 2.12},
                                                                       {15ns, 2.12}, {18ns, 2.12}};

    computeAndCheckAxisScrollVelocity(VelocityTracker::Strategy::IMPULSE, motions, {1690236059.86});
}

TEST_F(VelocityTrackerTest, AxisScrollVelocity_OnlyTwoValues) {
    std::vector<std::pair<std::chrono::nanoseconds, float>> motions = {{1ms, 5}, {2ms, 10}};

    computeAndCheckAxisScrollVelocity(VelocityTracker::Strategy::IMPULSE, motions, {10000});
}

TEST_F(VelocityTrackerTest, AxisScrollVelocity_ConstantVelocity) {
    std::vector<std::pair<std::chrono::nanoseconds, float>> motions = {{1ms, 20}, {2ms, 20},
                                                                       {3ms, 20}, {4ms, 20},
                                                                       {5ms, 20}, {6ms, 20}};

    computeAndCheckAxisScrollVelocity(VelocityTracker::Strategy::IMPULSE, motions, {20000});
}

TEST_F(VelocityTrackerTest, AxisScrollVelocity_NoMotion) {
    std::vector<std::pair<std::chrono::nanoseconds, float>> motions = {{1ns, 0}, {2ns, 0},
                                                                       {3ns, 0}, {4ns, 0},
                                                                       {5ns, 0}, {6ns, 0}};

    computeAndCheckAxisScrollVelocity(VelocityTracker::Strategy::IMPULSE, motions, {0});
}

TEST_F(VelocityTrackerTest, AxisScrollVelocity_NoData) {
    std::vector<std::pair<std::chrono::nanoseconds, float>> motions = {};

    computeAndCheckAxisScrollVelocity(VelocityTracker::Strategy::IMPULSE, motions, std::nullopt);
}

} // namespace android
