/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <cinttypes>
#include <memory>
#include <optional>

#include <CursorInputMapper.h>
#include <InputDevice.h>
#include <InputMapper.h>
#include <InputReader.h>
#include <InputReaderBase.h>
#include <InputReaderFactory.h>
#include <JoystickInputMapper.h>
#include <KeyboardInputMapper.h>
#include <MultiTouchInputMapper.h>
#include <PeripheralController.h>
#include <SensorInputMapper.h>
#include <SingleTouchInputMapper.h>
#include <SwitchInputMapper.h>
#include <TestEventMatchers.h>
#include <TestInputListener.h>
#include <TouchInputMapper.h>
#include <UinputDevice.h>
#include <VibratorInputMapper.h>
#include <android-base/thread_annotations.h>
#include <com_android_input_flags.h>
#include <ftl/enum.h>
#include <gtest/gtest.h>
#include <gui/constants.h>
#include <ui/Rotation.h>

#include <thread>
#include "FakeEventHub.h"
#include "FakeInputReaderPolicy.h"
#include "FakePointerController.h"
#include "InputMapperTest.h"
#include "InstrumentedInputReader.h"
#include "TestConstants.h"
#include "input/DisplayViewport.h"
#include "input/Input.h"

namespace android {

using namespace ftl::flag_operators;
using testing::AllOf;
using std::chrono_literals::operator""ms;
using std::chrono_literals::operator""s;

// Arbitrary display properties.
static constexpr int32_t DISPLAY_ID = 0;
static const std::string DISPLAY_UNIQUE_ID = "local:1";
static constexpr int32_t SECONDARY_DISPLAY_ID = DISPLAY_ID + 1;
static const std::string SECONDARY_DISPLAY_UNIQUE_ID = "local:2";
static constexpr int32_t DISPLAY_WIDTH = 480;
static constexpr int32_t DISPLAY_HEIGHT = 800;
static constexpr int32_t VIRTUAL_DISPLAY_ID = 1;
static constexpr int32_t VIRTUAL_DISPLAY_WIDTH = 400;
static constexpr int32_t VIRTUAL_DISPLAY_HEIGHT = 500;
static const char* VIRTUAL_DISPLAY_UNIQUE_ID = "virtual:1";
static constexpr std::optional<uint8_t> NO_PORT = std::nullopt; // no physical port is specified

static constexpr int32_t FIRST_SLOT = 0;
static constexpr int32_t SECOND_SLOT = 1;
static constexpr int32_t THIRD_SLOT = 2;
static constexpr int32_t INVALID_TRACKING_ID = -1;
static constexpr int32_t FIRST_TRACKING_ID = 0;
static constexpr int32_t SECOND_TRACKING_ID = 1;
static constexpr int32_t THIRD_TRACKING_ID = 2;
static constexpr int32_t LIGHT_BRIGHTNESS = 0x55000000;
static constexpr int32_t LIGHT_COLOR = 0x7F448866;
static constexpr int32_t LIGHT_PLAYER_ID = 2;

static constexpr int32_t ACTION_POINTER_0_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (0 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t ACTION_POINTER_0_UP =
        AMOTION_EVENT_ACTION_POINTER_UP | (0 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t ACTION_POINTER_1_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t ACTION_POINTER_1_UP =
        AMOTION_EVENT_ACTION_POINTER_UP | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);

static constexpr uint32_t STYLUS_FUSION_SOURCE =
        AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_BLUETOOTH_STYLUS;

// Minimum timestamp separation between subsequent input events from a Bluetooth device.
static constexpr nsecs_t MIN_BLUETOOTH_TIMESTAMP_DELTA = ms2ns(4);

namespace input_flags = com::android::input::flags;

template<typename T>
static inline T min(T a, T b) {
    return a < b ? a : b;
}

static inline float avg(float x, float y) {
    return (x + y) / 2;
}

// Mapping for light color name and the light color
const std::unordered_map<std::string, LightColor> LIGHT_COLORS = {{"red", LightColor::RED},
                                                                  {"green", LightColor::GREEN},
                                                                  {"blue", LightColor::BLUE}};

static ui::Rotation getInverseRotation(ui::Rotation orientation) {
    switch (orientation) {
        case ui::ROTATION_90:
            return ui::ROTATION_270;
        case ui::ROTATION_270:
            return ui::ROTATION_90;
        default:
            return orientation;
    }
}

static void assertAxisResolution(MultiTouchInputMapper& mapper, int axis, float resolution) {
    InputDeviceInfo info;
    mapper.populateDeviceInfo(info);

    const InputDeviceInfo::MotionRange* motionRange =
            info.getMotionRange(axis, AINPUT_SOURCE_TOUCHSCREEN);
    ASSERT_NEAR(motionRange->resolution, resolution, EPSILON);
}

static void assertAxisNotPresent(MultiTouchInputMapper& mapper, int axis) {
    InputDeviceInfo info;
    mapper.populateDeviceInfo(info);

    const InputDeviceInfo::MotionRange* motionRange =
            info.getMotionRange(axis, AINPUT_SOURCE_TOUCHSCREEN);
    ASSERT_EQ(nullptr, motionRange);
}

[[maybe_unused]] static void dumpReader(InputReader& reader) {
    std::string dump;
    reader.dump(dump);
    std::istringstream iss(dump);
    for (std::string line; std::getline(iss, line);) {
        ALOGE("%s", line.c_str());
        std::this_thread::sleep_for(1ms);
    }
}

// --- FakeInputMapper ---

class FakeInputMapper : public InputMapper {
    uint32_t mSources;
    int32_t mKeyboardType;
    int32_t mMetaState;
    KeyedVector<int32_t, int32_t> mKeyCodeStates;
    KeyedVector<int32_t, int32_t> mScanCodeStates;
    KeyedVector<int32_t, int32_t> mSwitchStates;
    // fake mapping which would normally come from keyCharacterMap
    std::unordered_map<int32_t, int32_t> mKeyCodeMapping;
    std::vector<int32_t> mSupportedKeyCodes;
    std::list<NotifyArgs> mProcessResult;

    std::mutex mLock;
    std::condition_variable mStateChangedCondition;
    bool mConfigureWasCalled GUARDED_BY(mLock);
    bool mResetWasCalled GUARDED_BY(mLock);
    bool mProcessWasCalled GUARDED_BY(mLock);
    RawEvent mLastEvent GUARDED_BY(mLock);

    std::optional<DisplayViewport> mViewport;
public:
    FakeInputMapper(InputDeviceContext& deviceContext, const InputReaderConfiguration& readerConfig,
                    uint32_t sources)
          : InputMapper(deviceContext, readerConfig),
            mSources(sources),
            mKeyboardType(AINPUT_KEYBOARD_TYPE_NONE),
            mMetaState(0),
            mConfigureWasCalled(false),
            mResetWasCalled(false),
            mProcessWasCalled(false) {}

    virtual ~FakeInputMapper() {}

    void setKeyboardType(int32_t keyboardType) {
        mKeyboardType = keyboardType;
    }

    void setMetaState(int32_t metaState) {
        mMetaState = metaState;
    }

    // Sets the return value for the `process` call.
    void setProcessResult(std::list<NotifyArgs> notifyArgs) {
        mProcessResult.clear();
        for (auto notifyArg : notifyArgs) {
            mProcessResult.push_back(notifyArg);
        }
    }

    void assertConfigureWasCalled() {
        std::unique_lock<std::mutex> lock(mLock);
        base::ScopedLockAssertion assumeLocked(mLock);
        const bool configureCalled =
                mStateChangedCondition.wait_for(lock, WAIT_TIMEOUT, [this]() REQUIRES(mLock) {
                    return mConfigureWasCalled;
                });
        if (!configureCalled) {
            FAIL() << "Expected configure() to have been called.";
        }
        mConfigureWasCalled = false;
    }

    void assertResetWasCalled() {
        std::unique_lock<std::mutex> lock(mLock);
        base::ScopedLockAssertion assumeLocked(mLock);
        const bool resetCalled =
                mStateChangedCondition.wait_for(lock, WAIT_TIMEOUT, [this]() REQUIRES(mLock) {
                    return mResetWasCalled;
                });
        if (!resetCalled) {
            FAIL() << "Expected reset() to have been called.";
        }
        mResetWasCalled = false;
    }

    void assertResetWasNotCalled() {
        std::scoped_lock lock(mLock);
        ASSERT_FALSE(mResetWasCalled) << "Expected reset to not have been called.";
    }

    void assertProcessWasCalled(RawEvent* outLastEvent = nullptr) {
        std::unique_lock<std::mutex> lock(mLock);
        base::ScopedLockAssertion assumeLocked(mLock);
        const bool processCalled =
                mStateChangedCondition.wait_for(lock, WAIT_TIMEOUT, [this]() REQUIRES(mLock) {
                    return mProcessWasCalled;
                });
        if (!processCalled) {
            FAIL() << "Expected process() to have been called.";
        }
        if (outLastEvent) {
            *outLastEvent = mLastEvent;
        }
        mProcessWasCalled = false;
    }

    void assertProcessWasNotCalled() {
        std::scoped_lock lock(mLock);
        ASSERT_FALSE(mProcessWasCalled) << "Expected process to not have been called.";
    }

    void setKeyCodeState(int32_t keyCode, int32_t state) {
        mKeyCodeStates.replaceValueFor(keyCode, state);
    }

    void setScanCodeState(int32_t scanCode, int32_t state) {
        mScanCodeStates.replaceValueFor(scanCode, state);
    }

    void setSwitchState(int32_t switchCode, int32_t state) {
        mSwitchStates.replaceValueFor(switchCode, state);
    }

    void addSupportedKeyCode(int32_t keyCode) {
        mSupportedKeyCodes.push_back(keyCode);
    }

    void addKeyCodeMapping(int32_t fromKeyCode, int32_t toKeyCode) {
        mKeyCodeMapping.insert_or_assign(fromKeyCode, toKeyCode);
    }

private:
    uint32_t getSources() const override { return mSources; }

    void populateDeviceInfo(InputDeviceInfo& deviceInfo) override {
        InputMapper::populateDeviceInfo(deviceInfo);

        if (mKeyboardType != AINPUT_KEYBOARD_TYPE_NONE) {
            deviceInfo.setKeyboardType(mKeyboardType);
        }
    }

    std::list<NotifyArgs> reconfigure(nsecs_t, const InputReaderConfiguration& config,
                                      ConfigurationChanges changes) override {
        std::scoped_lock<std::mutex> lock(mLock);
        mConfigureWasCalled = true;

        // Find the associated viewport if exist.
        const std::optional<uint8_t> displayPort = getDeviceContext().getAssociatedDisplayPort();
        if (displayPort && changes.test(InputReaderConfiguration::Change::DISPLAY_INFO)) {
            mViewport = config.getDisplayViewportByPort(*displayPort);
        }

        mStateChangedCondition.notify_all();
        return {};
    }

    std::list<NotifyArgs> reset(nsecs_t) override {
        std::scoped_lock<std::mutex> lock(mLock);
        mResetWasCalled = true;
        mStateChangedCondition.notify_all();
        return {};
    }

    std::list<NotifyArgs> process(const RawEvent* rawEvent) override {
        std::scoped_lock<std::mutex> lock(mLock);
        mLastEvent = *rawEvent;
        mProcessWasCalled = true;
        mStateChangedCondition.notify_all();
        return mProcessResult;
    }

    int32_t getKeyCodeState(uint32_t, int32_t keyCode) override {
        ssize_t index = mKeyCodeStates.indexOfKey(keyCode);
        return index >= 0 ? mKeyCodeStates.valueAt(index) : AKEY_STATE_UNKNOWN;
    }

    int32_t getKeyCodeForKeyLocation(int32_t locationKeyCode) const override {
        auto it = mKeyCodeMapping.find(locationKeyCode);
        return it != mKeyCodeMapping.end() ? it->second : locationKeyCode;
    }

    int32_t getScanCodeState(uint32_t, int32_t scanCode) override {
        ssize_t index = mScanCodeStates.indexOfKey(scanCode);
        return index >= 0 ? mScanCodeStates.valueAt(index) : AKEY_STATE_UNKNOWN;
    }

    int32_t getSwitchState(uint32_t, int32_t switchCode) override {
        ssize_t index = mSwitchStates.indexOfKey(switchCode);
        return index >= 0 ? mSwitchStates.valueAt(index) : AKEY_STATE_UNKNOWN;
    }

    // Return true if the device has non-empty key layout.
    bool markSupportedKeyCodes(uint32_t, const std::vector<int32_t>& keyCodes,
                               uint8_t* outFlags) override {
        for (size_t i = 0; i < keyCodes.size(); i++) {
            for (size_t j = 0; j < mSupportedKeyCodes.size(); j++) {
                if (keyCodes[i] == mSupportedKeyCodes[j]) {
                    outFlags[i] = 1;
                }
            }
        }
        bool result = mSupportedKeyCodes.size() > 0;
        return result;
    }

    virtual int32_t getMetaState() {
        return mMetaState;
    }

    virtual void fadePointer() {
    }

    virtual std::optional<int32_t> getAssociatedDisplay() {
        if (mViewport) {
            return std::make_optional(mViewport->displayId);
        }
        return std::nullopt;
    }
};

// --- InputReaderPolicyTest ---
class InputReaderPolicyTest : public testing::Test {
protected:
    sp<FakeInputReaderPolicy> mFakePolicy;

    void SetUp() override { mFakePolicy = sp<FakeInputReaderPolicy>::make(); }
    void TearDown() override { mFakePolicy.clear(); }
};

/**
 * Check that empty set of viewports is an acceptable configuration.
 * Also try to get internal viewport two different ways - by type and by uniqueId.
 *
 * There will be confusion if two viewports with empty uniqueId and identical type are present.
 * Such configuration is not currently allowed.
 */
TEST_F(InputReaderPolicyTest, Viewports_GetCleared) {
    static const std::string uniqueId = "local:0";

    // We didn't add any viewports yet, so there shouldn't be any.
    std::optional<DisplayViewport> internalViewport =
            mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
    ASSERT_FALSE(internalViewport);

    // Add an internal viewport, then clear it
    mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/true, uniqueId, NO_PORT, ViewportType::INTERNAL);

    // Check matching by uniqueId
    internalViewport = mFakePolicy->getDisplayViewportByUniqueId(uniqueId);
    ASSERT_TRUE(internalViewport);
    ASSERT_EQ(ViewportType::INTERNAL, internalViewport->type);

    // Check matching by viewport type
    internalViewport = mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
    ASSERT_TRUE(internalViewport);
    ASSERT_EQ(uniqueId, internalViewport->uniqueId);

    mFakePolicy->clearViewports();
    // Make sure nothing is found after clear
    internalViewport = mFakePolicy->getDisplayViewportByUniqueId(uniqueId);
    ASSERT_FALSE(internalViewport);
    internalViewport = mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
    ASSERT_FALSE(internalViewport);
}

TEST_F(InputReaderPolicyTest, Viewports_GetByType) {
    const std::string internalUniqueId = "local:0";
    const std::string externalUniqueId = "local:1";
    const std::string virtualUniqueId1 = "virtual:2";
    const std::string virtualUniqueId2 = "virtual:3";
    constexpr int32_t virtualDisplayId1 = 2;
    constexpr int32_t virtualDisplayId2 = 3;

    // Add an internal viewport
    mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/true, internalUniqueId, NO_PORT,
                                    ViewportType::INTERNAL);
    // Add an external viewport
    mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/true, externalUniqueId, NO_PORT,
                                    ViewportType::EXTERNAL);
    // Add an virtual viewport
    mFakePolicy->addDisplayViewport(virtualDisplayId1, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                    ui::ROTATION_0, /*isActive=*/true, virtualUniqueId1, NO_PORT,
                                    ViewportType::VIRTUAL);
    // Add another virtual viewport
    mFakePolicy->addDisplayViewport(virtualDisplayId2, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                    ui::ROTATION_0, /*isActive=*/true, virtualUniqueId2, NO_PORT,
                                    ViewportType::VIRTUAL);

    // Check matching by type for internal
    std::optional<DisplayViewport> internalViewport =
            mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
    ASSERT_TRUE(internalViewport);
    ASSERT_EQ(internalUniqueId, internalViewport->uniqueId);

    // Check matching by type for external
    std::optional<DisplayViewport> externalViewport =
            mFakePolicy->getDisplayViewportByType(ViewportType::EXTERNAL);
    ASSERT_TRUE(externalViewport);
    ASSERT_EQ(externalUniqueId, externalViewport->uniqueId);

    // Check matching by uniqueId for virtual viewport #1
    std::optional<DisplayViewport> virtualViewport1 =
            mFakePolicy->getDisplayViewportByUniqueId(virtualUniqueId1);
    ASSERT_TRUE(virtualViewport1);
    ASSERT_EQ(ViewportType::VIRTUAL, virtualViewport1->type);
    ASSERT_EQ(virtualUniqueId1, virtualViewport1->uniqueId);
    ASSERT_EQ(virtualDisplayId1, virtualViewport1->displayId);

    // Check matching by uniqueId for virtual viewport #2
    std::optional<DisplayViewport> virtualViewport2 =
            mFakePolicy->getDisplayViewportByUniqueId(virtualUniqueId2);
    ASSERT_TRUE(virtualViewport2);
    ASSERT_EQ(ViewportType::VIRTUAL, virtualViewport2->type);
    ASSERT_EQ(virtualUniqueId2, virtualViewport2->uniqueId);
    ASSERT_EQ(virtualDisplayId2, virtualViewport2->displayId);
}


/**
 * We can have 2 viewports of the same kind. We can distinguish them by uniqueId, and confirm
 * that lookup works by checking display id.
 * Check that 2 viewports of each kind is possible, for all existing viewport types.
 */
TEST_F(InputReaderPolicyTest, Viewports_TwoOfSameType) {
    const std::string uniqueId1 = "uniqueId1";
    const std::string uniqueId2 = "uniqueId2";
    constexpr int32_t displayId1 = 2;
    constexpr int32_t displayId2 = 3;

    std::vector<ViewportType> types = {ViewportType::INTERNAL, ViewportType::EXTERNAL,
                                       ViewportType::VIRTUAL};
    for (const ViewportType& type : types) {
        mFakePolicy->clearViewports();
        // Add a viewport
        mFakePolicy->addDisplayViewport(displayId1, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                        /*isActive=*/true, uniqueId1, NO_PORT, type);
        // Add another viewport
        mFakePolicy->addDisplayViewport(displayId2, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                        /*isActive=*/true, uniqueId2, NO_PORT, type);

        // Check that correct display viewport was returned by comparing the display IDs.
        std::optional<DisplayViewport> viewport1 =
                mFakePolicy->getDisplayViewportByUniqueId(uniqueId1);
        ASSERT_TRUE(viewport1);
        ASSERT_EQ(displayId1, viewport1->displayId);
        ASSERT_EQ(type, viewport1->type);

        std::optional<DisplayViewport> viewport2 =
                mFakePolicy->getDisplayViewportByUniqueId(uniqueId2);
        ASSERT_TRUE(viewport2);
        ASSERT_EQ(displayId2, viewport2->displayId);
        ASSERT_EQ(type, viewport2->type);

        // When there are multiple viewports of the same kind, and uniqueId is not specified
        // in the call to getDisplayViewport, then that situation is not supported.
        // The viewports can be stored in any order, so we cannot rely on the order, since that
        // is just implementation detail.
        // However, we can check that it still returns *a* viewport, we just cannot assert
        // which one specifically is returned.
        std::optional<DisplayViewport> someViewport = mFakePolicy->getDisplayViewportByType(type);
        ASSERT_TRUE(someViewport);
    }
}

/**
 * When we have multiple internal displays make sure we always return the default display when
 * querying by type.
 */
TEST_F(InputReaderPolicyTest, Viewports_ByTypeReturnsDefaultForInternal) {
    const std::string uniqueId1 = "uniqueId1";
    const std::string uniqueId2 = "uniqueId2";
    constexpr int32_t nonDefaultDisplayId = 2;
    static_assert(nonDefaultDisplayId != ADISPLAY_ID_DEFAULT,
                  "Test display ID should not be ADISPLAY_ID_DEFAULT");

    // Add the default display first and ensure it gets returned.
    mFakePolicy->clearViewports();
    mFakePolicy->addDisplayViewport(ADISPLAY_ID_DEFAULT, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                    ui::ROTATION_0, /*isActive=*/true, uniqueId1, NO_PORT,
                                    ViewportType::INTERNAL);
    mFakePolicy->addDisplayViewport(nonDefaultDisplayId, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                    ui::ROTATION_0, /*isActive=*/true, uniqueId2, NO_PORT,
                                    ViewportType::INTERNAL);

    std::optional<DisplayViewport> viewport =
            mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
    ASSERT_TRUE(viewport);
    ASSERT_EQ(ADISPLAY_ID_DEFAULT, viewport->displayId);
    ASSERT_EQ(ViewportType::INTERNAL, viewport->type);

    // Add the default display second to make sure order doesn't matter.
    mFakePolicy->clearViewports();
    mFakePolicy->addDisplayViewport(nonDefaultDisplayId, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                    ui::ROTATION_0, /*isActive=*/true, uniqueId2, NO_PORT,
                                    ViewportType::INTERNAL);
    mFakePolicy->addDisplayViewport(ADISPLAY_ID_DEFAULT, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                    ui::ROTATION_0, /*isActive=*/true, uniqueId1, NO_PORT,
                                    ViewportType::INTERNAL);

    viewport = mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
    ASSERT_TRUE(viewport);
    ASSERT_EQ(ADISPLAY_ID_DEFAULT, viewport->displayId);
    ASSERT_EQ(ViewportType::INTERNAL, viewport->type);
}

/**
 * Check getDisplayViewportByPort
 */
TEST_F(InputReaderPolicyTest, Viewports_GetByPort) {
    constexpr ViewportType type = ViewportType::EXTERNAL;
    const std::string uniqueId1 = "uniqueId1";
    const std::string uniqueId2 = "uniqueId2";
    constexpr int32_t displayId1 = 1;
    constexpr int32_t displayId2 = 2;
    const uint8_t hdmi1 = 0;
    const uint8_t hdmi2 = 1;
    const uint8_t hdmi3 = 2;

    mFakePolicy->clearViewports();
    // Add a viewport that's associated with some display port that's not of interest.
    mFakePolicy->addDisplayViewport(displayId1, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/true, uniqueId1, hdmi3, type);
    // Add another viewport, connected to HDMI1 port
    mFakePolicy->addDisplayViewport(displayId2, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/true, uniqueId2, hdmi1, type);

    // Check that correct display viewport was returned by comparing the display ports.
    std::optional<DisplayViewport> hdmi1Viewport = mFakePolicy->getDisplayViewportByPort(hdmi1);
    ASSERT_TRUE(hdmi1Viewport);
    ASSERT_EQ(displayId2, hdmi1Viewport->displayId);
    ASSERT_EQ(uniqueId2, hdmi1Viewport->uniqueId);

    // Check that we can still get the same viewport using the uniqueId
    hdmi1Viewport = mFakePolicy->getDisplayViewportByUniqueId(uniqueId2);
    ASSERT_TRUE(hdmi1Viewport);
    ASSERT_EQ(displayId2, hdmi1Viewport->displayId);
    ASSERT_EQ(uniqueId2, hdmi1Viewport->uniqueId);
    ASSERT_EQ(type, hdmi1Viewport->type);

    // Check that we cannot find a port with "HDMI2", because we never added one
    std::optional<DisplayViewport> hdmi2Viewport = mFakePolicy->getDisplayViewportByPort(hdmi2);
    ASSERT_FALSE(hdmi2Viewport);
}

// --- InputReaderTest ---

class InputReaderTest : public testing::Test {
protected:
    std::unique_ptr<TestInputListener> mFakeListener;
    sp<FakeInputReaderPolicy> mFakePolicy;
    std::shared_ptr<FakeEventHub> mFakeEventHub;
    std::unique_ptr<InstrumentedInputReader> mReader;

    void SetUp() override {
        mFakeEventHub = std::make_unique<FakeEventHub>();
        mFakePolicy = sp<FakeInputReaderPolicy>::make();
        mFakeListener = std::make_unique<TestInputListener>();

        mReader = std::make_unique<InstrumentedInputReader>(mFakeEventHub, mFakePolicy,
                                                            *mFakeListener);
    }

    void TearDown() override {
        mFakeListener.reset();
        mFakePolicy.clear();
    }

    void addDevice(int32_t eventHubId, const std::string& name,
                   ftl::Flags<InputDeviceClass> classes, const PropertyMap* configuration) {
        mFakeEventHub->addDevice(eventHubId, name, classes);

        if (configuration) {
            mFakeEventHub->addConfigurationMap(eventHubId, configuration);
        }
        mFakeEventHub->finishDeviceScan();
        mReader->loopOnce();
        mReader->loopOnce();
        ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyInputDevicesChangedWasCalled());
        ASSERT_NO_FATAL_FAILURE(mFakeEventHub->assertQueueIsEmpty());
    }

    void disableDevice(int32_t deviceId) {
        mFakePolicy->addDisabledDevice(deviceId);
        mReader->requestRefreshConfiguration(InputReaderConfiguration::Change::ENABLED_STATE);
    }

    void enableDevice(int32_t deviceId) {
        mFakePolicy->removeDisabledDevice(deviceId);
        mReader->requestRefreshConfiguration(InputReaderConfiguration::Change::ENABLED_STATE);
    }

    FakeInputMapper& addDeviceWithFakeInputMapper(int32_t deviceId, int32_t eventHubId,
                                                  const std::string& name,
                                                  ftl::Flags<InputDeviceClass> classes,
                                                  uint32_t sources,
                                                  const PropertyMap* configuration) {
        std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, name);
        FakeInputMapper& mapper =
                device->addMapper<FakeInputMapper>(eventHubId,
                                                   mFakePolicy->getReaderConfiguration(), sources);
        mReader->pushNextDevice(device);
        addDevice(eventHubId, name, classes, configuration);
        return mapper;
    }
};

TEST_F(InputReaderTest, PolicyGetInputDevices) {
    ASSERT_NO_FATAL_FAILURE(addDevice(1, "keyboard", InputDeviceClass::KEYBOARD, nullptr));
    ASSERT_NO_FATAL_FAILURE(addDevice(2, "ignored", ftl::Flags<InputDeviceClass>(0),
                                      nullptr)); // no classes so device will be ignored

    // Should also have received a notification describing the new input devices.
    const std::vector<InputDeviceInfo>& inputDevices = mFakePolicy->getInputDevices();
    ASSERT_EQ(1U, inputDevices.size());
    ASSERT_EQ(END_RESERVED_ID + 1, inputDevices[0].getId());
    ASSERT_STREQ("keyboard", inputDevices[0].getIdentifier().name.c_str());
    ASSERT_EQ(AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC, inputDevices[0].getKeyboardType());
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, inputDevices[0].getSources());
    ASSERT_EQ(0U, inputDevices[0].getMotionRanges().size());
}

TEST_F(InputReaderTest, InputDeviceRecreatedOnSysfsNodeChanged) {
    ASSERT_NO_FATAL_FAILURE(addDevice(1, "keyboard", InputDeviceClass::KEYBOARD, nullptr));
    mFakeEventHub->setSysfsRootPath(1, "xyz");

    // Should also have received a notification describing the new input device.
    ASSERT_EQ(1U, mFakePolicy->getInputDevices().size());
    InputDeviceInfo inputDevice = mFakePolicy->getInputDevices()[0];
    ASSERT_EQ(0U, inputDevice.getLights().size());

    RawLightInfo infoMonolight = {.id = 123,
                                  .name = "mono_keyboard_backlight",
                                  .maxBrightness = 255,
                                  .flags = InputLightClass::BRIGHTNESS,
                                  .path = ""};
    mFakeEventHub->addRawLightInfo(/*rawId=*/123, std::move(infoMonolight));
    mReader->sysfsNodeChanged("xyz");
    mReader->loopOnce();

    // Should also have received a notification describing the new recreated input device.
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
    inputDevice = mFakePolicy->getInputDevices()[0];
    ASSERT_EQ(1U, inputDevice.getLights().size());
}

TEST_F(InputReaderTest, GetMergedInputDevices) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr int32_t eventHubIds[2] = {END_RESERVED_ID, END_RESERVED_ID + 1};
    // Add two subdevices to device
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake");
    // Must add at least one mapper or the device will be ignored!
    device->addMapper<FakeInputMapper>(eventHubIds[0], mFakePolicy->getReaderConfiguration(),
                                       AINPUT_SOURCE_KEYBOARD);
    device->addMapper<FakeInputMapper>(eventHubIds[1], mFakePolicy->getReaderConfiguration(),
                                       AINPUT_SOURCE_KEYBOARD);

    // Push same device instance for next device to be added, so they'll have same identifier.
    mReader->pushNextDevice(device);
    mReader->pushNextDevice(device);
    ASSERT_NO_FATAL_FAILURE(
            addDevice(eventHubIds[0], "fake1", InputDeviceClass::KEYBOARD, nullptr));
    ASSERT_NO_FATAL_FAILURE(
            addDevice(eventHubIds[1], "fake2", InputDeviceClass::KEYBOARD, nullptr));

    // Two devices will be merged to one input device as they have same identifier
    ASSERT_EQ(1U, mFakePolicy->getInputDevices().size());
}

TEST_F(InputReaderTest, GetMergedInputDevicesEnabled) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr int32_t eventHubIds[2] = {END_RESERVED_ID, END_RESERVED_ID + 1};
    // Add two subdevices to device
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake");
    // Must add at least one mapper or the device will be ignored!
    device->addMapper<FakeInputMapper>(eventHubIds[0], mFakePolicy->getReaderConfiguration(),
                                       AINPUT_SOURCE_KEYBOARD);
    device->addMapper<FakeInputMapper>(eventHubIds[1], mFakePolicy->getReaderConfiguration(),
                                       AINPUT_SOURCE_KEYBOARD);

    // Push same device instance for next device to be added, so they'll have same identifier.
    mReader->pushNextDevice(device);
    mReader->pushNextDevice(device);
    // Sensor device is initially disabled
    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubIds[0], "fake1",
                                      InputDeviceClass::KEYBOARD | InputDeviceClass::SENSOR,
                                      nullptr));
    // Device is disabled because the only sub device is a sensor device and disabled initially.
    ASSERT_FALSE(mFakeEventHub->isDeviceEnabled(eventHubIds[0]));
    ASSERT_FALSE(device->isEnabled());
    ASSERT_NO_FATAL_FAILURE(
            addDevice(eventHubIds[1], "fake2", InputDeviceClass::KEYBOARD, nullptr));
    // The merged device is enabled if any sub device is enabled
    ASSERT_TRUE(mFakeEventHub->isDeviceEnabled(eventHubIds[1]));
    ASSERT_TRUE(device->isEnabled());
}

TEST_F(InputReaderTest, WhenEnabledChanges_SendsDeviceResetNotification) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr ftl::Flags<InputDeviceClass> deviceClass(InputDeviceClass::KEYBOARD);
    constexpr int32_t eventHubId = 1;
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake");
    // Must add at least one mapper or the device will be ignored!
    device->addMapper<FakeInputMapper>(eventHubId, mFakePolicy->getReaderConfiguration(),
                                       AINPUT_SOURCE_KEYBOARD);
    mReader->pushNextDevice(device);
    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubId, "fake", deviceClass, nullptr));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyConfigurationChangedWasCalled(nullptr));

    NotifyDeviceResetArgs resetArgs;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_EQ(deviceId, resetArgs.deviceId);

    ASSERT_EQ(device->isEnabled(), true);
    disableDevice(deviceId);
    mReader->loopOnce();

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_EQ(deviceId, resetArgs.deviceId);
    ASSERT_EQ(device->isEnabled(), false);

    disableDevice(deviceId);
    mReader->loopOnce();
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyConfigurationChangedWasNotCalled());
    ASSERT_EQ(device->isEnabled(), false);

    enableDevice(deviceId);
    mReader->loopOnce();
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_EQ(deviceId, resetArgs.deviceId);
    ASSERT_EQ(device->isEnabled(), true);
}

TEST_F(InputReaderTest, GetKeyCodeState_ForwardsRequestsToMappers) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr ftl::Flags<InputDeviceClass> deviceClass = InputDeviceClass::KEYBOARD;
    constexpr int32_t eventHubId = 1;
    FakeInputMapper& mapper =
            addDeviceWithFakeInputMapper(deviceId, eventHubId, "fake", deviceClass,
                                         AINPUT_SOURCE_KEYBOARD, nullptr);
    mapper.setKeyCodeState(AKEYCODE_A, AKEY_STATE_DOWN);

    ASSERT_EQ(AKEY_STATE_UNKNOWN, mReader->getKeyCodeState(0,
            AINPUT_SOURCE_ANY, AKEYCODE_A))
            << "Should return unknown when the device id is >= 0 but unknown.";

    ASSERT_EQ(AKEY_STATE_UNKNOWN,
              mReader->getKeyCodeState(deviceId, AINPUT_SOURCE_TRACKBALL, AKEYCODE_A))
            << "Should return unknown when the device id is valid but the sources are not "
               "supported by the device.";

    ASSERT_EQ(AKEY_STATE_DOWN,
              mReader->getKeyCodeState(deviceId, AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_TRACKBALL,
                                       AKEYCODE_A))
            << "Should return value provided by mapper when device id is valid and the device "
               "supports some of the sources.";

    ASSERT_EQ(AKEY_STATE_UNKNOWN, mReader->getKeyCodeState(-1,
            AINPUT_SOURCE_TRACKBALL, AKEYCODE_A))
            << "Should return unknown when the device id is < 0 but the sources are not supported by any device.";

    ASSERT_EQ(AKEY_STATE_DOWN, mReader->getKeyCodeState(-1,
            AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_TRACKBALL, AKEYCODE_A))
            << "Should return value provided by mapper when device id is < 0 and one of the devices supports some of the sources.";
}

TEST_F(InputReaderTest, GetKeyCodeForKeyLocation_ForwardsRequestsToMappers) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr int32_t eventHubId = 1;
    FakeInputMapper& mapper = addDeviceWithFakeInputMapper(deviceId, eventHubId, "keyboard",
                                                           InputDeviceClass::KEYBOARD,
                                                           AINPUT_SOURCE_KEYBOARD, nullptr);
    mapper.addKeyCodeMapping(AKEYCODE_Y, AKEYCODE_Z);

    ASSERT_EQ(AKEYCODE_UNKNOWN, mReader->getKeyCodeForKeyLocation(0, AKEYCODE_Y))
            << "Should return unknown when the device with the specified id is not found.";

    ASSERT_EQ(AKEYCODE_Z, mReader->getKeyCodeForKeyLocation(deviceId, AKEYCODE_Y))
            << "Should return correct mapping when device id is valid and mapping exists.";

    ASSERT_EQ(AKEYCODE_A, mReader->getKeyCodeForKeyLocation(deviceId, AKEYCODE_A))
            << "Should return the location key code when device id is valid and there's no "
               "mapping.";
}

TEST_F(InputReaderTest, GetKeyCodeForKeyLocation_NoKeyboardMapper) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr int32_t eventHubId = 1;
    FakeInputMapper& mapper = addDeviceWithFakeInputMapper(deviceId, eventHubId, "joystick",
                                                           InputDeviceClass::JOYSTICK,
                                                           AINPUT_SOURCE_GAMEPAD, nullptr);
    mapper.addKeyCodeMapping(AKEYCODE_Y, AKEYCODE_Z);

    ASSERT_EQ(AKEYCODE_UNKNOWN, mReader->getKeyCodeForKeyLocation(deviceId, AKEYCODE_Y))
            << "Should return unknown when the device id is valid but there is no keyboard mapper";
}

TEST_F(InputReaderTest, GetScanCodeState_ForwardsRequestsToMappers) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr ftl::Flags<InputDeviceClass> deviceClass = InputDeviceClass::KEYBOARD;
    constexpr int32_t eventHubId = 1;
    FakeInputMapper& mapper =
            addDeviceWithFakeInputMapper(deviceId, eventHubId, "fake", deviceClass,
                                         AINPUT_SOURCE_KEYBOARD, nullptr);
    mapper.setScanCodeState(KEY_A, AKEY_STATE_DOWN);

    ASSERT_EQ(AKEY_STATE_UNKNOWN, mReader->getScanCodeState(0,
            AINPUT_SOURCE_ANY, KEY_A))
            << "Should return unknown when the device id is >= 0 but unknown.";

    ASSERT_EQ(AKEY_STATE_UNKNOWN,
              mReader->getScanCodeState(deviceId, AINPUT_SOURCE_TRACKBALL, KEY_A))
            << "Should return unknown when the device id is valid but the sources are not "
               "supported by the device.";

    ASSERT_EQ(AKEY_STATE_DOWN,
              mReader->getScanCodeState(deviceId, AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_TRACKBALL,
                                        KEY_A))
            << "Should return value provided by mapper when device id is valid and the device "
               "supports some of the sources.";

    ASSERT_EQ(AKEY_STATE_UNKNOWN, mReader->getScanCodeState(-1,
            AINPUT_SOURCE_TRACKBALL, KEY_A))
            << "Should return unknown when the device id is < 0 but the sources are not supported by any device.";

    ASSERT_EQ(AKEY_STATE_DOWN, mReader->getScanCodeState(-1,
            AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_TRACKBALL, KEY_A))
            << "Should return value provided by mapper when device id is < 0 and one of the devices supports some of the sources.";
}

TEST_F(InputReaderTest, GetSwitchState_ForwardsRequestsToMappers) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr ftl::Flags<InputDeviceClass> deviceClass = InputDeviceClass::KEYBOARD;
    constexpr int32_t eventHubId = 1;
    FakeInputMapper& mapper =
            addDeviceWithFakeInputMapper(deviceId, eventHubId, "fake", deviceClass,
                                         AINPUT_SOURCE_KEYBOARD, nullptr);
    mapper.setSwitchState(SW_LID, AKEY_STATE_DOWN);

    ASSERT_EQ(AKEY_STATE_UNKNOWN, mReader->getSwitchState(0,
            AINPUT_SOURCE_ANY, SW_LID))
            << "Should return unknown when the device id is >= 0 but unknown.";

    ASSERT_EQ(AKEY_STATE_UNKNOWN,
              mReader->getSwitchState(deviceId, AINPUT_SOURCE_TRACKBALL, SW_LID))
            << "Should return unknown when the device id is valid but the sources are not "
               "supported by the device.";

    ASSERT_EQ(AKEY_STATE_DOWN,
              mReader->getSwitchState(deviceId, AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_TRACKBALL,
                                      SW_LID))
            << "Should return value provided by mapper when device id is valid and the device "
               "supports some of the sources.";

    ASSERT_EQ(AKEY_STATE_UNKNOWN, mReader->getSwitchState(-1,
            AINPUT_SOURCE_TRACKBALL, SW_LID))
            << "Should return unknown when the device id is < 0 but the sources are not supported by any device.";

    ASSERT_EQ(AKEY_STATE_DOWN, mReader->getSwitchState(-1,
            AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_TRACKBALL, SW_LID))
            << "Should return value provided by mapper when device id is < 0 and one of the devices supports some of the sources.";
}

TEST_F(InputReaderTest, MarkSupportedKeyCodes_ForwardsRequestsToMappers) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr ftl::Flags<InputDeviceClass> deviceClass = InputDeviceClass::KEYBOARD;
    constexpr int32_t eventHubId = 1;
    FakeInputMapper& mapper =
            addDeviceWithFakeInputMapper(deviceId, eventHubId, "fake", deviceClass,
                                         AINPUT_SOURCE_KEYBOARD, nullptr);

    mapper.addSupportedKeyCode(AKEYCODE_A);
    mapper.addSupportedKeyCode(AKEYCODE_B);

    const std::vector<int32_t> keyCodes{AKEYCODE_A, AKEYCODE_B, AKEYCODE_1, AKEYCODE_2};
    uint8_t flags[4] = { 0, 0, 0, 1 };

    ASSERT_FALSE(mReader->hasKeys(0, AINPUT_SOURCE_ANY, keyCodes, flags))
            << "Should return false when device id is >= 0 but unknown.";
    ASSERT_TRUE(!flags[0] && !flags[1] && !flags[2] && !flags[3]);

    flags[3] = 1;
    ASSERT_FALSE(mReader->hasKeys(deviceId, AINPUT_SOURCE_TRACKBALL, keyCodes, flags))
            << "Should return false when device id is valid but the sources are not supported by "
               "the device.";
    ASSERT_TRUE(!flags[0] && !flags[1] && !flags[2] && !flags[3]);

    flags[3] = 1;
    ASSERT_TRUE(mReader->hasKeys(deviceId, AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_TRACKBALL,
                                 keyCodes, flags))
            << "Should return value provided by mapper when device id is valid and the device "
               "supports some of the sources.";
    ASSERT_TRUE(flags[0] && flags[1] && !flags[2] && !flags[3]);

    flags[3] = 1;
    ASSERT_FALSE(mReader->hasKeys(-1, AINPUT_SOURCE_TRACKBALL, keyCodes, flags))
            << "Should return false when the device id is < 0 but the sources are not supported by "
               "any device.";
    ASSERT_TRUE(!flags[0] && !flags[1] && !flags[2] && !flags[3]);

    flags[3] = 1;
    ASSERT_TRUE(
            mReader->hasKeys(-1, AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_TRACKBALL, keyCodes, flags))
            << "Should return value provided by mapper when device id is < 0 and one of the "
               "devices supports some of the sources.";
    ASSERT_TRUE(flags[0] && flags[1] && !flags[2] && !flags[3]);
}

TEST_F(InputReaderTest, LoopOnce_WhenDeviceScanFinished_SendsConfigurationChanged) {
    constexpr int32_t eventHubId = 1;
    addDevice(eventHubId, "ignored", InputDeviceClass::KEYBOARD, nullptr);

    NotifyConfigurationChangedArgs args;

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyConfigurationChangedWasCalled(&args));
    ASSERT_EQ(ARBITRARY_TIME, args.eventTime);
}

TEST_F(InputReaderTest, LoopOnce_ForwardsRawEventsToMappers) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr ftl::Flags<InputDeviceClass> deviceClass = InputDeviceClass::KEYBOARD;
    constexpr nsecs_t when = 0;
    constexpr int32_t eventHubId = 1;
    constexpr nsecs_t readTime = 2;
    FakeInputMapper& mapper =
            addDeviceWithFakeInputMapper(deviceId, eventHubId, "fake", deviceClass,
                                         AINPUT_SOURCE_KEYBOARD, nullptr);

    mFakeEventHub->enqueueEvent(when, readTime, eventHubId, EV_KEY, KEY_A, 1);
    mReader->loopOnce();
    ASSERT_NO_FATAL_FAILURE(mFakeEventHub->assertQueueIsEmpty());

    RawEvent event;
    ASSERT_NO_FATAL_FAILURE(mapper.assertProcessWasCalled(&event));
    ASSERT_EQ(when, event.when);
    ASSERT_EQ(readTime, event.readTime);
    ASSERT_EQ(eventHubId, event.deviceId);
    ASSERT_EQ(EV_KEY, event.type);
    ASSERT_EQ(KEY_A, event.code);
    ASSERT_EQ(1, event.value);
}

TEST_F(InputReaderTest, DeviceReset_RandomId) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr ftl::Flags<InputDeviceClass> deviceClass = InputDeviceClass::KEYBOARD;
    constexpr int32_t eventHubId = 1;
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake");
    // Must add at least one mapper or the device will be ignored!
    device->addMapper<FakeInputMapper>(eventHubId, mFakePolicy->getReaderConfiguration(),
                                       AINPUT_SOURCE_KEYBOARD);
    mReader->pushNextDevice(device);
    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubId, "fake", deviceClass, nullptr));

    NotifyDeviceResetArgs resetArgs;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    int32_t prevId = resetArgs.id;

    disableDevice(deviceId);
    mReader->loopOnce();
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_NE(prevId, resetArgs.id);
    prevId = resetArgs.id;

    enableDevice(deviceId);
    mReader->loopOnce();
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_NE(prevId, resetArgs.id);
    prevId = resetArgs.id;

    disableDevice(deviceId);
    mReader->loopOnce();
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_NE(prevId, resetArgs.id);
    prevId = resetArgs.id;
}

TEST_F(InputReaderTest, DeviceReset_GenerateIdWithInputReaderSource) {
    constexpr int32_t deviceId = 1;
    constexpr ftl::Flags<InputDeviceClass> deviceClass = InputDeviceClass::KEYBOARD;
    constexpr int32_t eventHubId = 1;
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake");
    // Must add at least one mapper or the device will be ignored!
    device->addMapper<FakeInputMapper>(eventHubId, mFakePolicy->getReaderConfiguration(),
                                       AINPUT_SOURCE_KEYBOARD);
    mReader->pushNextDevice(device);
    ASSERT_NO_FATAL_FAILURE(addDevice(deviceId, "fake", deviceClass, nullptr));

    NotifyDeviceResetArgs resetArgs;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_EQ(IdGenerator::Source::INPUT_READER, IdGenerator::getSource(resetArgs.id));
}

TEST_F(InputReaderTest, Device_CanDispatchToDisplay) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr ftl::Flags<InputDeviceClass> deviceClass = InputDeviceClass::KEYBOARD;
    constexpr int32_t eventHubId = 1;
    const char* DEVICE_LOCATION = "USB1";
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake", DEVICE_LOCATION);
    FakeInputMapper& mapper =
            device->addMapper<FakeInputMapper>(eventHubId, mFakePolicy->getReaderConfiguration(),
                                               AINPUT_SOURCE_TOUCHSCREEN);
    mReader->pushNextDevice(device);

    const uint8_t hdmi1 = 1;

    // Associated touch screen with second display.
    mFakePolicy->addInputPortAssociation(DEVICE_LOCATION, hdmi1);

    // Add default and second display.
    mFakePolicy->clearViewports();
    mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/true, "local:0", NO_PORT, ViewportType::INTERNAL);
    mFakePolicy->addDisplayViewport(SECONDARY_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                    ui::ROTATION_0, /*isActive=*/true, "local:1", hdmi1,
                                    ViewportType::EXTERNAL);
    mReader->requestRefreshConfiguration(InputReaderConfiguration::Change::DISPLAY_INFO);
    mReader->loopOnce();

    // Add the device, and make sure all of the callbacks are triggered.
    // The device is added after the input port associations are processed since
    // we do not yet support dynamic device-to-display associations.
    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubId, "fake", deviceClass, nullptr));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyConfigurationChangedWasCalled());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled());
    ASSERT_NO_FATAL_FAILURE(mapper.assertConfigureWasCalled());

    // Device should only dispatch to the specified display.
    ASSERT_EQ(deviceId, device->getId());
    ASSERT_FALSE(mReader->canDispatchToDisplay(deviceId, DISPLAY_ID));
    ASSERT_TRUE(mReader->canDispatchToDisplay(deviceId, SECONDARY_DISPLAY_ID));

    // Can't dispatch event from a disabled device.
    disableDevice(deviceId);
    mReader->loopOnce();
    ASSERT_FALSE(mReader->canDispatchToDisplay(deviceId, SECONDARY_DISPLAY_ID));
}

TEST_F(InputReaderTest, WhenEnabledChanges_AllSubdevicesAreUpdated) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr ftl::Flags<InputDeviceClass> deviceClass = InputDeviceClass::KEYBOARD;
    constexpr int32_t eventHubIds[2] = {END_RESERVED_ID, END_RESERVED_ID + 1};
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake");
    // Must add at least one mapper or the device will be ignored!
    device->addMapper<FakeInputMapper>(eventHubIds[0], mFakePolicy->getReaderConfiguration(),
                                       AINPUT_SOURCE_KEYBOARD);
    device->addMapper<FakeInputMapper>(eventHubIds[1], mFakePolicy->getReaderConfiguration(),
                                       AINPUT_SOURCE_KEYBOARD);
    mReader->pushNextDevice(device);
    mReader->pushNextDevice(device);
    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubIds[0], "fake1", deviceClass, nullptr));
    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubIds[1], "fake2", deviceClass, nullptr));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyConfigurationChangedWasCalled(nullptr));

    NotifyDeviceResetArgs resetArgs;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_EQ(deviceId, resetArgs.deviceId);
    ASSERT_TRUE(device->isEnabled());
    ASSERT_TRUE(mFakeEventHub->isDeviceEnabled(eventHubIds[0]));
    ASSERT_TRUE(mFakeEventHub->isDeviceEnabled(eventHubIds[1]));

    disableDevice(deviceId);
    mReader->loopOnce();

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_EQ(deviceId, resetArgs.deviceId);
    ASSERT_FALSE(device->isEnabled());
    ASSERT_FALSE(mFakeEventHub->isDeviceEnabled(eventHubIds[0]));
    ASSERT_FALSE(mFakeEventHub->isDeviceEnabled(eventHubIds[1]));

    enableDevice(deviceId);
    mReader->loopOnce();

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_EQ(deviceId, resetArgs.deviceId);
    ASSERT_TRUE(device->isEnabled());
    ASSERT_TRUE(mFakeEventHub->isDeviceEnabled(eventHubIds[0]));
    ASSERT_TRUE(mFakeEventHub->isDeviceEnabled(eventHubIds[1]));
}

TEST_F(InputReaderTest, GetKeyCodeState_ForwardsRequestsToSubdeviceMappers) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    constexpr ftl::Flags<InputDeviceClass> deviceClass = InputDeviceClass::KEYBOARD;
    constexpr int32_t eventHubIds[2] = {END_RESERVED_ID, END_RESERVED_ID + 1};
    // Add two subdevices to device
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake");
    FakeInputMapper& mapperDevice1 =
            device->addMapper<FakeInputMapper>(eventHubIds[0],
                                               mFakePolicy->getReaderConfiguration(),
                                               AINPUT_SOURCE_KEYBOARD);
    FakeInputMapper& mapperDevice2 =
            device->addMapper<FakeInputMapper>(eventHubIds[1],
                                               mFakePolicy->getReaderConfiguration(),
                                               AINPUT_SOURCE_KEYBOARD);
    mReader->pushNextDevice(device);
    mReader->pushNextDevice(device);
    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubIds[0], "fake1", deviceClass, nullptr));
    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubIds[1], "fake2", deviceClass, nullptr));

    mapperDevice1.setKeyCodeState(AKEYCODE_A, AKEY_STATE_DOWN);
    mapperDevice2.setKeyCodeState(AKEYCODE_B, AKEY_STATE_DOWN);

    ASSERT_EQ(AKEY_STATE_DOWN,
              mReader->getKeyCodeState(deviceId, AINPUT_SOURCE_KEYBOARD, AKEYCODE_A));
    ASSERT_EQ(AKEY_STATE_DOWN,
              mReader->getKeyCodeState(deviceId, AINPUT_SOURCE_KEYBOARD, AKEYCODE_B));
    ASSERT_EQ(AKEY_STATE_UNKNOWN,
              mReader->getKeyCodeState(deviceId, AINPUT_SOURCE_KEYBOARD, AKEYCODE_C));
}

TEST_F(InputReaderTest, ChangingPointerCaptureNotifiesInputListener) {
    NotifyPointerCaptureChangedArgs args;

    auto request = mFakePolicy->setPointerCapture(true);
    mReader->requestRefreshConfiguration(InputReaderConfiguration::Change::POINTER_CAPTURE);
    mReader->loopOnce();
    mFakeListener->assertNotifyCaptureWasCalled(&args);
    ASSERT_TRUE(args.request.enable) << "Pointer Capture should be enabled.";
    ASSERT_EQ(args.request, request) << "Pointer Capture sequence number should match.";

    mFakePolicy->setPointerCapture(false);
    mReader->requestRefreshConfiguration(InputReaderConfiguration::Change::POINTER_CAPTURE);
    mReader->loopOnce();
    mFakeListener->assertNotifyCaptureWasCalled(&args);
    ASSERT_FALSE(args.request.enable) << "Pointer Capture should be disabled.";

    // Verify that the Pointer Capture state is not updated when the configuration value
    // does not change.
    mReader->requestRefreshConfiguration(InputReaderConfiguration::Change::POINTER_CAPTURE);
    mReader->loopOnce();
    mFakeListener->assertNotifyCaptureWasNotCalled();
}

class FakeVibratorInputMapper : public FakeInputMapper {
public:
    FakeVibratorInputMapper(InputDeviceContext& deviceContext,
                            const InputReaderConfiguration& readerConfig, uint32_t sources)
          : FakeInputMapper(deviceContext, readerConfig, sources) {}

    std::vector<int32_t> getVibratorIds() override { return getDeviceContext().getVibratorIds(); }
};

TEST_F(InputReaderTest, VibratorGetVibratorIds) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    ftl::Flags<InputDeviceClass> deviceClass =
            InputDeviceClass::KEYBOARD | InputDeviceClass::VIBRATOR;
    constexpr int32_t eventHubId = 1;
    const char* DEVICE_LOCATION = "BLUETOOTH";
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake", DEVICE_LOCATION);
    FakeVibratorInputMapper& mapper =
            device->addMapper<FakeVibratorInputMapper>(eventHubId,
                                                       mFakePolicy->getReaderConfiguration(),
                                                       AINPUT_SOURCE_KEYBOARD);
    mReader->pushNextDevice(device);

    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubId, "fake", deviceClass, nullptr));
    ASSERT_NO_FATAL_FAILURE(mapper.assertConfigureWasCalled());

    ASSERT_EQ(mapper.getVibratorIds().size(), 2U);
    ASSERT_EQ(mReader->getVibratorIds(deviceId).size(), 2U);
}

// --- FakePeripheralController ---

class FakePeripheralController : public PeripheralControllerInterface {
public:
    FakePeripheralController(InputDeviceContext& deviceContext) : mDeviceContext(deviceContext) {}

    ~FakePeripheralController() override {}

    int32_t getEventHubId() const { return getDeviceContext().getEventHubId(); }

    void populateDeviceInfo(InputDeviceInfo* deviceInfo) override {}

    void dump(std::string& dump) override {}

    std::optional<int32_t> getBatteryCapacity(int32_t batteryId) override {
        return getDeviceContext().getBatteryCapacity(batteryId);
    }

    std::optional<int32_t> getBatteryStatus(int32_t batteryId) override {
        return getDeviceContext().getBatteryStatus(batteryId);
    }

    bool setLightColor(int32_t lightId, int32_t color) override {
        getDeviceContext().setLightBrightness(lightId, color >> 24);
        return true;
    }

    std::optional<int32_t> getLightColor(int32_t lightId) override {
        std::optional<int32_t> result = getDeviceContext().getLightBrightness(lightId);
        if (!result.has_value()) {
            return std::nullopt;
        }
        return result.value() << 24;
    }

    bool setLightPlayerId(int32_t lightId, int32_t playerId) override { return true; }

    std::optional<int32_t> getLightPlayerId(int32_t lightId) override { return std::nullopt; }

private:
    InputDeviceContext& mDeviceContext;
    inline int32_t getDeviceId() { return mDeviceContext.getId(); }
    inline InputDeviceContext& getDeviceContext() { return mDeviceContext; }
    inline InputDeviceContext& getDeviceContext() const { return mDeviceContext; }
};

TEST_F(InputReaderTest, BatteryGetCapacity) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    ftl::Flags<InputDeviceClass> deviceClass =
            InputDeviceClass::KEYBOARD | InputDeviceClass::BATTERY;
    constexpr int32_t eventHubId = 1;
    const char* DEVICE_LOCATION = "BLUETOOTH";
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake", DEVICE_LOCATION);
    FakePeripheralController& controller =
            device->addController<FakePeripheralController>(eventHubId);
    mReader->pushNextDevice(device);

    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubId, "fake", deviceClass, nullptr));

    ASSERT_EQ(controller.getBatteryCapacity(FakeEventHub::DEFAULT_BATTERY),
              FakeEventHub::BATTERY_CAPACITY);
    ASSERT_EQ(mReader->getBatteryCapacity(deviceId), FakeEventHub::BATTERY_CAPACITY);
}

TEST_F(InputReaderTest, BatteryGetStatus) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    ftl::Flags<InputDeviceClass> deviceClass =
            InputDeviceClass::KEYBOARD | InputDeviceClass::BATTERY;
    constexpr int32_t eventHubId = 1;
    const char* DEVICE_LOCATION = "BLUETOOTH";
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake", DEVICE_LOCATION);
    FakePeripheralController& controller =
            device->addController<FakePeripheralController>(eventHubId);
    mReader->pushNextDevice(device);

    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubId, "fake", deviceClass, nullptr));

    ASSERT_EQ(controller.getBatteryStatus(FakeEventHub::DEFAULT_BATTERY),
              FakeEventHub::BATTERY_STATUS);
    ASSERT_EQ(mReader->getBatteryStatus(deviceId), FakeEventHub::BATTERY_STATUS);
}

TEST_F(InputReaderTest, BatteryGetDevicePath) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    ftl::Flags<InputDeviceClass> deviceClass =
            InputDeviceClass::KEYBOARD | InputDeviceClass::BATTERY;
    constexpr int32_t eventHubId = 1;
    const char* DEVICE_LOCATION = "BLUETOOTH";
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake", DEVICE_LOCATION);
    device->addController<FakePeripheralController>(eventHubId);
    mReader->pushNextDevice(device);

    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubId, "fake", deviceClass, nullptr));

    ASSERT_EQ(mReader->getBatteryDevicePath(deviceId), FakeEventHub::BATTERY_DEVPATH);
}

TEST_F(InputReaderTest, LightGetColor) {
    constexpr int32_t deviceId = END_RESERVED_ID + 1000;
    ftl::Flags<InputDeviceClass> deviceClass = InputDeviceClass::KEYBOARD | InputDeviceClass::LIGHT;
    constexpr int32_t eventHubId = 1;
    const char* DEVICE_LOCATION = "BLUETOOTH";
    std::shared_ptr<InputDevice> device = mReader->newDevice(deviceId, "fake", DEVICE_LOCATION);
    FakePeripheralController& controller =
            device->addController<FakePeripheralController>(eventHubId);
    mReader->pushNextDevice(device);
    RawLightInfo info = {.id = 1,
                         .name = "Mono",
                         .maxBrightness = 255,
                         .flags = InputLightClass::BRIGHTNESS,
                         .path = ""};
    mFakeEventHub->addRawLightInfo(/*rawId=*/1, std::move(info));
    mFakeEventHub->fakeLightBrightness(/*rawId=*/1, 0x55);

    ASSERT_NO_FATAL_FAILURE(addDevice(eventHubId, "fake", deviceClass, nullptr));

    ASSERT_TRUE(controller.setLightColor(/*lightId=*/1, LIGHT_BRIGHTNESS));
    ASSERT_EQ(controller.getLightColor(/*lightId=*/1), LIGHT_BRIGHTNESS);
    ASSERT_TRUE(mReader->setLightColor(deviceId, /*lightId=*/1, LIGHT_BRIGHTNESS));
    ASSERT_EQ(mReader->getLightColor(deviceId, /*lightId=*/1), LIGHT_BRIGHTNESS);
}

// --- InputReaderIntegrationTest ---

// These tests create and interact with the InputReader only through its interface.
// The InputReader is started during SetUp(), which starts its processing in its own
// thread. The tests use linux uinput to emulate input devices.
// NOTE: Interacting with the physical device while these tests are running may cause
// the tests to fail.
class InputReaderIntegrationTest : public testing::Test {
protected:
    std::unique_ptr<TestInputListener> mTestListener;
    sp<FakeInputReaderPolicy> mFakePolicy;
    std::unique_ptr<InputReaderInterface> mReader;

    std::shared_ptr<FakePointerController> mFakePointerController;

    constexpr static auto EVENT_HAPPENED_TIMEOUT = 2000ms;
    constexpr static auto EVENT_DID_NOT_HAPPEN_TIMEOUT = 30ms;

    void SetUp() override {
#if !defined(__ANDROID__)
        GTEST_SKIP();
#endif
        mFakePolicy = sp<FakeInputReaderPolicy>::make();
        mFakePointerController = std::make_shared<FakePointerController>();
        mFakePolicy->setPointerController(mFakePointerController);

        setupInputReader();
    }

    void TearDown() override {
#if !defined(__ANDROID__)
        return;
#endif
        ASSERT_EQ(mReader->stop(), OK);
        mReader.reset();
        mTestListener.reset();
        mFakePolicy.clear();
    }

    std::optional<InputDeviceInfo> waitForDevice(const std::string& deviceName) {
        std::chrono::time_point start = std::chrono::steady_clock::now();
        while (true) {
            const std::vector<InputDeviceInfo> inputDevices = mFakePolicy->getInputDevices();
            const auto& it = std::find_if(inputDevices.begin(), inputDevices.end(),
                                          [&deviceName](const InputDeviceInfo& info) {
                                              return info.getIdentifier().name == deviceName;
                                          });
            if (it != inputDevices.end()) {
                return std::make_optional(*it);
            }
            std::this_thread::sleep_for(1ms);
            std::chrono::duration elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed > 5s) {
                return {};
            }
        }
    }

    void setupInputReader() {
        mTestListener = std::make_unique<TestInputListener>(EVENT_HAPPENED_TIMEOUT,
                                                            EVENT_DID_NOT_HAPPEN_TIMEOUT);

        mReader = std::make_unique<InputReader>(std::make_shared<EventHub>(), mFakePolicy,
                                                *mTestListener);
        ASSERT_EQ(mReader->start(), OK);

        // Since this test is run on a real device, all the input devices connected
        // to the test device will show up in mReader. We wait for those input devices to
        // show up before beginning the tests.
        ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
        ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyInputDevicesChangedWasCalled());
        ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
    }
};

TEST_F(InputReaderIntegrationTest, TestInvalidDevice) {
    // An invalid input device that is only used for this test.
    class InvalidUinputDevice : public UinputDevice {
    public:
        InvalidUinputDevice() : UinputDevice("Invalid Device", /*productId=*/99) {}

    private:
        void configureDevice(int fd, uinput_user_dev* device) override {}
    };

    const size_t numDevices = mFakePolicy->getInputDevices().size();

    // UinputDevice does not set any event or key bits, so InputReader should not
    // consider it as a valid device.
    std::unique_ptr<UinputDevice> invalidDevice = createUinputDevice<InvalidUinputDevice>();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesNotChanged());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasNotCalled());
    ASSERT_EQ(numDevices, mFakePolicy->getInputDevices().size());

    invalidDevice.reset();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesNotChanged());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasNotCalled());
    ASSERT_EQ(numDevices, mFakePolicy->getInputDevices().size());
}

TEST_F(InputReaderIntegrationTest, AddNewDevice) {
    const size_t initialNumDevices = mFakePolicy->getInputDevices().size();

    std::unique_ptr<UinputHomeKey> keyboard = createUinputDevice<UinputHomeKey>();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
    ASSERT_EQ(initialNumDevices + 1, mFakePolicy->getInputDevices().size());

    const auto device = waitForDevice(keyboard->getName());
    ASSERT_TRUE(device.has_value());
    ASSERT_EQ(AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC, device->getKeyboardType());
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, device->getSources());
    ASSERT_EQ(0U, device->getMotionRanges().size());

    keyboard.reset();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
    ASSERT_EQ(initialNumDevices, mFakePolicy->getInputDevices().size());
}

TEST_F(InputReaderIntegrationTest, SendsEventsToInputListener) {
    std::unique_ptr<UinputHomeKey> keyboard = createUinputDevice<UinputHomeKey>();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());

    NotifyConfigurationChangedArgs configChangedArgs;
    ASSERT_NO_FATAL_FAILURE(
            mTestListener->assertNotifyConfigurationChangedWasCalled(&configChangedArgs));
    int32_t prevId = configChangedArgs.id;
    nsecs_t prevTimestamp = configChangedArgs.eventTime;

    NotifyKeyArgs keyArgs;
    keyboard->pressAndReleaseHomeKey();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, keyArgs.action);
    ASSERT_NE(prevId, keyArgs.id);
    prevId = keyArgs.id;
    ASSERT_LE(prevTimestamp, keyArgs.eventTime);
    ASSERT_LE(keyArgs.eventTime, keyArgs.readTime);
    prevTimestamp = keyArgs.eventTime;

    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, keyArgs.action);
    ASSERT_NE(prevId, keyArgs.id);
    ASSERT_LE(prevTimestamp, keyArgs.eventTime);
    ASSERT_LE(keyArgs.eventTime, keyArgs.readTime);
}

TEST_F(InputReaderIntegrationTest, ExternalStylusesButtons) {
    std::unique_ptr<UinputExternalStylus> stylus = createUinputDevice<UinputExternalStylus>();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());

    const auto device = waitForDevice(stylus->getName());
    ASSERT_TRUE(device.has_value());

    // An external stylus with buttons should also be recognized as a keyboard.
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_STYLUS, device->getSources())
            << "Unexpected source " << inputEventSourceToString(device->getSources()).c_str();
    ASSERT_EQ(AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC, device->getKeyboardType());

    const auto DOWN =
            AllOf(WithKeyAction(AKEY_EVENT_ACTION_DOWN), WithSource(AINPUT_SOURCE_KEYBOARD));
    const auto UP = AllOf(WithKeyAction(AKEY_EVENT_ACTION_UP), WithSource(AINPUT_SOURCE_KEYBOARD));

    stylus->pressAndReleaseKey(BTN_STYLUS);
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(
            AllOf(DOWN, WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY))));
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(
            AllOf(UP, WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY))));

    stylus->pressAndReleaseKey(BTN_STYLUS2);
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(
            AllOf(DOWN, WithKeyCode(AKEYCODE_STYLUS_BUTTON_SECONDARY))));
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(
            AllOf(UP, WithKeyCode(AKEYCODE_STYLUS_BUTTON_SECONDARY))));

    stylus->pressAndReleaseKey(BTN_STYLUS3);
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(
            AllOf(DOWN, WithKeyCode(AKEYCODE_STYLUS_BUTTON_TERTIARY))));
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(
            AllOf(UP, WithKeyCode(AKEYCODE_STYLUS_BUTTON_TERTIARY))));
}

TEST_F(InputReaderIntegrationTest, KeyboardWithStylusButtons) {
    std::unique_ptr<UinputKeyboard> keyboard =
            createUinputDevice<UinputKeyboard>("KeyboardWithStylusButtons", /*productId=*/99,
                                               std::initializer_list<int>{KEY_Q, KEY_W, KEY_E,
                                                                          KEY_R, KEY_T, KEY_Y,
                                                                          BTN_STYLUS, BTN_STYLUS2,
                                                                          BTN_STYLUS3});
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());

    const auto device = waitForDevice(keyboard->getName());
    ASSERT_TRUE(device.has_value());

    // An alphabetical keyboard that reports stylus buttons should not be recognized as a stylus.
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, device->getSources())
            << "Unexpected source " << inputEventSourceToString(device->getSources()).c_str();
    ASSERT_EQ(AINPUT_KEYBOARD_TYPE_ALPHABETIC, device->getKeyboardType());
}

TEST_F(InputReaderIntegrationTest, HidUsageKeyboardIsNotAStylus) {
    // Create a Uinput keyboard that simulates a keyboard that can report HID usage codes. The
    // hid-input driver reports HID usage codes using the value for EV_MSC MSC_SCAN event.
    std::unique_ptr<UinputKeyboardWithHidUsage> keyboard =
            createUinputDevice<UinputKeyboardWithHidUsage>(
                    std::initializer_list<int>{KEY_VOLUMEUP, KEY_VOLUMEDOWN});
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());

    const auto device = waitForDevice(keyboard->getName());
    ASSERT_TRUE(device.has_value());

    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, device->getSources())
            << "Unexpected source " << inputEventSourceToString(device->getSources()).c_str();

    // If a device supports reporting HID usage codes, it shouldn't automatically support
    // stylus keys.
    const std::vector<int> keycodes{AKEYCODE_STYLUS_BUTTON_PRIMARY};
    uint8_t outFlags[] = {0};
    ASSERT_TRUE(mReader->hasKeys(device->getId(), AINPUT_SOURCE_KEYBOARD, keycodes, outFlags));
    ASSERT_EQ(0, outFlags[0]) << "Keyboard should not have stylus button";
}

/**
 * The Steam controller sends BTN_GEAR_DOWN and BTN_GEAR_UP for the two "paddle" buttons
 * on the back. In this test, we make sure that BTN_GEAR_DOWN / BTN_WHEEL and BTN_GEAR_UP
 * are passed to the listener.
 */
static_assert(BTN_GEAR_DOWN == BTN_WHEEL);
TEST_F(InputReaderIntegrationTest, SendsGearDownAndUpToInputListener) {
    std::unique_ptr<UinputSteamController> controller = createUinputDevice<UinputSteamController>();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
    NotifyKeyArgs keyArgs;

    controller->pressAndReleaseKey(BTN_GEAR_DOWN);
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(&keyArgs)); // ACTION_DOWN
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(&keyArgs)); // ACTION_UP
    ASSERT_EQ(BTN_GEAR_DOWN, keyArgs.scanCode);

    controller->pressAndReleaseKey(BTN_GEAR_UP);
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(&keyArgs)); // ACTION_DOWN
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasCalled(&keyArgs)); // ACTION_UP
    ASSERT_EQ(BTN_GEAR_UP, keyArgs.scanCode);
}

// --- TouchIntegrationTest ---

class BaseTouchIntegrationTest : public InputReaderIntegrationTest {
protected:
    const std::string UNIQUE_ID = "local:0";

    void SetUp() override {
#if !defined(__ANDROID__)
        GTEST_SKIP();
#endif
        InputReaderIntegrationTest::SetUp();
        // At least add an internal display.
        setDisplayInfoAndReconfigure(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                     UNIQUE_ID, NO_PORT, ViewportType::INTERNAL);

        mDevice = createUinputDevice<UinputTouchScreen>(Rect(0, 0, DISPLAY_WIDTH, DISPLAY_HEIGHT));
        ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
        ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
        const auto info = waitForDevice(mDevice->getName());
        ASSERT_TRUE(info);
        mDeviceInfo = *info;
    }

    void setDisplayInfoAndReconfigure(int32_t displayId, int32_t width, int32_t height,
                                      ui::Rotation orientation, const std::string& uniqueId,
                                      std::optional<uint8_t> physicalPort,
                                      ViewportType viewportType) {
        mFakePolicy->addDisplayViewport(displayId, width, height, orientation, /*isActive=*/true,
                                        uniqueId, physicalPort, viewportType);
        mReader->requestRefreshConfiguration(InputReaderConfiguration::Change::DISPLAY_INFO);
    }

    void assertReceivedMotion(int32_t action, const std::vector<Point>& points) {
        NotifyMotionArgs args;
        ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
        EXPECT_EQ(action, args.action);
        ASSERT_EQ(points.size(), args.getPointerCount());
        for (size_t i = 0; i < args.getPointerCount(); i++) {
            EXPECT_EQ(points[i].x, args.pointerCoords[i].getX());
            EXPECT_EQ(points[i].y, args.pointerCoords[i].getY());
        }
    }

    std::unique_ptr<UinputTouchScreen> mDevice;
    InputDeviceInfo mDeviceInfo;
};

enum class TouchIntegrationTestDisplays { DISPLAY_INTERNAL, DISPLAY_INPUT_PORT, DISPLAY_UNIQUE_ID };

class TouchIntegrationTest : public BaseTouchIntegrationTest,
                             public testing::WithParamInterface<TouchIntegrationTestDisplays> {
protected:
    static constexpr std::optional<uint8_t> DISPLAY_PORT = 0;
    const std::string INPUT_PORT = "uinput_touch/input0";

    void SetUp() override {
#if !defined(__ANDROID__)
        GTEST_SKIP();
#endif
        if (GetParam() == TouchIntegrationTestDisplays::DISPLAY_INTERNAL) {
            BaseTouchIntegrationTest::SetUp();
            return;
        }

        // setup policy with a input-port or UniqueId association to the display
        bool isInputPortAssociation =
                GetParam() == TouchIntegrationTestDisplays::DISPLAY_INPUT_PORT;

        mFakePolicy = sp<FakeInputReaderPolicy>::make();
        if (isInputPortAssociation) {
            mFakePolicy->addInputPortAssociation(INPUT_PORT, DISPLAY_PORT.value());
        } else {
            mFakePolicy->addInputUniqueIdAssociation(INPUT_PORT, UNIQUE_ID);
        }
        mFakePointerController = std::make_shared<FakePointerController>();
        mFakePolicy->setPointerController(mFakePointerController);

        InputReaderIntegrationTest::setupInputReader();

        mDevice = createUinputDevice<UinputTouchScreen>(Rect(0, 0, DISPLAY_WIDTH, DISPLAY_HEIGHT),
                                                        INPUT_PORT);
        ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());

        // Add a display linked to a physical port or UniqueId.
        setDisplayInfoAndReconfigure(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                     UNIQUE_ID, isInputPortAssociation ? DISPLAY_PORT : NO_PORT,
                                     ViewportType::INTERNAL);
        ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
        ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
        const auto info = waitForDevice(mDevice->getName());
        ASSERT_TRUE(info);
        mDeviceInfo = *info;
    }
};

TEST_P(TouchIntegrationTest, MultiTouchDeviceSource) {
    // The UinputTouchScreen is an MT device that supports MT_TOOL_TYPE and also supports stylus
    // buttons. It should show up as a touchscreen, stylus, and keyboard (for reporting button
    // presses).
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_STYLUS | AINPUT_SOURCE_KEYBOARD,
              mDeviceInfo.getSources());
}

TEST_P(TouchIntegrationTest, InputEvent_ProcessSingleTouch) {
    NotifyMotionArgs args;
    const Point centerPoint = mDevice->getCenterPoint();

    // ACTION_DOWN
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendDown(centerPoint);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, args.action);

    // ACTION_MOVE
    mDevice->sendMove(centerPoint + Point(1, 1));
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, args.action);

    // ACTION_UP
    mDevice->sendUp();
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, args.action);
}

TEST_P(TouchIntegrationTest, InputEvent_ProcessMultiTouch) {
    NotifyMotionArgs args;
    const Point centerPoint = mDevice->getCenterPoint();

    // ACTION_DOWN
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendDown(centerPoint);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, args.action);

    // ACTION_POINTER_DOWN (Second slot)
    const Point secondPoint = centerPoint + Point(100, 100);
    mDevice->sendSlot(SECOND_SLOT);
    mDevice->sendTrackingId(SECOND_TRACKING_ID);
    mDevice->sendDown(secondPoint);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(ACTION_POINTER_1_DOWN, args.action);

    // ACTION_MOVE (Second slot)
    mDevice->sendMove(secondPoint + Point(1, 1));
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, args.action);

    // ACTION_POINTER_UP (Second slot)
    mDevice->sendPointerUp();
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(ACTION_POINTER_1_UP, args.action);

    // ACTION_UP
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendUp();
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, args.action);
}

/**
 * What happens when a pointer goes up while another pointer moves in the same frame? Are POINTER_UP
 * events guaranteed to contain the same data as a preceding MOVE, or can they contain different
 * data?
 * In this test, we try to send a change in coordinates in Pointer 0 in the same frame as the
 * liftoff of Pointer 1. We check that POINTER_UP event is generated first, and the MOVE event
 * for Pointer 0 only is generated after.
 * Suppose we are only interested in learning the movement of Pointer 0. If we only observe MOVE
 * events, we will not miss any information.
 * Even though the Pointer 1 up event contains updated Pointer 0 coordinates, there is another MOVE
 * event generated afterwards that contains the newest movement of pointer 0.
 * This is important for palm rejection. If there is a subsequent InputListener stage that detects
 * palms, and wants to cancel Pointer 1, then it is safe to simply drop POINTER_1_UP event without
 * losing information about non-palm pointers.
 */
TEST_P(TouchIntegrationTest, MultiTouch_PointerMoveAndSecondPointerUp) {
    NotifyMotionArgs args;
    const Point centerPoint = mDevice->getCenterPoint();

    // ACTION_DOWN
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendDown(centerPoint);
    mDevice->sendSync();
    assertReceivedMotion(AMOTION_EVENT_ACTION_DOWN, {centerPoint});

    // ACTION_POINTER_DOWN (Second slot)
    const Point secondPoint = centerPoint + Point(100, 100);
    mDevice->sendSlot(SECOND_SLOT);
    mDevice->sendTrackingId(SECOND_TRACKING_ID);
    mDevice->sendDown(secondPoint);
    mDevice->sendSync();
    assertReceivedMotion(ACTION_POINTER_1_DOWN, {centerPoint, secondPoint});

    // ACTION_MOVE (First slot)
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendMove(centerPoint + Point(5, 5));
    // ACTION_POINTER_UP (Second slot)
    mDevice->sendSlot(SECOND_SLOT);
    mDevice->sendPointerUp();
    // Send a single sync for the above 2 pointer updates
    mDevice->sendSync();

    // First, we should get POINTER_UP for the second pointer
    assertReceivedMotion(ACTION_POINTER_1_UP,
                         {/*first pointer */ centerPoint + Point(5, 5),
                          /*second pointer*/ secondPoint});

    // Next, the MOVE event for the first pointer
    assertReceivedMotion(AMOTION_EVENT_ACTION_MOVE, {centerPoint + Point(5, 5)});
}

/**
 * Similar scenario as above. The difference is that when the second pointer goes up, it will first
 * move, and then it will go up, all in the same frame.
 * In this scenario, the movement of the second pointer just prior to liftoff is ignored, and never
 * gets sent to the listener.
 */
TEST_P(TouchIntegrationTest, MultiTouch_PointerMoveAndSecondPointerMoveAndUp) {
    NotifyMotionArgs args;
    const Point centerPoint = mDevice->getCenterPoint();

    // ACTION_DOWN
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendDown(centerPoint);
    mDevice->sendSync();
    assertReceivedMotion(AMOTION_EVENT_ACTION_DOWN, {centerPoint});

    // ACTION_POINTER_DOWN (Second slot)
    const Point secondPoint = centerPoint + Point(100, 100);
    mDevice->sendSlot(SECOND_SLOT);
    mDevice->sendTrackingId(SECOND_TRACKING_ID);
    mDevice->sendDown(secondPoint);
    mDevice->sendSync();
    assertReceivedMotion(ACTION_POINTER_1_DOWN, {centerPoint, secondPoint});

    // ACTION_MOVE (First slot)
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendMove(centerPoint + Point(5, 5));
    // ACTION_POINTER_UP (Second slot)
    mDevice->sendSlot(SECOND_SLOT);
    mDevice->sendMove(secondPoint + Point(6, 6));
    mDevice->sendPointerUp();
    // Send a single sync for the above 2 pointer updates
    mDevice->sendSync();

    // First, we should get POINTER_UP for the second pointer
    // The movement of the second pointer during the liftoff frame is ignored.
    // The coordinates 'secondPoint + Point(6, 6)' are never sent to the listener.
    assertReceivedMotion(ACTION_POINTER_1_UP,
                         {/*first pointer */ centerPoint + Point(5, 5),
                          /*second pointer*/ secondPoint});

    // Next, the MOVE event for the first pointer
    assertReceivedMotion(AMOTION_EVENT_ACTION_MOVE, {centerPoint + Point(5, 5)});
}

TEST_P(TouchIntegrationTest, InputEvent_ProcessPalm) {
    NotifyMotionArgs args;
    const Point centerPoint = mDevice->getCenterPoint();

    // ACTION_DOWN
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendDown(centerPoint);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, args.action);

    // ACTION_POINTER_DOWN (second slot)
    const Point secondPoint = centerPoint + Point(100, 100);
    mDevice->sendSlot(SECOND_SLOT);
    mDevice->sendTrackingId(SECOND_TRACKING_ID);
    mDevice->sendDown(secondPoint);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(ACTION_POINTER_1_DOWN, args.action);

    // ACTION_MOVE (second slot)
    mDevice->sendMove(secondPoint + Point(1, 1));
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, args.action);

    // Send MT_TOOL_PALM (second slot), which indicates that the touch IC has determined this to be
    // a palm event.
    // Expect to receive the ACTION_POINTER_UP with cancel flag.
    mDevice->sendToolType(MT_TOOL_PALM);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(ACTION_POINTER_1_UP, args.action);
    ASSERT_EQ(AMOTION_EVENT_FLAG_CANCELED, args.flags);

    // Send up to second slot, expect first slot send moving.
    mDevice->sendPointerUp();
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, args.action);

    // Send ACTION_UP (first slot)
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendUp();
    mDevice->sendSync();

    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, args.action);
}

/**
 * Some drivers historically have reported axis values outside of the range specified in the
 * evdev axis info. Ensure we don't crash when this happens. For example, a driver may report a
 * pressure value greater than the reported maximum, since it unclear what specific meaning the
 * maximum value for pressure has (beyond the maximum value that can be produced by a sensor),
 * and no units for pressure (resolution) is specified by the evdev documentation.
 */
TEST_P(TouchIntegrationTest, AcceptsAxisValuesOutsideReportedRange) {
    const Point centerPoint = mDevice->getCenterPoint();

    // Down with pressure outside the reported range
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendDown(centerPoint);
    mDevice->sendPressure(UinputTouchScreen::RAW_PRESSURE_MAX + 2);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_DOWN)));

    // Move to a point outside the reported range
    mDevice->sendMove(Point(DISPLAY_WIDTH, DISPLAY_HEIGHT) + Point(1, 1));
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_MOVE)));

    // Up
    mDevice->sendUp();
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(
            mTestListener->assertNotifyMotionWasCalled(WithMotionAction(AMOTION_EVENT_ACTION_UP)));
}

TEST_P(TouchIntegrationTest, NotifiesPolicyWhenStylusGestureStarted) {
    const Point centerPoint = mDevice->getCenterPoint();

    // Send down with the pen tool selected. The policy should be notified of the stylus presence.
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendToolType(MT_TOOL_PEN);
    mDevice->sendDown(centerPoint);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithToolType(ToolType::STYLUS))));

    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertStylusGestureNotified(mDeviceInfo.getId()));

    // Release the stylus touch.
    mDevice->sendUp();
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(
            mTestListener->assertNotifyMotionWasCalled(WithMotionAction(AMOTION_EVENT_ACTION_UP)));

    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertStylusGestureNotNotified());

    // Touch down with the finger, without the pen tool selected. The policy is not notified.
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendToolType(MT_TOOL_FINGER);
    mDevice->sendDown(centerPoint);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithToolType(ToolType::FINGER))));

    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertStylusGestureNotNotified());

    mDevice->sendUp();
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(
            mTestListener->assertNotifyMotionWasCalled(WithMotionAction(AMOTION_EVENT_ACTION_UP)));

    // Send a move event with the stylus tool without BTN_TOUCH to generate a hover enter.
    // The policy should be notified of the stylus presence.
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendToolType(MT_TOOL_PEN);
    mDevice->sendMove(centerPoint);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                  WithToolType(ToolType::STYLUS))));

    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertStylusGestureNotified(mDeviceInfo.getId()));
}

TEST_P(TouchIntegrationTest, ExternalStylusConnectedDuringTouchGesture) {
    const Point centerPoint = mDevice->getCenterPoint();

    // Down
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendDown(centerPoint);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_DOWN)));

    // Move
    mDevice->sendMove(centerPoint + Point(1, 1));
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_MOVE)));

    // Connecting an external stylus mid-gesture should not interrupt the ongoing gesture stream.
    auto externalStylus = createUinputDevice<UinputExternalStylus>();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
    const auto stylusInfo = waitForDevice(externalStylus->getName());
    ASSERT_TRUE(stylusInfo);

    // Move
    mDevice->sendMove(centerPoint + Point(2, 2));
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_MOVE)));

    // Disconnecting an external stylus mid-gesture should not interrupt the ongoing gesture stream.
    externalStylus.reset();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasNotCalled());

    // Up
    mDevice->sendUp();
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(
            mTestListener->assertNotifyMotionWasCalled(WithMotionAction(AMOTION_EVENT_ACTION_UP)));

    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasNotCalled());
}

INSTANTIATE_TEST_SUITE_P(TouchIntegrationTestDisplayVariants, TouchIntegrationTest,
                         testing::Values(TouchIntegrationTestDisplays::DISPLAY_INTERNAL,
                                         TouchIntegrationTestDisplays::DISPLAY_INPUT_PORT,
                                         TouchIntegrationTestDisplays::DISPLAY_UNIQUE_ID));

// --- StylusButtonIntegrationTest ---

// Verify the behavior of button presses reported by various kinds of styluses, including buttons
// reported by the touchscreen's device, by a fused external stylus, and by an un-fused external
// stylus.
template <typename UinputStylusDevice>
class StylusButtonIntegrationTest : public BaseTouchIntegrationTest {
protected:
    void SetUp() override {
#if !defined(__ANDROID__)
        GTEST_SKIP();
#endif
        BaseTouchIntegrationTest::SetUp();
        mTouchscreen = mDevice.get();
        mTouchscreenInfo = mDeviceInfo;

        setUpStylusDevice();
    }

    UinputStylusDevice* mStylus{nullptr};
    InputDeviceInfo mStylusInfo{};

    UinputTouchScreen* mTouchscreen{nullptr};
    InputDeviceInfo mTouchscreenInfo{};

private:
    // When we are attempting to test stylus button events that are sent from the touchscreen,
    // use the same Uinput device for the touchscreen and the stylus.
    template <typename T = UinputStylusDevice>
    std::enable_if_t<std::is_same_v<UinputTouchScreen, T>, void> setUpStylusDevice() {
        mStylus = mDevice.get();
        mStylusInfo = mDeviceInfo;
    }

    // When we are attempting to stylus buttons from an external stylus being merged with touches
    // from a touchscreen, create a new Uinput device through which stylus buttons can be injected.
    template <typename T = UinputStylusDevice>
    std::enable_if_t<!std::is_same_v<UinputTouchScreen, T>, void> setUpStylusDevice() {
        mStylusDeviceLifecycleTracker = createUinputDevice<T>();
        mStylus = mStylusDeviceLifecycleTracker.get();
        ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
        ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
        const auto info = waitForDevice(mStylus->getName());
        ASSERT_TRUE(info);
        mStylusInfo = *info;
    }

    std::unique_ptr<UinputStylusDevice> mStylusDeviceLifecycleTracker{};

    // Hide the base class's device to expose it with a different name for readability.
    using BaseTouchIntegrationTest::mDevice;
    using BaseTouchIntegrationTest::mDeviceInfo;
};

using StylusButtonIntegrationTestTypes =
        ::testing::Types<UinputTouchScreen, UinputExternalStylus, UinputExternalStylusWithPressure>;
TYPED_TEST_SUITE(StylusButtonIntegrationTest, StylusButtonIntegrationTestTypes);

TYPED_TEST(StylusButtonIntegrationTest, StylusButtonsGenerateKeyEvents) {
    const auto stylusId = TestFixture::mStylusInfo.getId();

    TestFixture::mStylus->pressKey(BTN_STYLUS);
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyKeyWasCalled(
            AllOf(WithKeyAction(AKEY_EVENT_ACTION_DOWN), WithSource(AINPUT_SOURCE_KEYBOARD),
                  WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY), WithDeviceId(stylusId))));

    TestFixture::mStylus->releaseKey(BTN_STYLUS);
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyKeyWasCalled(
            AllOf(WithKeyAction(AKEY_EVENT_ACTION_UP), WithSource(AINPUT_SOURCE_KEYBOARD),
                  WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY), WithDeviceId(stylusId))));
}

TYPED_TEST(StylusButtonIntegrationTest, StylusButtonsSurroundingTouchGesture) {
    const Point centerPoint = TestFixture::mTouchscreen->getCenterPoint();
    const auto touchscreenId = TestFixture::mTouchscreenInfo.getId();
    const auto stylusId = TestFixture::mStylusInfo.getId();

    // Press the stylus button.
    TestFixture::mStylus->pressKey(BTN_STYLUS);
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyKeyWasCalled(
            AllOf(WithKeyAction(AKEY_EVENT_ACTION_DOWN), WithSource(AINPUT_SOURCE_KEYBOARD),
                  WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY), WithDeviceId(stylusId))));

    // Start and finish a stylus gesture.
    TestFixture::mTouchscreen->sendSlot(FIRST_SLOT);
    TestFixture::mTouchscreen->sendTrackingId(FIRST_TRACKING_ID);
    TestFixture::mTouchscreen->sendToolType(MT_TOOL_PEN);
    TestFixture::mTouchscreen->sendDown(centerPoint);
    TestFixture::mTouchscreen->sendSync();
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithToolType(ToolType::STYLUS),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY),
                  WithDeviceId(touchscreenId))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                  WithToolType(ToolType::STYLUS),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY),
                  WithDeviceId(touchscreenId))));

    TestFixture::mTouchscreen->sendTrackingId(INVALID_TRACKING_ID);
    TestFixture::mTouchscreen->sendSync();
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                  WithToolType(ToolType::STYLUS), WithButtonState(0),
                  WithDeviceId(touchscreenId))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                  WithToolType(ToolType::STYLUS), WithButtonState(0),
                  WithDeviceId(touchscreenId))));

    // Release the stylus button.
    TestFixture::mStylus->releaseKey(BTN_STYLUS);
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyKeyWasCalled(
            AllOf(WithKeyAction(AKEY_EVENT_ACTION_UP), WithSource(AINPUT_SOURCE_KEYBOARD),
                  WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY), WithDeviceId(stylusId))));
}

TYPED_TEST(StylusButtonIntegrationTest, StylusButtonsSurroundingHoveringTouchGesture) {
    const Point centerPoint = TestFixture::mTouchscreen->getCenterPoint();
    const auto touchscreenId = TestFixture::mTouchscreenInfo.getId();
    const auto stylusId = TestFixture::mStylusInfo.getId();
    auto toolTypeDevice =
            AllOf(WithToolType(ToolType::STYLUS), WithDeviceId(touchscreenId));

    // Press the stylus button.
    TestFixture::mStylus->pressKey(BTN_STYLUS);
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyKeyWasCalled(
            AllOf(WithKeyAction(AKEY_EVENT_ACTION_DOWN), WithSource(AINPUT_SOURCE_KEYBOARD),
                  WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY), WithDeviceId(stylusId))));

    // Start hovering with the stylus.
    TestFixture::mTouchscreen->sendSlot(FIRST_SLOT);
    TestFixture::mTouchscreen->sendTrackingId(FIRST_TRACKING_ID);
    TestFixture::mTouchscreen->sendToolType(MT_TOOL_PEN);
    TestFixture::mTouchscreen->sendMove(centerPoint);
    TestFixture::mTouchscreen->sendSync();
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeDevice, WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeDevice, WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeDevice, WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));

    // Touch down with the stylus.
    TestFixture::mTouchscreen->sendTrackingId(FIRST_TRACKING_ID);
    TestFixture::mTouchscreen->sendToolType(MT_TOOL_PEN);
    TestFixture::mTouchscreen->sendDown(centerPoint);
    TestFixture::mTouchscreen->sendSync();
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeDevice, WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));

    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeDevice, WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));

    // Stop touching with the stylus, and start hovering.
    TestFixture::mTouchscreen->sendUp();
    TestFixture::mTouchscreen->sendTrackingId(FIRST_TRACKING_ID);
    TestFixture::mTouchscreen->sendToolType(MT_TOOL_PEN);
    TestFixture::mTouchscreen->sendMove(centerPoint);
    TestFixture::mTouchscreen->sendSync();
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeDevice, WithMotionAction(AMOTION_EVENT_ACTION_UP),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeDevice, WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeDevice, WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));

    // Stop hovering.
    TestFixture::mTouchscreen->sendTrackingId(INVALID_TRACKING_ID);
    TestFixture::mTouchscreen->sendSync();
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeDevice, WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                  WithButtonState(0))));
    // TODO(b/257971675): Fix inconsistent button state when exiting hover.
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeDevice, WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));

    // Release the stylus button.
    TestFixture::mStylus->releaseKey(BTN_STYLUS);
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyKeyWasCalled(
            AllOf(WithKeyAction(AKEY_EVENT_ACTION_UP), WithSource(AINPUT_SOURCE_KEYBOARD),
                  WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY), WithDeviceId(stylusId))));
}

TYPED_TEST(StylusButtonIntegrationTest, StylusButtonsWithinTouchGesture) {
    const Point centerPoint = TestFixture::mTouchscreen->getCenterPoint();
    const auto touchscreenId = TestFixture::mTouchscreenInfo.getId();
    const auto stylusId = TestFixture::mStylusInfo.getId();

    // Start a stylus gesture.
    TestFixture::mTouchscreen->sendSlot(FIRST_SLOT);
    TestFixture::mTouchscreen->sendTrackingId(FIRST_TRACKING_ID);
    TestFixture::mTouchscreen->sendToolType(MT_TOOL_PEN);
    TestFixture::mTouchscreen->sendDown(centerPoint);
    TestFixture::mTouchscreen->sendSync();
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithToolType(ToolType::STYLUS), WithButtonState(0),
                  WithDeviceId(touchscreenId))));

    // Press and release a stylus button. Each change in button state also generates a MOVE event.
    TestFixture::mStylus->pressKey(BTN_STYLUS);
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyKeyWasCalled(
            AllOf(WithKeyAction(AKEY_EVENT_ACTION_DOWN), WithSource(AINPUT_SOURCE_KEYBOARD),
                  WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY), WithDeviceId(stylusId))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithToolType(ToolType::STYLUS),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY),
                  WithDeviceId(touchscreenId))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                  WithToolType(ToolType::STYLUS),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY),
                  WithDeviceId(touchscreenId))));

    TestFixture::mStylus->releaseKey(BTN_STYLUS);
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyKeyWasCalled(
            AllOf(WithKeyAction(AKEY_EVENT_ACTION_UP), WithSource(AINPUT_SOURCE_KEYBOARD),
                  WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY), WithDeviceId(stylusId))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                  WithToolType(ToolType::STYLUS), WithButtonState(0),
                  WithDeviceId(touchscreenId))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithToolType(ToolType::STYLUS), WithButtonState(0),
                  WithDeviceId(touchscreenId))));

    // Finish the stylus gesture.
    TestFixture::mTouchscreen->sendTrackingId(INVALID_TRACKING_ID);
    TestFixture::mTouchscreen->sendSync();
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                  WithToolType(ToolType::STYLUS), WithButtonState(0),
                  WithDeviceId(touchscreenId))));
}

TYPED_TEST(StylusButtonIntegrationTest, StylusButtonMotionEventsDisabled) {
    TestFixture::mFakePolicy->setStylusButtonMotionEventsEnabled(false);
    TestFixture::mReader->requestRefreshConfiguration(
            InputReaderConfiguration::Change::STYLUS_BUTTON_REPORTING);

    const Point centerPoint = TestFixture::mTouchscreen->getCenterPoint();
    const auto touchscreenId = TestFixture::mTouchscreenInfo.getId();
    const auto stylusId = TestFixture::mStylusInfo.getId();

    // Start a stylus gesture. By the time this event is processed, the configuration change that
    // was requested is guaranteed to be completed.
    TestFixture::mTouchscreen->sendSlot(FIRST_SLOT);
    TestFixture::mTouchscreen->sendTrackingId(FIRST_TRACKING_ID);
    TestFixture::mTouchscreen->sendToolType(MT_TOOL_PEN);
    TestFixture::mTouchscreen->sendDown(centerPoint);
    TestFixture::mTouchscreen->sendSync();
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithToolType(ToolType::STYLUS), WithButtonState(0),
                  WithDeviceId(touchscreenId))));

    // Press and release a stylus button. Each change only generates a MOVE motion event.
    // Key events are unaffected.
    TestFixture::mStylus->pressKey(BTN_STYLUS);
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyKeyWasCalled(
            AllOf(WithKeyAction(AKEY_EVENT_ACTION_DOWN), WithSource(AINPUT_SOURCE_KEYBOARD),
                  WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY), WithDeviceId(stylusId))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithToolType(ToolType::STYLUS), WithButtonState(0),
                  WithDeviceId(touchscreenId))));

    TestFixture::mStylus->releaseKey(BTN_STYLUS);
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyKeyWasCalled(
            AllOf(WithKeyAction(AKEY_EVENT_ACTION_UP), WithSource(AINPUT_SOURCE_KEYBOARD),
                  WithKeyCode(AKEYCODE_STYLUS_BUTTON_PRIMARY), WithDeviceId(stylusId))));
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithToolType(ToolType::STYLUS), WithButtonState(0),
                  WithDeviceId(touchscreenId))));

    // Finish the stylus gesture.
    TestFixture::mTouchscreen->sendTrackingId(INVALID_TRACKING_ID);
    TestFixture::mTouchscreen->sendSync();
    ASSERT_NO_FATAL_FAILURE(TestFixture::mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                  WithToolType(ToolType::STYLUS), WithButtonState(0),
                  WithDeviceId(touchscreenId))));
}

// --- ExternalStylusIntegrationTest ---

// Verify the behavior of an external stylus. An external stylus can report pressure or button
// data independently of the touchscreen, which is then sent as a MotionEvent as part of an
// ongoing stylus gesture that is being emitted by the touchscreen.
using ExternalStylusIntegrationTest = BaseTouchIntegrationTest;

TEST_F(ExternalStylusIntegrationTest, ExternalStylusConnectionChangesTouchscreenSource) {
    // Create an external stylus capable of reporting pressure data that
    // should be fused with a touch pointer.
    std::unique_ptr<UinputExternalStylusWithPressure> stylus =
            createUinputDevice<UinputExternalStylusWithPressure>();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
    const auto stylusInfo = waitForDevice(stylus->getName());
    ASSERT_TRUE(stylusInfo);

    // Connecting an external stylus changes the source of the touchscreen.
    const auto deviceInfo = waitForDevice(mDevice->getName());
    ASSERT_TRUE(deviceInfo);
    ASSERT_TRUE(isFromSource(deviceInfo->getSources(), STYLUS_FUSION_SOURCE));
}

TEST_F(ExternalStylusIntegrationTest, FusedExternalStylusPressureReported) {
    const Point centerPoint = mDevice->getCenterPoint();

    // Create an external stylus capable of reporting pressure data that
    // should be fused with a touch pointer.
    std::unique_ptr<UinputExternalStylusWithPressure> stylus =
            createUinputDevice<UinputExternalStylusWithPressure>();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
    const auto stylusInfo = waitForDevice(stylus->getName());
    ASSERT_TRUE(stylusInfo);

    ASSERT_EQ(AINPUT_SOURCE_STYLUS | AINPUT_SOURCE_KEYBOARD, stylusInfo->getSources());

    const auto touchscreenId = mDeviceInfo.getId();

    // Set a pressure value on the stylus. It doesn't generate any events.
    const auto& RAW_PRESSURE_MAX = UinputExternalStylusWithPressure::RAW_PRESSURE_MAX;
    stylus->setPressure(100);
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasNotCalled());

    // Start a finger gesture, and ensure it shows up as stylus gesture
    // with the pressure set by the external stylus.
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendToolType(MT_TOOL_FINGER);
    mDevice->sendDown(centerPoint);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithToolType(ToolType::STYLUS),
                  WithButtonState(0), WithSource(STYLUS_FUSION_SOURCE), WithDeviceId(touchscreenId),
                  WithPressure(100.f / RAW_PRESSURE_MAX))));

    // Change the pressure on the external stylus, and ensure the touchscreen generates a MOVE
    // event with the updated pressure.
    stylus->setPressure(200);
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithToolType(ToolType::STYLUS),
                  WithButtonState(0), WithSource(STYLUS_FUSION_SOURCE), WithDeviceId(touchscreenId),
                  WithPressure(200.f / RAW_PRESSURE_MAX))));

    // The external stylus did not generate any events.
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasNotCalled());
}

TEST_F(ExternalStylusIntegrationTest, FusedExternalStylusPressureNotReported) {
    const Point centerPoint = mDevice->getCenterPoint();

    // Create an external stylus capable of reporting pressure data that
    // should be fused with a touch pointer.
    std::unique_ptr<UinputExternalStylusWithPressure> stylus =
            createUinputDevice<UinputExternalStylusWithPressure>();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
    const auto stylusInfo = waitForDevice(stylus->getName());
    ASSERT_TRUE(stylusInfo);

    ASSERT_EQ(AINPUT_SOURCE_STYLUS | AINPUT_SOURCE_KEYBOARD, stylusInfo->getSources());

    const auto touchscreenId = mDeviceInfo.getId();

    // Set a pressure value of 0 on the stylus. It doesn't generate any events.
    const auto& RAW_PRESSURE_MAX = UinputExternalStylusWithPressure::RAW_PRESSURE_MAX;
    // Send a non-zero value first to prevent the kernel from consuming the zero event.
    stylus->setPressure(100);
    stylus->setPressure(0);
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasNotCalled());

    // Start a finger gesture. The touch device will withhold generating any touches for
    // up to 72 milliseconds while waiting for pressure data from the external stylus.
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendToolType(MT_TOOL_FINGER);
    mDevice->sendDown(centerPoint);
    const auto syncTime = std::chrono::system_clock::now();
    // After 72 ms, the event *will* be generated. If we wait the full 72 ms to check that NO event
    // is generated in that period, there will be a race condition between the event being generated
    // and the test's wait timeout expiring. Thus, we wait for a shorter duration in the test, which
    // will reduce the liklihood of the race condition occurring.
    const auto waitUntilTimeForNoEvent =
            syncTime + std::chrono::milliseconds(ns2ms(EXTERNAL_STYLUS_DATA_TIMEOUT / 2));
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasNotCalled(waitUntilTimeForNoEvent));

    // Since the external stylus did not report a pressure value within the timeout,
    // it shows up as a finger pointer.
    const auto waitUntilTimeForEvent = syncTime +
            std::chrono::milliseconds(ns2ms(EXTERNAL_STYLUS_DATA_TIMEOUT)) + EVENT_HAPPENED_TIMEOUT;
    ASSERT_NO_FATAL_FAILURE(
            mTestListener->assertNotifyMotionWasCalled(AllOf(WithMotionAction(
                                                                     AMOTION_EVENT_ACTION_DOWN),
                                                             WithSource(AINPUT_SOURCE_TOUCHSCREEN |
                                                                        AINPUT_SOURCE_STYLUS),
                                                             WithToolType(ToolType::FINGER),
                                                             WithDeviceId(touchscreenId),
                                                             WithPressure(1.f)),
                                                       waitUntilTimeForEvent));

    // Change the pressure on the external stylus. Since the pressure was not present at the start
    // of the gesture, it is ignored for now.
    stylus->setPressure(200);
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasNotCalled());

    // Finish the finger gesture.
    mDevice->sendTrackingId(INVALID_TRACKING_ID);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                  WithSource(AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_STYLUS),
                  WithToolType(ToolType::FINGER))));

    // Start a new gesture. Since we have a valid pressure value, it shows up as a stylus.
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendToolType(MT_TOOL_FINGER);
    mDevice->sendDown(centerPoint);
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithSource(STYLUS_FUSION_SOURCE),
                  WithToolType(ToolType::STYLUS), WithButtonState(0), WithDeviceId(touchscreenId),
                  WithPressure(200.f / RAW_PRESSURE_MAX))));

    // The external stylus did not generate any events.
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasNotCalled());
}

TEST_F(ExternalStylusIntegrationTest, UnfusedExternalStylus) {
    const Point centerPoint = mDevice->getCenterPoint();

    // Create an external stylus device that does not support pressure. It should not affect any
    // touch pointers.
    std::unique_ptr<UinputExternalStylus> stylus = createUinputDevice<UinputExternalStylus>();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertInputDevicesChanged());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyConfigurationChangedWasCalled());
    const auto stylusInfo = waitForDevice(stylus->getName());
    ASSERT_TRUE(stylusInfo);

    ASSERT_EQ(AINPUT_SOURCE_STYLUS | AINPUT_SOURCE_KEYBOARD, stylusInfo->getSources());

    const auto touchscreenId = mDeviceInfo.getId();

    // Start a finger gesture and ensure a finger pointer is generated for it, without waiting for
    // pressure data from the external stylus.
    mDevice->sendSlot(FIRST_SLOT);
    mDevice->sendTrackingId(FIRST_TRACKING_ID);
    mDevice->sendToolType(MT_TOOL_FINGER);
    mDevice->sendDown(centerPoint);
    auto waitUntil = std::chrono::system_clock::now() +
            std::chrono::milliseconds(ns2ms(EXTERNAL_STYLUS_DATA_TIMEOUT));
    mDevice->sendSync();
    ASSERT_NO_FATAL_FAILURE(
            mTestListener->assertNotifyMotionWasCalled(AllOf(WithMotionAction(
                                                                     AMOTION_EVENT_ACTION_DOWN),
                                                             WithToolType(ToolType::FINGER),
                                                             WithSource(AINPUT_SOURCE_TOUCHSCREEN |
                                                                        AINPUT_SOURCE_STYLUS),
                                                             WithButtonState(0),
                                                             WithDeviceId(touchscreenId),
                                                             WithPressure(1.f)),
                                                       waitUntil));

    // The external stylus did not generate any events.
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyMotionWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mTestListener->assertNotifyKeyWasNotCalled());
}

// --- InputDeviceTest ---
class InputDeviceTest : public testing::Test {
protected:
    static const char* DEVICE_NAME;
    static const char* DEVICE_LOCATION;
    static const int32_t DEVICE_ID;
    static const int32_t DEVICE_GENERATION;
    static const int32_t DEVICE_CONTROLLER_NUMBER;
    static const ftl::Flags<InputDeviceClass> DEVICE_CLASSES;
    static const int32_t EVENTHUB_ID;
    static const std::string DEVICE_BLUETOOTH_ADDRESS;

    std::shared_ptr<FakeEventHub> mFakeEventHub;
    sp<FakeInputReaderPolicy> mFakePolicy;
    std::unique_ptr<TestInputListener> mFakeListener;
    std::unique_ptr<InstrumentedInputReader> mReader;
    std::shared_ptr<InputDevice> mDevice;

    void SetUp() override {
        mFakeEventHub = std::make_unique<FakeEventHub>();
        mFakePolicy = sp<FakeInputReaderPolicy>::make();
        mFakeListener = std::make_unique<TestInputListener>();
        mReader = std::make_unique<InstrumentedInputReader>(mFakeEventHub, mFakePolicy,
                                                            *mFakeListener);
        InputDeviceIdentifier identifier;
        identifier.name = DEVICE_NAME;
        identifier.location = DEVICE_LOCATION;
        identifier.bluetoothAddress = DEVICE_BLUETOOTH_ADDRESS;
        mDevice = std::make_shared<InputDevice>(mReader->getContext(), DEVICE_ID, DEVICE_GENERATION,
                                                identifier);
        mReader->pushNextDevice(mDevice);
        mFakeEventHub->addDevice(EVENTHUB_ID, DEVICE_NAME, ftl::Flags<InputDeviceClass>(0));
        mReader->loopOnce();
    }

    void TearDown() override {
        mFakeListener.reset();
        mFakePolicy.clear();
    }
};

const char* InputDeviceTest::DEVICE_NAME = "device";
const char* InputDeviceTest::DEVICE_LOCATION = "USB1";
const int32_t InputDeviceTest::DEVICE_ID = END_RESERVED_ID + 1000;
const int32_t InputDeviceTest::DEVICE_GENERATION = 2;
const int32_t InputDeviceTest::DEVICE_CONTROLLER_NUMBER = 0;
const ftl::Flags<InputDeviceClass> InputDeviceTest::DEVICE_CLASSES =
        InputDeviceClass::KEYBOARD | InputDeviceClass::TOUCH | InputDeviceClass::JOYSTICK;
const int32_t InputDeviceTest::EVENTHUB_ID = 1;
const std::string InputDeviceTest::DEVICE_BLUETOOTH_ADDRESS = "11:AA:22:BB:33:CC";

TEST_F(InputDeviceTest, ImmutableProperties) {
    ASSERT_EQ(DEVICE_ID, mDevice->getId());
    ASSERT_STREQ(DEVICE_NAME, mDevice->getName().c_str());
    ASSERT_EQ(ftl::Flags<InputDeviceClass>(0), mDevice->getClasses());
}

TEST_F(InputDeviceTest, WhenDeviceCreated_EnabledIsFalse) {
    ASSERT_EQ(mDevice->isEnabled(), false);
}

TEST_F(InputDeviceTest, WhenNoMappersAreRegistered_DeviceIsIgnored) {
    // Configuration.
    InputReaderConfiguration config;
    std::list<NotifyArgs> unused = mDevice->configure(ARBITRARY_TIME, config, /*changes=*/{});

    // Reset.
    unused += mDevice->reset(ARBITRARY_TIME);

    NotifyDeviceResetArgs resetArgs;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_EQ(ARBITRARY_TIME, resetArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, resetArgs.deviceId);

    // Metadata.
    ASSERT_TRUE(mDevice->isIgnored());
    ASSERT_EQ(AINPUT_SOURCE_UNKNOWN, mDevice->getSources());

    InputDeviceInfo info = mDevice->getDeviceInfo();
    ASSERT_EQ(DEVICE_ID, info.getId());
    ASSERT_STREQ(DEVICE_NAME, info.getIdentifier().name.c_str());
    ASSERT_EQ(AINPUT_KEYBOARD_TYPE_NONE, info.getKeyboardType());
    ASSERT_EQ(AINPUT_SOURCE_UNKNOWN, info.getSources());

    // State queries.
    ASSERT_EQ(0, mDevice->getMetaState());

    ASSERT_EQ(AKEY_STATE_UNKNOWN, mDevice->getKeyCodeState(AINPUT_SOURCE_KEYBOARD, 0))
            << "Ignored device should return unknown key code state.";
    ASSERT_EQ(AKEY_STATE_UNKNOWN, mDevice->getScanCodeState(AINPUT_SOURCE_KEYBOARD, 0))
            << "Ignored device should return unknown scan code state.";
    ASSERT_EQ(AKEY_STATE_UNKNOWN, mDevice->getSwitchState(AINPUT_SOURCE_KEYBOARD, 0))
            << "Ignored device should return unknown switch state.";

    const std::vector<int32_t> keyCodes{AKEYCODE_A, AKEYCODE_B};
    uint8_t flags[2] = { 0, 1 };
    ASSERT_FALSE(mDevice->markSupportedKeyCodes(AINPUT_SOURCE_KEYBOARD, keyCodes, flags))
            << "Ignored device should never mark any key codes.";
    ASSERT_EQ(0, flags[0]) << "Flag for unsupported key should be unchanged.";
    ASSERT_EQ(1, flags[1]) << "Flag for unsupported key should be unchanged.";
}

TEST_F(InputDeviceTest, WhenMappersAreRegistered_DeviceIsNotIgnoredAndForwardsRequestsToMappers) {
    // Configuration.
    mFakeEventHub->addConfigurationProperty(EVENTHUB_ID, "key", "value");

    FakeInputMapper& mapper1 =
            mDevice->addMapper<FakeInputMapper>(EVENTHUB_ID, mFakePolicy->getReaderConfiguration(),
                                                AINPUT_SOURCE_KEYBOARD);
    mapper1.setKeyboardType(AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    mapper1.setMetaState(AMETA_ALT_ON);
    mapper1.addSupportedKeyCode(AKEYCODE_A);
    mapper1.addSupportedKeyCode(AKEYCODE_B);
    mapper1.setKeyCodeState(AKEYCODE_A, AKEY_STATE_DOWN);
    mapper1.setKeyCodeState(AKEYCODE_B, AKEY_STATE_UP);
    mapper1.setScanCodeState(2, AKEY_STATE_DOWN);
    mapper1.setScanCodeState(3, AKEY_STATE_UP);
    mapper1.setSwitchState(4, AKEY_STATE_DOWN);

    FakeInputMapper& mapper2 =
            mDevice->addMapper<FakeInputMapper>(EVENTHUB_ID, mFakePolicy->getReaderConfiguration(),
                                                AINPUT_SOURCE_TOUCHSCREEN);
    mapper2.setMetaState(AMETA_SHIFT_ON);

    InputReaderConfiguration config;
    std::list<NotifyArgs> unused = mDevice->configure(ARBITRARY_TIME, config, /*changes=*/{});

    std::optional<std::string> propertyValue = mDevice->getConfiguration().getString("key");
    ASSERT_TRUE(propertyValue.has_value())
            << "Device should have read configuration during configuration phase.";
    ASSERT_EQ("value", *propertyValue);

    ASSERT_NO_FATAL_FAILURE(mapper1.assertConfigureWasCalled());
    ASSERT_NO_FATAL_FAILURE(mapper2.assertConfigureWasCalled());

    // Reset
    unused += mDevice->reset(ARBITRARY_TIME);
    ASSERT_NO_FATAL_FAILURE(mapper1.assertResetWasCalled());
    ASSERT_NO_FATAL_FAILURE(mapper2.assertResetWasCalled());

    NotifyDeviceResetArgs resetArgs;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_EQ(ARBITRARY_TIME, resetArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, resetArgs.deviceId);

    // Metadata.
    ASSERT_FALSE(mDevice->isIgnored());
    ASSERT_EQ(uint32_t(AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_TOUCHSCREEN), mDevice->getSources());

    InputDeviceInfo info = mDevice->getDeviceInfo();
    ASSERT_EQ(DEVICE_ID, info.getId());
    ASSERT_STREQ(DEVICE_NAME, info.getIdentifier().name.c_str());
    ASSERT_EQ(AINPUT_KEYBOARD_TYPE_ALPHABETIC, info.getKeyboardType());
    ASSERT_EQ(uint32_t(AINPUT_SOURCE_KEYBOARD | AINPUT_SOURCE_TOUCHSCREEN), info.getSources());

    // State queries.
    ASSERT_EQ(AMETA_ALT_ON | AMETA_SHIFT_ON, mDevice->getMetaState())
            << "Should query mappers and combine meta states.";

    ASSERT_EQ(AKEY_STATE_UNKNOWN, mDevice->getKeyCodeState(AINPUT_SOURCE_TRACKBALL, AKEYCODE_A))
            << "Should return unknown key code state when source not supported.";
    ASSERT_EQ(AKEY_STATE_UNKNOWN, mDevice->getScanCodeState(AINPUT_SOURCE_TRACKBALL, AKEYCODE_A))
            << "Should return unknown scan code state when source not supported.";
    ASSERT_EQ(AKEY_STATE_UNKNOWN, mDevice->getSwitchState(AINPUT_SOURCE_TRACKBALL, AKEYCODE_A))
            << "Should return unknown switch state when source not supported.";

    ASSERT_EQ(AKEY_STATE_DOWN, mDevice->getKeyCodeState(AINPUT_SOURCE_KEYBOARD, AKEYCODE_A))
            << "Should query mapper when source is supported.";
    ASSERT_EQ(AKEY_STATE_UP, mDevice->getScanCodeState(AINPUT_SOURCE_KEYBOARD, 3))
            << "Should query mapper when source is supported.";
    ASSERT_EQ(AKEY_STATE_DOWN, mDevice->getSwitchState(AINPUT_SOURCE_KEYBOARD, 4))
            << "Should query mapper when source is supported.";

    const std::vector<int32_t> keyCodes{AKEYCODE_A, AKEYCODE_B, AKEYCODE_1, AKEYCODE_2};
    uint8_t flags[4] = { 0, 0, 0, 1 };
    ASSERT_FALSE(mDevice->markSupportedKeyCodes(AINPUT_SOURCE_TRACKBALL, keyCodes, flags))
            << "Should do nothing when source is unsupported.";
    ASSERT_EQ(0, flags[0]) << "Flag should be unchanged when source is unsupported.";
    ASSERT_EQ(0, flags[1]) << "Flag should be unchanged when source is unsupported.";
    ASSERT_EQ(0, flags[2]) << "Flag should be unchanged when source is unsupported.";
    ASSERT_EQ(1, flags[3]) << "Flag should be unchanged when source is unsupported.";

    ASSERT_TRUE(mDevice->markSupportedKeyCodes(AINPUT_SOURCE_KEYBOARD, keyCodes, flags))
            << "Should query mapper when source is supported.";
    ASSERT_EQ(1, flags[0]) << "Flag for supported key should be set.";
    ASSERT_EQ(1, flags[1]) << "Flag for supported key should be set.";
    ASSERT_EQ(0, flags[2]) << "Flag for unsupported key should be unchanged.";
    ASSERT_EQ(1, flags[3]) << "Flag for unsupported key should be unchanged.";

    // Event handling.
    RawEvent event;
    event.deviceId = EVENTHUB_ID;
    unused += mDevice->process(&event, 1);

    ASSERT_NO_FATAL_FAILURE(mapper1.assertProcessWasCalled());
    ASSERT_NO_FATAL_FAILURE(mapper2.assertProcessWasCalled());
}

TEST_F(InputDeviceTest, Configure_SmoothScrollViewBehaviorNotSet) {
    // Set some behavior to force the configuration to be update.
    mFakeEventHub->addConfigurationProperty(EVENTHUB_ID, "device.wake", "1");
    mDevice->addMapper<FakeInputMapper>(EVENTHUB_ID, mFakePolicy->getReaderConfiguration(),
                                        AINPUT_SOURCE_KEYBOARD);

    std::list<NotifyArgs> unused =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});

    ASSERT_FALSE(mDevice->getDeviceInfo().getViewBehavior().shouldSmoothScroll.has_value());
}

TEST_F(InputDeviceTest, Configure_SmoothScrollViewBehaviorEnabled) {
    mFakeEventHub->addConfigurationProperty(EVENTHUB_ID, "device.viewBehavior_smoothScroll", "1");
    mDevice->addMapper<FakeInputMapper>(EVENTHUB_ID, mFakePolicy->getReaderConfiguration(),
                                        AINPUT_SOURCE_KEYBOARD);

    std::list<NotifyArgs> unused =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});

    ASSERT_TRUE(mDevice->getDeviceInfo().getViewBehavior().shouldSmoothScroll.value_or(false));
}

TEST_F(InputDeviceTest, WakeDevice_AddsWakeFlagToProcessNotifyArgs) {
    mFakeEventHub->addConfigurationProperty(EVENTHUB_ID, "device.wake", "1");
    FakeInputMapper& mapper =
            mDevice->addMapper<FakeInputMapper>(EVENTHUB_ID, mFakePolicy->getReaderConfiguration(),
                                                AINPUT_SOURCE_KEYBOARD);
    NotifyMotionArgs args1;
    NotifySwitchArgs args2;
    NotifyKeyArgs args3;
    mapper.setProcessResult({args1, args2, args3});

    InputReaderConfiguration config;
    std::list<NotifyArgs> unused = mDevice->configure(ARBITRARY_TIME, config, /*changes=*/{});

    RawEvent event;
    event.deviceId = EVENTHUB_ID;
    std::list<NotifyArgs> notifyArgs = mDevice->process(&event, 1);

    for (auto& arg : notifyArgs) {
        if (const auto notifyMotionArgs = std::get_if<NotifyMotionArgs>(&arg)) {
            ASSERT_EQ(POLICY_FLAG_WAKE, notifyMotionArgs->policyFlags);
        } else if (const auto notifySwitchArgs = std::get_if<NotifySwitchArgs>(&arg)) {
            ASSERT_EQ(POLICY_FLAG_WAKE, notifySwitchArgs->policyFlags);
        } else if (const auto notifyKeyArgs = std::get_if<NotifyKeyArgs>(&arg)) {
            ASSERT_EQ(POLICY_FLAG_WAKE, notifyKeyArgs->policyFlags);
        }
    }
}

TEST_F(InputDeviceTest, NotWakeDevice_DoesNotAddWakeFlagToProcessNotifyArgs) {
    mFakeEventHub->addConfigurationProperty(EVENTHUB_ID, "device.wake", "0");
    FakeInputMapper& mapper =
            mDevice->addMapper<FakeInputMapper>(EVENTHUB_ID, mFakePolicy->getReaderConfiguration(),
                                                AINPUT_SOURCE_KEYBOARD);
    NotifyMotionArgs args;
    mapper.setProcessResult({args});

    InputReaderConfiguration config;
    std::list<NotifyArgs> unused = mDevice->configure(ARBITRARY_TIME, config, /*changes=*/{});

    RawEvent event;
    event.deviceId = EVENTHUB_ID;
    std::list<NotifyArgs> notifyArgs = mDevice->process(&event, 1);

    // POLICY_FLAG_WAKE is not added to the NotifyArgs.
    ASSERT_EQ(0u, std::get<NotifyMotionArgs>(notifyArgs.front()).policyFlags);
}

TEST_F(InputDeviceTest, NotWakeDevice_DoesNotRemoveExistingWakeFlagFromProcessNotifyArgs) {
    mFakeEventHub->addConfigurationProperty(EVENTHUB_ID, "device.wake", "0");
    FakeInputMapper& mapper =
            mDevice->addMapper<FakeInputMapper>(EVENTHUB_ID, mFakePolicy->getReaderConfiguration(),
                                                AINPUT_SOURCE_KEYBOARD);
    NotifyMotionArgs args;
    args.policyFlags = POLICY_FLAG_WAKE;
    mapper.setProcessResult({args});

    InputReaderConfiguration config;
    std::list<NotifyArgs> unused = mDevice->configure(ARBITRARY_TIME, config, /*changes=*/{});

    RawEvent event;
    event.deviceId = EVENTHUB_ID;
    std::list<NotifyArgs> notifyArgs = mDevice->process(&event, 1);

    // The POLICY_FLAG_WAKE is preserved, despite the device being a non-wake device.
    ASSERT_EQ(POLICY_FLAG_WAKE, std::get<NotifyMotionArgs>(notifyArgs.front()).policyFlags);
}

// A single input device is associated with a specific display. Check that:
// 1. Device is disabled if the viewport corresponding to the associated display is not found
// 2. Device is disabled when configure API is called
TEST_F(InputDeviceTest, Configure_AssignsDisplayPort) {
    mDevice->addMapper<FakeInputMapper>(EVENTHUB_ID, mFakePolicy->getReaderConfiguration(),
                                        AINPUT_SOURCE_TOUCHSCREEN);

    // First Configuration.
    std::list<NotifyArgs> unused =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});

    // Device should be enabled by default.
    ASSERT_TRUE(mDevice->isEnabled());

    // Prepare associated info.
    constexpr uint8_t hdmi = 1;
    const std::string UNIQUE_ID = "local:1";

    mFakePolicy->addInputPortAssociation(DEVICE_LOCATION, hdmi);
    unused += mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::DISPLAY_INFO);
    // Device should be disabled because it is associated with a specific display via
    // input port <-> display port association, but the corresponding display is not found
    ASSERT_FALSE(mDevice->isEnabled());

    // Prepare displays.
    mFakePolicy->addDisplayViewport(SECONDARY_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                    ui::ROTATION_0, /*isActive=*/true, UNIQUE_ID, hdmi,
                                    ViewportType::INTERNAL);
    unused += mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::DISPLAY_INFO);
    ASSERT_TRUE(mDevice->isEnabled());

    // Device should be disabled after set disable.
    mFakePolicy->addDisabledDevice(mDevice->getId());
    unused += mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::ENABLED_STATE);
    ASSERT_FALSE(mDevice->isEnabled());

    // Device should still be disabled even found the associated display.
    unused += mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::DISPLAY_INFO);
    ASSERT_FALSE(mDevice->isEnabled());
}

TEST_F(InputDeviceTest, Configure_AssignsDisplayUniqueId) {
    // Device should be enabled by default.
    mFakePolicy->clearViewports();
    mDevice->addMapper<FakeInputMapper>(EVENTHUB_ID, mFakePolicy->getReaderConfiguration(),
                                        AINPUT_SOURCE_KEYBOARD);
    std::list<NotifyArgs> unused =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});
    ASSERT_TRUE(mDevice->isEnabled());

    // Device should be disabled because it is associated with a specific display, but the
    // corresponding display is not found.
    mFakePolicy->addInputUniqueIdAssociation(DEVICE_LOCATION, DISPLAY_UNIQUE_ID);
    unused += mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::DISPLAY_INFO);
    ASSERT_FALSE(mDevice->isEnabled());

    // Device should be enabled when a display is found.
    mFakePolicy->addDisplayViewport(SECONDARY_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                    ui::ROTATION_0, /* isActive= */ true, DISPLAY_UNIQUE_ID,
                                    NO_PORT, ViewportType::INTERNAL);
    unused += mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::DISPLAY_INFO);
    ASSERT_TRUE(mDevice->isEnabled());

    // Device should be disabled after set disable.
    mFakePolicy->addDisabledDevice(mDevice->getId());
    unused += mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::ENABLED_STATE);
    ASSERT_FALSE(mDevice->isEnabled());

    // Device should still be disabled even found the associated display.
    unused += mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::DISPLAY_INFO);
    ASSERT_FALSE(mDevice->isEnabled());
}

TEST_F(InputDeviceTest, Configure_UniqueId_CorrectlyMatches) {
    mFakePolicy->clearViewports();
    mDevice->addMapper<FakeInputMapper>(EVENTHUB_ID, mFakePolicy->getReaderConfiguration(),
                                        AINPUT_SOURCE_KEYBOARD);
    std::list<NotifyArgs> unused =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});

    mFakePolicy->addInputUniqueIdAssociation(DEVICE_LOCATION, DISPLAY_UNIQUE_ID);
    mFakePolicy->addDisplayViewport(SECONDARY_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                    ui::ROTATION_0, /* isActive= */ true, DISPLAY_UNIQUE_ID,
                                    NO_PORT, ViewportType::INTERNAL);
    const auto initialGeneration = mDevice->getGeneration();
    unused += mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::DISPLAY_INFO);
    ASSERT_EQ(DISPLAY_UNIQUE_ID, mDevice->getAssociatedDisplayUniqueId());
    ASSERT_GT(mDevice->getGeneration(), initialGeneration);
    ASSERT_EQ(mDevice->getDeviceInfo().getAssociatedDisplayId(), SECONDARY_DISPLAY_ID);
}

/**
 * This test reproduces a crash caused by a dangling reference that remains after device is added
 * and removed. The reference is accessed in InputDevice::dump(..);
 */
TEST_F(InputDeviceTest, DumpDoesNotCrash) {
    constexpr int32_t TEST_EVENTHUB_ID = 10;
    mFakeEventHub->addDevice(TEST_EVENTHUB_ID, "Test EventHub device", InputDeviceClass::BATTERY);

    InputDevice device(mReader->getContext(), /*id=*/1, /*generation=*/2, /*identifier=*/{});
    auto _ = device.addEventHubDevice(ARBITRARY_TIME, TEST_EVENTHUB_ID,
                                      mFakePolicy->getReaderConfiguration());
    device.removeEventHubDevice(TEST_EVENTHUB_ID);
    std::string dumpStr, eventHubDevStr;
    device.dump(dumpStr, eventHubDevStr);
}

TEST_F(InputDeviceTest, GetBluetoothAddress) {
    const auto& address = mReader->getBluetoothAddress(DEVICE_ID);
    ASSERT_TRUE(address);
    ASSERT_EQ(DEVICE_BLUETOOTH_ADDRESS, *address);
}

TEST_F(InputDeviceTest, KernelBufferOverflowResetsMappers) {
    mFakePolicy->clearViewports();
    FakeInputMapper& mapper =
            mDevice->addMapper<FakeInputMapper>(EVENTHUB_ID, mFakePolicy->getReaderConfiguration(),
                                                AINPUT_SOURCE_KEYBOARD);
    std::list<NotifyArgs> unused =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});

    mapper.assertConfigureWasCalled();
    mapper.assertResetWasNotCalled();

    RawEvent event{.when = ARBITRARY_TIME,
                   .readTime = ARBITRARY_TIME,
                   .deviceId = EVENTHUB_ID,
                   .type = EV_SYN,
                   .code = SYN_REPORT,
                   .value = 0};

    // Events are processed normally.
    unused = mDevice->process(&event, /*count=*/1);
    mapper.assertProcessWasCalled();

    // Simulate a kernel buffer overflow, which generates a SYN_DROPPED event.
    event.type = EV_SYN;
    event.code = SYN_DROPPED;
    event.value = 0;
    unused = mDevice->process(&event, /*count=*/1);
    mapper.assertProcessWasNotCalled();

    // All events until the next SYN_REPORT should be dropped.
    event.type = EV_KEY;
    event.code = KEY_A;
    event.value = 1;
    unused = mDevice->process(&event, /*count=*/1);
    mapper.assertProcessWasNotCalled();

    // We get the SYN_REPORT event now, which is not forwarded to mappers.
    // This should reset the mapper.
    event.type = EV_SYN;
    event.code = SYN_REPORT;
    event.value = 0;
    unused = mDevice->process(&event, /*count=*/1);
    mapper.assertProcessWasNotCalled();
    mapper.assertResetWasCalled();

    // The mapper receives events normally now.
    event.type = EV_KEY;
    event.code = KEY_B;
    event.value = 1;
    unused = mDevice->process(&event, /*count=*/1);
    mapper.assertProcessWasCalled();
}

// --- SwitchInputMapperTest ---

class SwitchInputMapperTest : public InputMapperTest {
protected:
};

TEST_F(SwitchInputMapperTest, GetSources) {
    SwitchInputMapper& mapper = constructAndAddMapper<SwitchInputMapper>();

    ASSERT_EQ(uint32_t(AINPUT_SOURCE_SWITCH), mapper.getSources());
}

TEST_F(SwitchInputMapperTest, GetSwitchState) {
    SwitchInputMapper& mapper = constructAndAddMapper<SwitchInputMapper>();

    mFakeEventHub->setSwitchState(EVENTHUB_ID, SW_LID, 1);
    ASSERT_EQ(1, mapper.getSwitchState(AINPUT_SOURCE_ANY, SW_LID));

    mFakeEventHub->setSwitchState(EVENTHUB_ID, SW_LID, 0);
    ASSERT_EQ(0, mapper.getSwitchState(AINPUT_SOURCE_ANY, SW_LID));
}

TEST_F(SwitchInputMapperTest, Process) {
    SwitchInputMapper& mapper = constructAndAddMapper<SwitchInputMapper>();
    std::list<NotifyArgs> out;
    out = process(mapper, ARBITRARY_TIME, READ_TIME, EV_SW, SW_LID, 1);
    ASSERT_TRUE(out.empty());
    out = process(mapper, ARBITRARY_TIME, READ_TIME, EV_SW, SW_JACK_PHYSICAL_INSERT, 1);
    ASSERT_TRUE(out.empty());
    out = process(mapper, ARBITRARY_TIME, READ_TIME, EV_SW, SW_HEADPHONE_INSERT, 0);
    ASSERT_TRUE(out.empty());
    out = process(mapper, ARBITRARY_TIME, READ_TIME, EV_SYN, SYN_REPORT, 0);

    ASSERT_EQ(1u, out.size());
    const NotifySwitchArgs& args = std::get<NotifySwitchArgs>(*out.begin());
    ASSERT_EQ(ARBITRARY_TIME, args.eventTime);
    ASSERT_EQ((1U << SW_LID) | (1U << SW_JACK_PHYSICAL_INSERT), args.switchValues);
    ASSERT_EQ((1U << SW_LID) | (1U << SW_JACK_PHYSICAL_INSERT) | (1 << SW_HEADPHONE_INSERT),
            args.switchMask);
    ASSERT_EQ(uint32_t(0), args.policyFlags);
}

// --- VibratorInputMapperTest ---
class VibratorInputMapperTest : public InputMapperTest {
protected:
    void SetUp() override { InputMapperTest::SetUp(DEVICE_CLASSES | InputDeviceClass::VIBRATOR); }
};

TEST_F(VibratorInputMapperTest, GetSources) {
    VibratorInputMapper& mapper = constructAndAddMapper<VibratorInputMapper>();

    ASSERT_EQ(AINPUT_SOURCE_UNKNOWN, mapper.getSources());
}

TEST_F(VibratorInputMapperTest, GetVibratorIds) {
    VibratorInputMapper& mapper = constructAndAddMapper<VibratorInputMapper>();

    ASSERT_EQ(mapper.getVibratorIds().size(), 2U);
}

TEST_F(VibratorInputMapperTest, Vibrate) {
    constexpr uint8_t DEFAULT_AMPLITUDE = 192;
    constexpr int32_t VIBRATION_TOKEN = 100;
    VibratorInputMapper& mapper = constructAndAddMapper<VibratorInputMapper>();

    VibrationElement pattern(2);
    VibrationSequence sequence(2);
    pattern.duration = std::chrono::milliseconds(200);
    pattern.channels = {{/*vibratorId=*/0, DEFAULT_AMPLITUDE / 2},
                        {/*vibratorId=*/1, DEFAULT_AMPLITUDE}};
    sequence.addElement(pattern);
    pattern.duration = std::chrono::milliseconds(500);
    pattern.channels = {{/*vibratorId=*/0, DEFAULT_AMPLITUDE / 4},
                        {/*vibratorId=*/1, DEFAULT_AMPLITUDE}};
    sequence.addElement(pattern);

    std::vector<int64_t> timings = {0, 1};
    std::vector<uint8_t> amplitudes = {DEFAULT_AMPLITUDE, DEFAULT_AMPLITUDE / 2};

    ASSERT_FALSE(mapper.isVibrating());
    // Start vibrating
    std::list<NotifyArgs> out = mapper.vibrate(sequence, /*repeat=*/-1, VIBRATION_TOKEN);
    ASSERT_TRUE(mapper.isVibrating());
    // Verify vibrator state listener was notified.
    mReader->loopOnce();
    ASSERT_EQ(1u, out.size());
    const NotifyVibratorStateArgs& vibrateArgs = std::get<NotifyVibratorStateArgs>(*out.begin());
    ASSERT_EQ(DEVICE_ID, vibrateArgs.deviceId);
    ASSERT_TRUE(vibrateArgs.isOn);
    // Stop vibrating
    out = mapper.cancelVibrate(VIBRATION_TOKEN);
    ASSERT_FALSE(mapper.isVibrating());
    // Verify vibrator state listener was notified.
    mReader->loopOnce();
    ASSERT_EQ(1u, out.size());
    const NotifyVibratorStateArgs& cancelArgs = std::get<NotifyVibratorStateArgs>(*out.begin());
    ASSERT_EQ(DEVICE_ID, cancelArgs.deviceId);
    ASSERT_FALSE(cancelArgs.isOn);
}

// --- SensorInputMapperTest ---

class SensorInputMapperTest : public InputMapperTest {
protected:
    static const int32_t ACCEL_RAW_MIN;
    static const int32_t ACCEL_RAW_MAX;
    static const int32_t ACCEL_RAW_FUZZ;
    static const int32_t ACCEL_RAW_FLAT;
    static const int32_t ACCEL_RAW_RESOLUTION;

    static const int32_t GYRO_RAW_MIN;
    static const int32_t GYRO_RAW_MAX;
    static const int32_t GYRO_RAW_FUZZ;
    static const int32_t GYRO_RAW_FLAT;
    static const int32_t GYRO_RAW_RESOLUTION;

    static const float GRAVITY_MS2_UNIT;
    static const float DEGREE_RADIAN_UNIT;

    void prepareAccelAxes();
    void prepareGyroAxes();
    void setAccelProperties();
    void setGyroProperties();
    void SetUp() override { InputMapperTest::SetUp(DEVICE_CLASSES | InputDeviceClass::SENSOR); }
};

const int32_t SensorInputMapperTest::ACCEL_RAW_MIN = -32768;
const int32_t SensorInputMapperTest::ACCEL_RAW_MAX = 32768;
const int32_t SensorInputMapperTest::ACCEL_RAW_FUZZ = 16;
const int32_t SensorInputMapperTest::ACCEL_RAW_FLAT = 0;
const int32_t SensorInputMapperTest::ACCEL_RAW_RESOLUTION = 8192;

const int32_t SensorInputMapperTest::GYRO_RAW_MIN = -2097152;
const int32_t SensorInputMapperTest::GYRO_RAW_MAX = 2097152;
const int32_t SensorInputMapperTest::GYRO_RAW_FUZZ = 16;
const int32_t SensorInputMapperTest::GYRO_RAW_FLAT = 0;
const int32_t SensorInputMapperTest::GYRO_RAW_RESOLUTION = 1024;

const float SensorInputMapperTest::GRAVITY_MS2_UNIT = 9.80665f;
const float SensorInputMapperTest::DEGREE_RADIAN_UNIT = 0.0174533f;

void SensorInputMapperTest::prepareAccelAxes() {
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_X, ACCEL_RAW_MIN, ACCEL_RAW_MAX, ACCEL_RAW_FUZZ,
                                   ACCEL_RAW_FLAT, ACCEL_RAW_RESOLUTION);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_Y, ACCEL_RAW_MIN, ACCEL_RAW_MAX, ACCEL_RAW_FUZZ,
                                   ACCEL_RAW_FLAT, ACCEL_RAW_RESOLUTION);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_Z, ACCEL_RAW_MIN, ACCEL_RAW_MAX, ACCEL_RAW_FUZZ,
                                   ACCEL_RAW_FLAT, ACCEL_RAW_RESOLUTION);
}

void SensorInputMapperTest::prepareGyroAxes() {
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_RX, GYRO_RAW_MIN, GYRO_RAW_MAX, GYRO_RAW_FUZZ,
                                   GYRO_RAW_FLAT, GYRO_RAW_RESOLUTION);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_RY, GYRO_RAW_MIN, GYRO_RAW_MAX, GYRO_RAW_FUZZ,
                                   GYRO_RAW_FLAT, GYRO_RAW_RESOLUTION);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_RZ, GYRO_RAW_MIN, GYRO_RAW_MAX, GYRO_RAW_FUZZ,
                                   GYRO_RAW_FLAT, GYRO_RAW_RESOLUTION);
}

void SensorInputMapperTest::setAccelProperties() {
    mFakeEventHub->addSensorAxis(EVENTHUB_ID, /* absCode */ 0, InputDeviceSensorType::ACCELEROMETER,
                                 /* sensorDataIndex */ 0);
    mFakeEventHub->addSensorAxis(EVENTHUB_ID, /* absCode */ 1, InputDeviceSensorType::ACCELEROMETER,
                                 /* sensorDataIndex */ 1);
    mFakeEventHub->addSensorAxis(EVENTHUB_ID, /* absCode */ 2, InputDeviceSensorType::ACCELEROMETER,
                                 /* sensorDataIndex */ 2);
    mFakeEventHub->setMscEvent(EVENTHUB_ID, MSC_TIMESTAMP);
    addConfigurationProperty("sensor.accelerometer.reportingMode", "0");
    addConfigurationProperty("sensor.accelerometer.maxDelay", "100000");
    addConfigurationProperty("sensor.accelerometer.minDelay", "5000");
    addConfigurationProperty("sensor.accelerometer.power", "1.5");
}

void SensorInputMapperTest::setGyroProperties() {
    mFakeEventHub->addSensorAxis(EVENTHUB_ID, /* absCode */ 3, InputDeviceSensorType::GYROSCOPE,
                                 /* sensorDataIndex */ 0);
    mFakeEventHub->addSensorAxis(EVENTHUB_ID, /* absCode */ 4, InputDeviceSensorType::GYROSCOPE,
                                 /* sensorDataIndex */ 1);
    mFakeEventHub->addSensorAxis(EVENTHUB_ID, /* absCode */ 5, InputDeviceSensorType::GYROSCOPE,
                                 /* sensorDataIndex */ 2);
    mFakeEventHub->setMscEvent(EVENTHUB_ID, MSC_TIMESTAMP);
    addConfigurationProperty("sensor.gyroscope.reportingMode", "0");
    addConfigurationProperty("sensor.gyroscope.maxDelay", "100000");
    addConfigurationProperty("sensor.gyroscope.minDelay", "5000");
    addConfigurationProperty("sensor.gyroscope.power", "0.8");
}

TEST_F(SensorInputMapperTest, GetSources) {
    SensorInputMapper& mapper = constructAndAddMapper<SensorInputMapper>();

    ASSERT_EQ(static_cast<uint32_t>(AINPUT_SOURCE_SENSOR), mapper.getSources());
}

TEST_F(SensorInputMapperTest, ProcessAccelerometerSensor) {
    setAccelProperties();
    prepareAccelAxes();
    SensorInputMapper& mapper = constructAndAddMapper<SensorInputMapper>();

    ASSERT_TRUE(mapper.enableSensor(InputDeviceSensorType::ACCELEROMETER,
                                    std::chrono::microseconds(10000),
                                    std::chrono::microseconds(0)));
    ASSERT_TRUE(mFakeEventHub->isDeviceEnabled(EVENTHUB_ID));
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_X, 20000);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_Y, -20000);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_Z, 40000);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_MSC, MSC_TIMESTAMP, 1000);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_SYN, SYN_REPORT, 0);

    NotifySensorArgs args;
    std::vector<float> values = {20000.0f / ACCEL_RAW_RESOLUTION * GRAVITY_MS2_UNIT,
                                 -20000.0f / ACCEL_RAW_RESOLUTION * GRAVITY_MS2_UNIT,
                                 40000.0f / ACCEL_RAW_RESOLUTION * GRAVITY_MS2_UNIT};

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifySensorWasCalled(&args));
    ASSERT_EQ(args.source, AINPUT_SOURCE_SENSOR);
    ASSERT_EQ(args.deviceId, DEVICE_ID);
    ASSERT_EQ(args.sensorType, InputDeviceSensorType::ACCELEROMETER);
    ASSERT_EQ(args.accuracy, InputDeviceSensorAccuracy::ACCURACY_HIGH);
    ASSERT_EQ(args.hwTimestamp, ARBITRARY_TIME);
    ASSERT_EQ(args.values, values);
    mapper.flushSensor(InputDeviceSensorType::ACCELEROMETER);
}

TEST_F(SensorInputMapperTest, ProcessGyroscopeSensor) {
    setGyroProperties();
    prepareGyroAxes();
    SensorInputMapper& mapper = constructAndAddMapper<SensorInputMapper>();

    ASSERT_TRUE(mapper.enableSensor(InputDeviceSensorType::GYROSCOPE,
                                    std::chrono::microseconds(10000),
                                    std::chrono::microseconds(0)));
    ASSERT_TRUE(mFakeEventHub->isDeviceEnabled(EVENTHUB_ID));
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_RX, 20000);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_RY, -20000);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_RZ, 40000);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_MSC, MSC_TIMESTAMP, 1000);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_SYN, SYN_REPORT, 0);

    NotifySensorArgs args;
    std::vector<float> values = {20000.0f / GYRO_RAW_RESOLUTION * DEGREE_RADIAN_UNIT,
                                 -20000.0f / GYRO_RAW_RESOLUTION * DEGREE_RADIAN_UNIT,
                                 40000.0f / GYRO_RAW_RESOLUTION * DEGREE_RADIAN_UNIT};

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifySensorWasCalled(&args));
    ASSERT_EQ(args.source, AINPUT_SOURCE_SENSOR);
    ASSERT_EQ(args.deviceId, DEVICE_ID);
    ASSERT_EQ(args.sensorType, InputDeviceSensorType::GYROSCOPE);
    ASSERT_EQ(args.accuracy, InputDeviceSensorAccuracy::ACCURACY_HIGH);
    ASSERT_EQ(args.hwTimestamp, ARBITRARY_TIME);
    ASSERT_EQ(args.values, values);
    mapper.flushSensor(InputDeviceSensorType::GYROSCOPE);
}

// --- KeyboardInputMapperTest ---

class KeyboardInputMapperTest : public InputMapperTest {
protected:
    const std::string UNIQUE_ID = "local:0";
    const KeyboardLayoutInfo DEVICE_KEYBOARD_LAYOUT_INFO = KeyboardLayoutInfo("en-US", "qwerty");
    void prepareDisplay(ui::Rotation orientation);

    void testDPadKeyRotation(KeyboardInputMapper& mapper, int32_t originalScanCode,
                             int32_t originalKeyCode, int32_t rotatedKeyCode,
                             int32_t displayId = ADISPLAY_ID_NONE);
};

/* Similar to setDisplayInfoAndReconfigure, but pre-populates all parameters except for the
 * orientation.
 */
void KeyboardInputMapperTest::prepareDisplay(ui::Rotation orientation) {
    setDisplayInfoAndReconfigure(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, orientation, UNIQUE_ID,
                                 NO_PORT, ViewportType::INTERNAL);
}

void KeyboardInputMapperTest::testDPadKeyRotation(KeyboardInputMapper& mapper,
                                                  int32_t originalScanCode, int32_t originalKeyCode,
                                                  int32_t rotatedKeyCode, int32_t displayId) {
    NotifyKeyArgs args;

    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, originalScanCode, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, args.action);
    ASSERT_EQ(originalScanCode, args.scanCode);
    ASSERT_EQ(rotatedKeyCode, args.keyCode);
    ASSERT_EQ(displayId, args.displayId);

    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, originalScanCode, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, args.action);
    ASSERT_EQ(originalScanCode, args.scanCode);
    ASSERT_EQ(rotatedKeyCode, args.keyCode);
    ASSERT_EQ(displayId, args.displayId);
}

TEST_F(KeyboardInputMapperTest, GetSources) {
    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, mapper.getSources());
}

TEST_F(KeyboardInputMapperTest, Process_SimpleKeyPress) {
    const int32_t USAGE_A = 0x070004;
    const int32_t USAGE_UNKNOWN = 0x07ffff;
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_HOME, 0, AKEYCODE_HOME, POLICY_FLAG_WAKE);
    mFakeEventHub->addKey(EVENTHUB_ID, 0, USAGE_A, AKEYCODE_A, POLICY_FLAG_WAKE);
    mFakeEventHub->addKey(EVENTHUB_ID, 0, KEY_NUMLOCK, AKEYCODE_NUM_LOCK, POLICY_FLAG_WAKE);
    mFakeEventHub->addKey(EVENTHUB_ID, 0, KEY_CAPSLOCK, AKEYCODE_CAPS_LOCK, POLICY_FLAG_WAKE);
    mFakeEventHub->addKey(EVENTHUB_ID, 0, KEY_SCROLLLOCK, AKEYCODE_SCROLL_LOCK, POLICY_FLAG_WAKE);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    // Initial metastate is AMETA_NONE.
    ASSERT_EQ(AMETA_NONE, mapper.getMetaState());

    // Key down by scan code.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_HOME, 1);
    NotifyKeyArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(DEVICE_ID, args.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, args.source);
    ASSERT_EQ(ARBITRARY_TIME, args.eventTime);
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, args.action);
    ASSERT_EQ(AKEYCODE_HOME, args.keyCode);
    ASSERT_EQ(KEY_HOME, args.scanCode);
    ASSERT_EQ(AMETA_NONE, args.metaState);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM, args.flags);
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);
    ASSERT_EQ(ARBITRARY_TIME, args.downTime);

    // Key up by scan code.
    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_HOME, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(DEVICE_ID, args.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, args.source);
    ASSERT_EQ(ARBITRARY_TIME + 1, args.eventTime);
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, args.action);
    ASSERT_EQ(AKEYCODE_HOME, args.keyCode);
    ASSERT_EQ(KEY_HOME, args.scanCode);
    ASSERT_EQ(AMETA_NONE, args.metaState);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM, args.flags);
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);
    ASSERT_EQ(ARBITRARY_TIME, args.downTime);

    // Key down by usage code.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_MSC, MSC_SCAN, USAGE_A);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, 0, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(DEVICE_ID, args.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, args.source);
    ASSERT_EQ(ARBITRARY_TIME, args.eventTime);
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, args.action);
    ASSERT_EQ(AKEYCODE_A, args.keyCode);
    ASSERT_EQ(0, args.scanCode);
    ASSERT_EQ(AMETA_NONE, args.metaState);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM, args.flags);
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);
    ASSERT_EQ(ARBITRARY_TIME, args.downTime);

    // Key up by usage code.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_MSC, MSC_SCAN, USAGE_A);
    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, 0, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(DEVICE_ID, args.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, args.source);
    ASSERT_EQ(ARBITRARY_TIME + 1, args.eventTime);
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, args.action);
    ASSERT_EQ(AKEYCODE_A, args.keyCode);
    ASSERT_EQ(0, args.scanCode);
    ASSERT_EQ(AMETA_NONE, args.metaState);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM, args.flags);
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);
    ASSERT_EQ(ARBITRARY_TIME, args.downTime);

    // Key down with unknown scan code or usage code.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_MSC, MSC_SCAN, USAGE_UNKNOWN);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UNKNOWN, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(DEVICE_ID, args.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, args.source);
    ASSERT_EQ(ARBITRARY_TIME, args.eventTime);
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, args.action);
    ASSERT_EQ(0, args.keyCode);
    ASSERT_EQ(KEY_UNKNOWN, args.scanCode);
    ASSERT_EQ(AMETA_NONE, args.metaState);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM, args.flags);
    ASSERT_EQ(0U, args.policyFlags);
    ASSERT_EQ(ARBITRARY_TIME, args.downTime);

    // Key up with unknown scan code or usage code.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_MSC, MSC_SCAN, USAGE_UNKNOWN);
    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_UNKNOWN, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(DEVICE_ID, args.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, args.source);
    ASSERT_EQ(ARBITRARY_TIME + 1, args.eventTime);
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, args.action);
    ASSERT_EQ(0, args.keyCode);
    ASSERT_EQ(KEY_UNKNOWN, args.scanCode);
    ASSERT_EQ(AMETA_NONE, args.metaState);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM, args.flags);
    ASSERT_EQ(0U, args.policyFlags);
    ASSERT_EQ(ARBITRARY_TIME, args.downTime);
}

TEST_F(KeyboardInputMapperTest, Process_KeyRemapping) {
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_A, 0, AKEYCODE_A, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_B, 0, AKEYCODE_B, 0);
    mFakeEventHub->addKeyRemapping(EVENTHUB_ID, AKEYCODE_A, AKEYCODE_B);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    // Key down by scan code.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_A, 1);
    NotifyKeyArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AKEYCODE_B, args.keyCode);

    // Key up by scan code.
    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_A, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AKEYCODE_B, args.keyCode);
}

/**
 * Ensure that the readTime is set to the time when the EV_KEY is received.
 */
TEST_F(KeyboardInputMapperTest, Process_SendsReadTime) {
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_HOME, 0, AKEYCODE_HOME, POLICY_FLAG_WAKE);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    NotifyKeyArgs args;

    // Key down
    process(mapper, ARBITRARY_TIME, /*readTime=*/12, EV_KEY, KEY_HOME, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(12, args.readTime);

    // Key up
    process(mapper, ARBITRARY_TIME, /*readTime=*/15, EV_KEY, KEY_HOME, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(15, args.readTime);
}

TEST_F(KeyboardInputMapperTest, Process_ShouldUpdateMetaState) {
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_LEFTSHIFT, 0, AKEYCODE_SHIFT_LEFT, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_A, 0, AKEYCODE_A, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, 0, KEY_NUMLOCK, AKEYCODE_NUM_LOCK, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, 0, KEY_CAPSLOCK, AKEYCODE_CAPS_LOCK, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, 0, KEY_SCROLLLOCK, AKEYCODE_SCROLL_LOCK, 0);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    // Initial metastate is AMETA_NONE.
    ASSERT_EQ(AMETA_NONE, mapper.getMetaState());

    // Metakey down.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_LEFTSHIFT, 1);
    NotifyKeyArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, args.metaState);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, mapper.getMetaState());
    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertUpdateGlobalMetaStateWasCalled());

    // Key down.
    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_A, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, args.metaState);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, mapper.getMetaState());

    // Key up.
    process(mapper, ARBITRARY_TIME + 2, READ_TIME, EV_KEY, KEY_A, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, args.metaState);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, mapper.getMetaState());

    // Metakey up.
    process(mapper, ARBITRARY_TIME + 3, READ_TIME, EV_KEY, KEY_LEFTSHIFT, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AMETA_NONE, args.metaState);
    ASSERT_EQ(AMETA_NONE, mapper.getMetaState());
    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertUpdateGlobalMetaStateWasCalled());
}

TEST_F(KeyboardInputMapperTest, Process_WhenNotOrientationAware_ShouldNotRotateDPad) {
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_UP, 0, AKEYCODE_DPAD_UP, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_RIGHT, 0, AKEYCODE_DPAD_RIGHT, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_DOWN, 0, AKEYCODE_DPAD_DOWN, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_LEFT, 0, AKEYCODE_DPAD_LEFT, 0);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    prepareDisplay(ui::ROTATION_90);
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper,
            KEY_UP, AKEYCODE_DPAD_UP, AKEYCODE_DPAD_UP));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper,
            KEY_RIGHT, AKEYCODE_DPAD_RIGHT, AKEYCODE_DPAD_RIGHT));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper,
            KEY_DOWN, AKEYCODE_DPAD_DOWN, AKEYCODE_DPAD_DOWN));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper,
            KEY_LEFT, AKEYCODE_DPAD_LEFT, AKEYCODE_DPAD_LEFT));
}

TEST_F(KeyboardInputMapperTest, Process_WhenOrientationAware_ShouldRotateDPad) {
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_UP, 0, AKEYCODE_DPAD_UP, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_RIGHT, 0, AKEYCODE_DPAD_RIGHT, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_DOWN, 0, AKEYCODE_DPAD_DOWN, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_LEFT, 0, AKEYCODE_DPAD_LEFT, 0);

    addConfigurationProperty("keyboard.orientationAware", "1");
    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    prepareDisplay(ui::ROTATION_0);
    ASSERT_NO_FATAL_FAILURE(
            testDPadKeyRotation(mapper, KEY_UP, AKEYCODE_DPAD_UP, AKEYCODE_DPAD_UP, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_RIGHT, AKEYCODE_DPAD_RIGHT,
                                                AKEYCODE_DPAD_RIGHT, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_DOWN, AKEYCODE_DPAD_DOWN,
                                                AKEYCODE_DPAD_DOWN, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_LEFT, AKEYCODE_DPAD_LEFT,
                                                AKEYCODE_DPAD_LEFT, DISPLAY_ID));

    clearViewports();
    prepareDisplay(ui::ROTATION_90);
    ASSERT_NO_FATAL_FAILURE(
            testDPadKeyRotation(mapper, KEY_UP, AKEYCODE_DPAD_UP, AKEYCODE_DPAD_LEFT, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_RIGHT, AKEYCODE_DPAD_RIGHT,
                                                AKEYCODE_DPAD_UP, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_DOWN, AKEYCODE_DPAD_DOWN,
                                                AKEYCODE_DPAD_RIGHT, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_LEFT, AKEYCODE_DPAD_LEFT,
                                                AKEYCODE_DPAD_DOWN, DISPLAY_ID));

    clearViewports();
    prepareDisplay(ui::ROTATION_180);
    ASSERT_NO_FATAL_FAILURE(
            testDPadKeyRotation(mapper, KEY_UP, AKEYCODE_DPAD_UP, AKEYCODE_DPAD_DOWN, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_RIGHT, AKEYCODE_DPAD_RIGHT,
                                                AKEYCODE_DPAD_LEFT, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_DOWN, AKEYCODE_DPAD_DOWN,
                                                AKEYCODE_DPAD_UP, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_LEFT, AKEYCODE_DPAD_LEFT,
                                                AKEYCODE_DPAD_RIGHT, DISPLAY_ID));

    clearViewports();
    prepareDisplay(ui::ROTATION_270);
    ASSERT_NO_FATAL_FAILURE(
            testDPadKeyRotation(mapper, KEY_UP, AKEYCODE_DPAD_UP, AKEYCODE_DPAD_RIGHT, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_RIGHT, AKEYCODE_DPAD_RIGHT,
                                                AKEYCODE_DPAD_DOWN, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_DOWN, AKEYCODE_DPAD_DOWN,
                                                AKEYCODE_DPAD_LEFT, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_LEFT, AKEYCODE_DPAD_LEFT,
                                                AKEYCODE_DPAD_UP, DISPLAY_ID));

    // Special case: if orientation changes while key is down, we still emit the same keycode
    // in the key up as we did in the key down.
    NotifyKeyArgs args;
    clearViewports();
    prepareDisplay(ui::ROTATION_270);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UP, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, args.action);
    ASSERT_EQ(KEY_UP, args.scanCode);
    ASSERT_EQ(AKEYCODE_DPAD_RIGHT, args.keyCode);

    clearViewports();
    prepareDisplay(ui::ROTATION_180);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UP, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, args.action);
    ASSERT_EQ(KEY_UP, args.scanCode);
    ASSERT_EQ(AKEYCODE_DPAD_RIGHT, args.keyCode);
}

TEST_F(KeyboardInputMapperTest, DisplayIdConfigurationChange_NotOrientationAware) {
    // If the keyboard is not orientation aware,
    // key events should not be associated with a specific display id
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_UP, 0, AKEYCODE_DPAD_UP, 0);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    NotifyKeyArgs args;

    // Display id should be ADISPLAY_ID_NONE without any display configuration.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UP, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UP, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(ADISPLAY_ID_NONE, args.displayId);

    prepareDisplay(ui::ROTATION_0);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UP, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UP, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(ADISPLAY_ID_NONE, args.displayId);
}

TEST_F(KeyboardInputMapperTest, DisplayIdConfigurationChange_OrientationAware) {
    // If the keyboard is orientation aware,
    // key events should be associated with the internal viewport
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_UP, 0, AKEYCODE_DPAD_UP, 0);

    addConfigurationProperty("keyboard.orientationAware", "1");
    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    NotifyKeyArgs args;

    // Display id should be ADISPLAY_ID_NONE without any display configuration.
    // ^--- already checked by the previous test

    setDisplayInfoAndReconfigure(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                 UNIQUE_ID, NO_PORT, ViewportType::INTERNAL);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UP, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UP, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(DISPLAY_ID, args.displayId);

    constexpr int32_t newDisplayId = 2;
    clearViewports();
    setDisplayInfoAndReconfigure(newDisplayId, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                 UNIQUE_ID, NO_PORT, ViewportType::INTERNAL);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UP, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UP, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(newDisplayId, args.displayId);
}

TEST_F(KeyboardInputMapperTest, GetKeyCodeState) {
    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    mFakeEventHub->setKeyCodeState(EVENTHUB_ID, AKEYCODE_A, 1);
    ASSERT_EQ(1, mapper.getKeyCodeState(AINPUT_SOURCE_ANY, AKEYCODE_A));

    mFakeEventHub->setKeyCodeState(EVENTHUB_ID, AKEYCODE_A, 0);
    ASSERT_EQ(0, mapper.getKeyCodeState(AINPUT_SOURCE_ANY, AKEYCODE_A));
}

TEST_F(KeyboardInputMapperTest, GetKeyCodeForKeyLocation) {
    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    mFakeEventHub->addKeyCodeMapping(EVENTHUB_ID, AKEYCODE_Y, AKEYCODE_Z);
    ASSERT_EQ(AKEYCODE_Z, mapper.getKeyCodeForKeyLocation(AKEYCODE_Y))
            << "If a mapping is available, the result is equal to the mapping";

    ASSERT_EQ(AKEYCODE_A, mapper.getKeyCodeForKeyLocation(AKEYCODE_A))
            << "If no mapping is available, the result is the key location";
}

TEST_F(KeyboardInputMapperTest, GetScanCodeState) {
    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    mFakeEventHub->setScanCodeState(EVENTHUB_ID, KEY_A, 1);
    ASSERT_EQ(1, mapper.getScanCodeState(AINPUT_SOURCE_ANY, KEY_A));

    mFakeEventHub->setScanCodeState(EVENTHUB_ID, KEY_A, 0);
    ASSERT_EQ(0, mapper.getScanCodeState(AINPUT_SOURCE_ANY, KEY_A));
}

TEST_F(KeyboardInputMapperTest, MarkSupportedKeyCodes) {
    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    mFakeEventHub->addKey(EVENTHUB_ID, KEY_A, 0, AKEYCODE_A, 0);

    uint8_t flags[2] = { 0, 0 };
    ASSERT_TRUE(mapper.markSupportedKeyCodes(AINPUT_SOURCE_ANY, {AKEYCODE_A, AKEYCODE_B}, flags));
    ASSERT_TRUE(flags[0]);
    ASSERT_FALSE(flags[1]);
}

TEST_F(KeyboardInputMapperTest, Process_LockedKeysShouldToggleMetaStateAndLeds) {
    mFakeEventHub->addLed(EVENTHUB_ID, LED_CAPSL, true /*initially on*/);
    mFakeEventHub->addLed(EVENTHUB_ID, LED_NUML, false /*initially off*/);
    mFakeEventHub->addLed(EVENTHUB_ID, LED_SCROLLL, false /*initially off*/);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_CAPSLOCK, 0, AKEYCODE_CAPS_LOCK, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_NUMLOCK, 0, AKEYCODE_NUM_LOCK, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_SCROLLLOCK, 0, AKEYCODE_SCROLL_LOCK, 0);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    // Initial metastate is AMETA_NONE.
    ASSERT_EQ(AMETA_NONE, mapper.getMetaState());

    // Initialization should have turned all of the lights off.
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_CAPSL));
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_NUML));
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_SCROLLL));

    // Toggle caps lock on.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_CAPSLOCK, 1);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_CAPSLOCK, 0);
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_CAPSL));
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_NUML));
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_SCROLLL));
    ASSERT_EQ(AMETA_CAPS_LOCK_ON, mapper.getMetaState());

    // Toggle num lock on.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_NUMLOCK, 1);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_NUMLOCK, 0);
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_CAPSL));
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_NUML));
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_SCROLLL));
    ASSERT_EQ(AMETA_CAPS_LOCK_ON | AMETA_NUM_LOCK_ON, mapper.getMetaState());

    // Toggle caps lock off.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_CAPSLOCK, 1);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_CAPSLOCK, 0);
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_CAPSL));
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_NUML));
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_SCROLLL));
    ASSERT_EQ(AMETA_NUM_LOCK_ON, mapper.getMetaState());

    // Toggle scroll lock on.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_SCROLLLOCK, 1);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_SCROLLLOCK, 0);
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_CAPSL));
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_NUML));
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_SCROLLL));
    ASSERT_EQ(AMETA_NUM_LOCK_ON | AMETA_SCROLL_LOCK_ON, mapper.getMetaState());

    // Toggle num lock off.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_NUMLOCK, 1);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_NUMLOCK, 0);
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_CAPSL));
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_NUML));
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_SCROLLL));
    ASSERT_EQ(AMETA_SCROLL_LOCK_ON, mapper.getMetaState());

    // Toggle scroll lock off.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_SCROLLLOCK, 1);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_SCROLLLOCK, 0);
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_CAPSL));
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_NUML));
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_SCROLLL));
    ASSERT_EQ(AMETA_NONE, mapper.getMetaState());
}

TEST_F(KeyboardInputMapperTest, NoMetaStateWhenMetaKeysNotPresent) {
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_A, 0, AKEYCODE_BUTTON_A, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_B, 0, AKEYCODE_BUTTON_B, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_X, 0, AKEYCODE_BUTTON_X, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_Y, 0, AKEYCODE_BUTTON_Y, 0);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC);

    // Meta state should be AMETA_NONE after reset
    std::list<NotifyArgs> unused = mapper.reset(ARBITRARY_TIME);
    ASSERT_EQ(AMETA_NONE, mapper.getMetaState());
    // Meta state should be AMETA_NONE with update, as device doesn't have the keys.
    mapper.updateMetaState(AKEYCODE_NUM_LOCK);
    ASSERT_EQ(AMETA_NONE, mapper.getMetaState());

    NotifyKeyArgs args;
    // Press button "A"
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, BTN_A, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AMETA_NONE, args.metaState);
    ASSERT_EQ(AMETA_NONE, mapper.getMetaState());
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, args.action);
    ASSERT_EQ(AKEYCODE_BUTTON_A, args.keyCode);

    // Button up.
    process(mapper, ARBITRARY_TIME + 2, READ_TIME, EV_KEY, BTN_A, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AMETA_NONE, args.metaState);
    ASSERT_EQ(AMETA_NONE, mapper.getMetaState());
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, args.action);
    ASSERT_EQ(AKEYCODE_BUTTON_A, args.keyCode);
}

TEST_F(KeyboardInputMapperTest, Configure_AssignsDisplayPort) {
    // keyboard 1.
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_UP, 0, AKEYCODE_DPAD_UP, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_RIGHT, 0, AKEYCODE_DPAD_RIGHT, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_DOWN, 0, AKEYCODE_DPAD_DOWN, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_LEFT, 0, AKEYCODE_DPAD_LEFT, 0);

    // keyboard 2.
    const std::string USB2 = "USB2";
    const std::string DEVICE_NAME2 = "KEYBOARD2";
    constexpr int32_t SECOND_DEVICE_ID = DEVICE_ID + 1;
    constexpr int32_t SECOND_EVENTHUB_ID = EVENTHUB_ID + 1;
    std::shared_ptr<InputDevice> device2 =
            newDevice(SECOND_DEVICE_ID, DEVICE_NAME2, USB2, SECOND_EVENTHUB_ID,
                      ftl::Flags<InputDeviceClass>(0));

    mFakeEventHub->addKey(SECOND_EVENTHUB_ID, KEY_UP, 0, AKEYCODE_DPAD_UP, 0);
    mFakeEventHub->addKey(SECOND_EVENTHUB_ID, KEY_RIGHT, 0, AKEYCODE_DPAD_RIGHT, 0);
    mFakeEventHub->addKey(SECOND_EVENTHUB_ID, KEY_DOWN, 0, AKEYCODE_DPAD_DOWN, 0);
    mFakeEventHub->addKey(SECOND_EVENTHUB_ID, KEY_LEFT, 0, AKEYCODE_DPAD_LEFT, 0);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    device2->addEmptyEventHubDevice(SECOND_EVENTHUB_ID);
    KeyboardInputMapper& mapper2 =
            device2->constructAndAddMapper<KeyboardInputMapper>(SECOND_EVENTHUB_ID,
                                                                mFakePolicy
                                                                        ->getReaderConfiguration(),
                                                                AINPUT_SOURCE_KEYBOARD,
                                                                AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    std::list<NotifyArgs> unused =
            device2->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});
    unused += device2->reset(ARBITRARY_TIME);

    // Prepared displays and associated info.
    constexpr uint8_t hdmi1 = 0;
    constexpr uint8_t hdmi2 = 1;
    const std::string SECONDARY_UNIQUE_ID = "local:1";

    mFakePolicy->addInputPortAssociation(DEVICE_LOCATION, hdmi1);
    mFakePolicy->addInputPortAssociation(USB2, hdmi2);

    // No associated display viewport found, should disable the device.
    unused += device2->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::DISPLAY_INFO);
    ASSERT_FALSE(device2->isEnabled());

    // Prepare second display.
    constexpr int32_t newDisplayId = 2;
    setDisplayInfoAndReconfigure(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                 UNIQUE_ID, hdmi1, ViewportType::INTERNAL);
    setDisplayInfoAndReconfigure(newDisplayId, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                 SECONDARY_UNIQUE_ID, hdmi2, ViewportType::EXTERNAL);
    // Default device will reconfigure above, need additional reconfiguration for another device.
    unused += device2->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::DISPLAY_INFO);

    // Device should be enabled after the associated display is found.
    ASSERT_TRUE(mDevice->isEnabled());
    ASSERT_TRUE(device2->isEnabled());

    // Test pad key events
    ASSERT_NO_FATAL_FAILURE(
            testDPadKeyRotation(mapper, KEY_UP, AKEYCODE_DPAD_UP, AKEYCODE_DPAD_UP, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_RIGHT, AKEYCODE_DPAD_RIGHT,
                                                AKEYCODE_DPAD_RIGHT, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_DOWN, AKEYCODE_DPAD_DOWN,
                                                AKEYCODE_DPAD_DOWN, DISPLAY_ID));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper, KEY_LEFT, AKEYCODE_DPAD_LEFT,
                                                AKEYCODE_DPAD_LEFT, DISPLAY_ID));

    ASSERT_NO_FATAL_FAILURE(
            testDPadKeyRotation(mapper2, KEY_UP, AKEYCODE_DPAD_UP, AKEYCODE_DPAD_UP, newDisplayId));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper2, KEY_RIGHT, AKEYCODE_DPAD_RIGHT,
                                                AKEYCODE_DPAD_RIGHT, newDisplayId));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper2, KEY_DOWN, AKEYCODE_DPAD_DOWN,
                                                AKEYCODE_DPAD_DOWN, newDisplayId));
    ASSERT_NO_FATAL_FAILURE(testDPadKeyRotation(mapper2, KEY_LEFT, AKEYCODE_DPAD_LEFT,
                                                AKEYCODE_DPAD_LEFT, newDisplayId));
}

TEST_F(KeyboardInputMapperTest, Process_LockedKeysShouldToggleAfterReattach) {
    mFakeEventHub->addLed(EVENTHUB_ID, LED_CAPSL, true /*initially on*/);
    mFakeEventHub->addLed(EVENTHUB_ID, LED_NUML, false /*initially off*/);
    mFakeEventHub->addLed(EVENTHUB_ID, LED_SCROLLL, false /*initially off*/);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_CAPSLOCK, 0, AKEYCODE_CAPS_LOCK, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_NUMLOCK, 0, AKEYCODE_NUM_LOCK, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_SCROLLLOCK, 0, AKEYCODE_SCROLL_LOCK, 0);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    // Initial metastate is AMETA_NONE.
    ASSERT_EQ(AMETA_NONE, mapper.getMetaState());

    // Initialization should have turned all of the lights off.
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_CAPSL));
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_NUML));
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_SCROLLL));

    // Toggle caps lock on.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_CAPSLOCK, 1);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_CAPSLOCK, 0);
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_CAPSL));
    ASSERT_EQ(AMETA_CAPS_LOCK_ON, mapper.getMetaState());

    // Toggle num lock on.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_NUMLOCK, 1);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_NUMLOCK, 0);
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_NUML));
    ASSERT_EQ(AMETA_CAPS_LOCK_ON | AMETA_NUM_LOCK_ON, mapper.getMetaState());

    // Toggle scroll lock on.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_SCROLLLOCK, 1);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_SCROLLLOCK, 0);
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_SCROLLL));
    ASSERT_EQ(AMETA_CAPS_LOCK_ON | AMETA_NUM_LOCK_ON | AMETA_SCROLL_LOCK_ON, mapper.getMetaState());

    mFakeEventHub->removeDevice(EVENTHUB_ID);
    mReader->loopOnce();

    // keyboard 2 should default toggle keys.
    const std::string USB2 = "USB2";
    const std::string DEVICE_NAME2 = "KEYBOARD2";
    constexpr int32_t SECOND_DEVICE_ID = DEVICE_ID + 1;
    constexpr int32_t SECOND_EVENTHUB_ID = EVENTHUB_ID + 1;
    std::shared_ptr<InputDevice> device2 =
            newDevice(SECOND_DEVICE_ID, DEVICE_NAME2, USB2, SECOND_EVENTHUB_ID,
                      ftl::Flags<InputDeviceClass>(0));
    mFakeEventHub->addLed(SECOND_EVENTHUB_ID, LED_CAPSL, true /*initially on*/);
    mFakeEventHub->addLed(SECOND_EVENTHUB_ID, LED_NUML, false /*initially off*/);
    mFakeEventHub->addLed(SECOND_EVENTHUB_ID, LED_SCROLLL, false /*initially off*/);
    mFakeEventHub->addKey(SECOND_EVENTHUB_ID, KEY_CAPSLOCK, 0, AKEYCODE_CAPS_LOCK, 0);
    mFakeEventHub->addKey(SECOND_EVENTHUB_ID, KEY_NUMLOCK, 0, AKEYCODE_NUM_LOCK, 0);
    mFakeEventHub->addKey(SECOND_EVENTHUB_ID, KEY_SCROLLLOCK, 0, AKEYCODE_SCROLL_LOCK, 0);

    device2->addEmptyEventHubDevice(SECOND_EVENTHUB_ID);
    KeyboardInputMapper& mapper2 =
            device2->constructAndAddMapper<KeyboardInputMapper>(SECOND_EVENTHUB_ID,
                                                                mFakePolicy
                                                                        ->getReaderConfiguration(),
                                                                AINPUT_SOURCE_KEYBOARD,
                                                                AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    std::list<NotifyArgs> unused =
            device2->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});
    unused += device2->reset(ARBITRARY_TIME);

    ASSERT_TRUE(mFakeEventHub->getLedState(SECOND_EVENTHUB_ID, LED_CAPSL));
    ASSERT_TRUE(mFakeEventHub->getLedState(SECOND_EVENTHUB_ID, LED_NUML));
    ASSERT_TRUE(mFakeEventHub->getLedState(SECOND_EVENTHUB_ID, LED_SCROLLL));
    ASSERT_EQ(AMETA_CAPS_LOCK_ON | AMETA_NUM_LOCK_ON | AMETA_SCROLL_LOCK_ON,
              mapper2.getMetaState());
}

TEST_F(KeyboardInputMapperTest, Process_toggleCapsLockState) {
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_CAPSLOCK, 0, AKEYCODE_CAPS_LOCK, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_NUMLOCK, 0, AKEYCODE_NUM_LOCK, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_SCROLLLOCK, 0, AKEYCODE_SCROLL_LOCK, 0);

    // Suppose we have two mappers. (DPAD + KEYBOARD)
    constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_DPAD,
                                               AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC);
    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    // Initial metastate is AMETA_NONE.
    ASSERT_EQ(AMETA_NONE, mapper.getMetaState());

    mReader->toggleCapsLockState(DEVICE_ID);
    ASSERT_EQ(AMETA_CAPS_LOCK_ON, mapper.getMetaState());
}

TEST_F(KeyboardInputMapperTest, Process_LockedKeysShouldToggleInMultiDevices) {
    // keyboard 1.
    mFakeEventHub->addLed(EVENTHUB_ID, LED_CAPSL, true /*initially on*/);
    mFakeEventHub->addLed(EVENTHUB_ID, LED_NUML, false /*initially off*/);
    mFakeEventHub->addLed(EVENTHUB_ID, LED_SCROLLL, false /*initially off*/);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_CAPSLOCK, 0, AKEYCODE_CAPS_LOCK, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_NUMLOCK, 0, AKEYCODE_NUM_LOCK, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_SCROLLLOCK, 0, AKEYCODE_SCROLL_LOCK, 0);

    KeyboardInputMapper& mapper1 =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    // keyboard 2.
    const std::string USB2 = "USB2";
    const std::string DEVICE_NAME2 = "KEYBOARD2";
    constexpr int32_t SECOND_DEVICE_ID = DEVICE_ID + 1;
    constexpr int32_t SECOND_EVENTHUB_ID = EVENTHUB_ID + 1;
    std::shared_ptr<InputDevice> device2 =
            newDevice(SECOND_DEVICE_ID, DEVICE_NAME2, USB2, SECOND_EVENTHUB_ID,
                      ftl::Flags<InputDeviceClass>(0));
    mFakeEventHub->addLed(SECOND_EVENTHUB_ID, LED_CAPSL, true /*initially on*/);
    mFakeEventHub->addLed(SECOND_EVENTHUB_ID, LED_NUML, false /*initially off*/);
    mFakeEventHub->addLed(SECOND_EVENTHUB_ID, LED_SCROLLL, false /*initially off*/);
    mFakeEventHub->addKey(SECOND_EVENTHUB_ID, KEY_CAPSLOCK, 0, AKEYCODE_CAPS_LOCK, 0);
    mFakeEventHub->addKey(SECOND_EVENTHUB_ID, KEY_NUMLOCK, 0, AKEYCODE_NUM_LOCK, 0);
    mFakeEventHub->addKey(SECOND_EVENTHUB_ID, KEY_SCROLLLOCK, 0, AKEYCODE_SCROLL_LOCK, 0);

    device2->addEmptyEventHubDevice(SECOND_EVENTHUB_ID);
    KeyboardInputMapper& mapper2 =
            device2->constructAndAddMapper<KeyboardInputMapper>(SECOND_EVENTHUB_ID,
                                                                mFakePolicy
                                                                        ->getReaderConfiguration(),
                                                                AINPUT_SOURCE_KEYBOARD,
                                                                AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    std::list<NotifyArgs> unused =
            device2->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});
    unused += device2->reset(ARBITRARY_TIME);

    // Initial metastate is AMETA_NONE.
    ASSERT_EQ(AMETA_NONE, mapper1.getMetaState());
    ASSERT_EQ(AMETA_NONE, mapper2.getMetaState());

    // Toggle num lock on and off.
    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_NUMLOCK, 1);
    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_NUMLOCK, 0);
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_NUML));
    ASSERT_EQ(AMETA_NUM_LOCK_ON, mapper1.getMetaState());
    ASSERT_EQ(AMETA_NUM_LOCK_ON, mapper2.getMetaState());

    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_NUMLOCK, 1);
    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_NUMLOCK, 0);
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_NUML));
    ASSERT_EQ(AMETA_NONE, mapper1.getMetaState());
    ASSERT_EQ(AMETA_NONE, mapper2.getMetaState());

    // Toggle caps lock on and off.
    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_CAPSLOCK, 1);
    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_CAPSLOCK, 0);
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_CAPSL));
    ASSERT_EQ(AMETA_CAPS_LOCK_ON, mapper1.getMetaState());
    ASSERT_EQ(AMETA_CAPS_LOCK_ON, mapper2.getMetaState());

    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_CAPSLOCK, 1);
    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_CAPSLOCK, 0);
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_CAPSL));
    ASSERT_EQ(AMETA_NONE, mapper1.getMetaState());
    ASSERT_EQ(AMETA_NONE, mapper2.getMetaState());

    // Toggle scroll lock on and off.
    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_SCROLLLOCK, 1);
    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_SCROLLLOCK, 0);
    ASSERT_TRUE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_SCROLLL));
    ASSERT_EQ(AMETA_SCROLL_LOCK_ON, mapper1.getMetaState());
    ASSERT_EQ(AMETA_SCROLL_LOCK_ON, mapper2.getMetaState());

    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_SCROLLLOCK, 1);
    process(mapper1, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_SCROLLLOCK, 0);
    ASSERT_FALSE(mFakeEventHub->getLedState(EVENTHUB_ID, LED_SCROLLL));
    ASSERT_EQ(AMETA_NONE, mapper1.getMetaState());
    ASSERT_EQ(AMETA_NONE, mapper2.getMetaState());
}

TEST_F(KeyboardInputMapperTest, Process_DisabledDevice) {
    const int32_t USAGE_A = 0x070004;
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_HOME, 0, AKEYCODE_HOME, POLICY_FLAG_WAKE);
    mFakeEventHub->addKey(EVENTHUB_ID, 0, USAGE_A, AKEYCODE_A, POLICY_FLAG_WAKE);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    // Key down by scan code.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_HOME, 1);
    NotifyKeyArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(DEVICE_ID, args.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, args.source);
    ASSERT_EQ(ARBITRARY_TIME, args.eventTime);
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, args.action);
    ASSERT_EQ(AKEYCODE_HOME, args.keyCode);
    ASSERT_EQ(KEY_HOME, args.scanCode);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM, args.flags);

    // Disable device, it should synthesize cancellation events for down events.
    mFakePolicy->addDisabledDevice(DEVICE_ID);
    configureDevice(InputReaderConfiguration::Change::ENABLED_STATE);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, args.action);
    ASSERT_EQ(AKEYCODE_HOME, args.keyCode);
    ASSERT_EQ(KEY_HOME, args.scanCode);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM | AKEY_EVENT_FLAG_CANCELED, args.flags);
}

TEST_F(KeyboardInputMapperTest, Configure_AssignKeyboardLayoutInfo) {
    constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                               AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    std::list<NotifyArgs> unused =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});

    uint32_t generation = mReader->getContext()->getGeneration();
    mFakePolicy->addKeyboardLayoutAssociation(DEVICE_LOCATION, DEVICE_KEYBOARD_LAYOUT_INFO);

    unused += mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::KEYBOARD_LAYOUT_ASSOCIATION);

    InputDeviceInfo deviceInfo = mDevice->getDeviceInfo();
    ASSERT_EQ(DEVICE_KEYBOARD_LAYOUT_INFO.languageTag,
              deviceInfo.getKeyboardLayoutInfo()->languageTag);
    ASSERT_EQ(DEVICE_KEYBOARD_LAYOUT_INFO.layoutType,
              deviceInfo.getKeyboardLayoutInfo()->layoutType);
    ASSERT_TRUE(mReader->getContext()->getGeneration() != generation);

    // Call change layout association with the same values: Generation shouldn't change
    generation = mReader->getContext()->getGeneration();
    mFakePolicy->addKeyboardLayoutAssociation(DEVICE_LOCATION, DEVICE_KEYBOARD_LAYOUT_INFO);
    unused += mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::KEYBOARD_LAYOUT_ASSOCIATION);
    ASSERT_TRUE(mReader->getContext()->getGeneration() == generation);
}

TEST_F(KeyboardInputMapperTest, LayoutInfoCorrectlyMapped) {
    mFakeEventHub->setRawLayoutInfo(EVENTHUB_ID,
                                    RawLayoutInfo{.languageTag = "en", .layoutType = "extended"});

    // Configuration
    constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                               AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    InputReaderConfiguration config;
    std::list<NotifyArgs> unused = mDevice->configure(ARBITRARY_TIME, config, /*changes=*/{});

    ASSERT_EQ("en", mDevice->getDeviceInfo().getKeyboardLayoutInfo()->languageTag);
    ASSERT_EQ("extended", mDevice->getDeviceInfo().getKeyboardLayoutInfo()->layoutType);
}

TEST_F(KeyboardInputMapperTest, Process_GesureEventToSetFlagKeepTouchMode) {
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_LEFT, 0, AKEYCODE_DPAD_LEFT, POLICY_FLAG_GESTURE);
    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);
    NotifyKeyArgs args;

    // Key down
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_LEFT, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM | AKEY_EVENT_FLAG_KEEP_TOUCH_MODE, args.flags);
}

// --- KeyboardInputMapperTest_ExternalDevice ---

class KeyboardInputMapperTest_ExternalDevice : public InputMapperTest {
protected:
    void SetUp() override { InputMapperTest::SetUp(DEVICE_CLASSES | InputDeviceClass::EXTERNAL); }
};

TEST_F(KeyboardInputMapperTest_ExternalDevice, WakeBehavior_AlphabeticKeyboard) {
    // For external devices, keys will trigger wake on key down. Media keys should also trigger
    // wake if triggered from external devices.

    mFakeEventHub->addKey(EVENTHUB_ID, KEY_HOME, 0, AKEYCODE_HOME, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_PLAY, 0, AKEYCODE_MEDIA_PLAY, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_PLAYPAUSE, 0, AKEYCODE_MEDIA_PLAY_PAUSE,
                          POLICY_FLAG_WAKE);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_HOME, 1);
    NotifyKeyArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);

    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_HOME, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(uint32_t(0), args.policyFlags);

    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_PLAY, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);

    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_PLAY, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(uint32_t(0), args.policyFlags);

    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_PLAYPAUSE, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);

    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_PLAYPAUSE, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);
}

TEST_F(KeyboardInputMapperTest_ExternalDevice, WakeBehavior_NoneAlphabeticKeyboard) {
    // For external devices, keys will trigger wake on key down. Media keys should not trigger
    // wake if triggered from external non-alphaebtic keyboard (e.g. headsets).

    mFakeEventHub->addKey(EVENTHUB_ID, KEY_PLAY, 0, AKEYCODE_MEDIA_PLAY, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_PLAYPAUSE, 0, AKEYCODE_MEDIA_PLAY_PAUSE,
                          POLICY_FLAG_WAKE);

    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC);

    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_PLAY, 1);
    NotifyKeyArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(uint32_t(0), args.policyFlags);

    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_PLAY, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(uint32_t(0), args.policyFlags);

    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_PLAYPAUSE, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);

    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_PLAYPAUSE, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);
}

TEST_F(KeyboardInputMapperTest_ExternalDevice, DoNotWakeByDefaultBehavior) {
    // Tv Remote key's wake behavior is prescribed by the keylayout file.

    mFakeEventHub->addKey(EVENTHUB_ID, KEY_HOME, 0, AKEYCODE_HOME, POLICY_FLAG_WAKE);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_DOWN, 0, AKEYCODE_DPAD_DOWN, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_PLAY, 0, AKEYCODE_MEDIA_PLAY, POLICY_FLAG_WAKE);

    addConfigurationProperty("keyboard.doNotWakeByDefault", "1");
    KeyboardInputMapper& mapper =
            constructAndAddMapper<KeyboardInputMapper>(AINPUT_SOURCE_KEYBOARD,
                                                       AINPUT_KEYBOARD_TYPE_ALPHABETIC);

    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_HOME, 1);
    NotifyKeyArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);

    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_HOME, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);

    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_DOWN, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(uint32_t(0), args.policyFlags);

    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_DOWN, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(uint32_t(0), args.policyFlags);

    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_PLAY, 1);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);

    process(mapper, ARBITRARY_TIME + 1, READ_TIME, EV_KEY, KEY_PLAY, 0);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(POLICY_FLAG_WAKE, args.policyFlags);
}

// --- TouchInputMapperTest ---

class TouchInputMapperTest : public InputMapperTest {
protected:
    static const int32_t RAW_X_MIN;
    static const int32_t RAW_X_MAX;
    static const int32_t RAW_Y_MIN;
    static const int32_t RAW_Y_MAX;
    static const int32_t RAW_TOUCH_MIN;
    static const int32_t RAW_TOUCH_MAX;
    static const int32_t RAW_TOOL_MIN;
    static const int32_t RAW_TOOL_MAX;
    static const int32_t RAW_PRESSURE_MIN;
    static const int32_t RAW_PRESSURE_MAX;
    static const int32_t RAW_ORIENTATION_MIN;
    static const int32_t RAW_ORIENTATION_MAX;
    static const int32_t RAW_DISTANCE_MIN;
    static const int32_t RAW_DISTANCE_MAX;
    static const int32_t RAW_TILT_MIN;
    static const int32_t RAW_TILT_MAX;
    static const int32_t RAW_ID_MIN;
    static const int32_t RAW_ID_MAX;
    static const int32_t RAW_SLOT_MIN;
    static const int32_t RAW_SLOT_MAX;
    static const float X_PRECISION;
    static const float Y_PRECISION;
    static const float X_PRECISION_VIRTUAL;
    static const float Y_PRECISION_VIRTUAL;

    static const float GEOMETRIC_SCALE;
    static const TouchAffineTransformation AFFINE_TRANSFORM;

    static const VirtualKeyDefinition VIRTUAL_KEYS[2];

    const std::string UNIQUE_ID = "local:0";
    const std::string SECONDARY_UNIQUE_ID = "local:1";

    enum Axes {
        POSITION = 1 << 0,
        TOUCH = 1 << 1,
        TOOL = 1 << 2,
        PRESSURE = 1 << 3,
        ORIENTATION = 1 << 4,
        MINOR = 1 << 5,
        ID = 1 << 6,
        DISTANCE = 1 << 7,
        TILT = 1 << 8,
        SLOT = 1 << 9,
        TOOL_TYPE = 1 << 10,
    };

    void prepareDisplay(ui::Rotation orientation, std::optional<uint8_t> port = NO_PORT);
    void prepareSecondaryDisplay(ViewportType type, std::optional<uint8_t> port = NO_PORT);
    void prepareVirtualDisplay(ui::Rotation orientation);
    void prepareVirtualKeys();
    void prepareLocationCalibration();
    int32_t toRawX(float displayX);
    int32_t toRawY(float displayY);
    int32_t toRotatedRawX(float displayX);
    int32_t toRotatedRawY(float displayY);
    float toCookedX(float rawX, float rawY);
    float toCookedY(float rawX, float rawY);
    float toDisplayX(int32_t rawX);
    float toDisplayX(int32_t rawX, int32_t displayWidth);
    float toDisplayY(int32_t rawY);
    float toDisplayY(int32_t rawY, int32_t displayHeight);

};

const int32_t TouchInputMapperTest::RAW_X_MIN = 25;
const int32_t TouchInputMapperTest::RAW_X_MAX = 1019;
const int32_t TouchInputMapperTest::RAW_Y_MIN = 30;
const int32_t TouchInputMapperTest::RAW_Y_MAX = 1009;
const int32_t TouchInputMapperTest::RAW_TOUCH_MIN = 0;
const int32_t TouchInputMapperTest::RAW_TOUCH_MAX = 31;
const int32_t TouchInputMapperTest::RAW_TOOL_MIN = 0;
const int32_t TouchInputMapperTest::RAW_TOOL_MAX = 15;
const int32_t TouchInputMapperTest::RAW_PRESSURE_MIN = 0;
const int32_t TouchInputMapperTest::RAW_PRESSURE_MAX = 255;
const int32_t TouchInputMapperTest::RAW_ORIENTATION_MIN = -7;
const int32_t TouchInputMapperTest::RAW_ORIENTATION_MAX = 7;
const int32_t TouchInputMapperTest::RAW_DISTANCE_MIN = 0;
const int32_t TouchInputMapperTest::RAW_DISTANCE_MAX = 7;
const int32_t TouchInputMapperTest::RAW_TILT_MIN = 0;
const int32_t TouchInputMapperTest::RAW_TILT_MAX = 150;
const int32_t TouchInputMapperTest::RAW_ID_MIN = 0;
const int32_t TouchInputMapperTest::RAW_ID_MAX = 9;
const int32_t TouchInputMapperTest::RAW_SLOT_MIN = 0;
const int32_t TouchInputMapperTest::RAW_SLOT_MAX = 9;
const float TouchInputMapperTest::X_PRECISION = float(RAW_X_MAX - RAW_X_MIN + 1) / DISPLAY_WIDTH;
const float TouchInputMapperTest::Y_PRECISION = float(RAW_Y_MAX - RAW_Y_MIN + 1) / DISPLAY_HEIGHT;
const float TouchInputMapperTest::X_PRECISION_VIRTUAL =
        float(RAW_X_MAX - RAW_X_MIN + 1) / VIRTUAL_DISPLAY_WIDTH;
const float TouchInputMapperTest::Y_PRECISION_VIRTUAL =
        float(RAW_Y_MAX - RAW_Y_MIN + 1) / VIRTUAL_DISPLAY_HEIGHT;
const TouchAffineTransformation TouchInputMapperTest::AFFINE_TRANSFORM =
        TouchAffineTransformation(1, -2, 3, -4, 5, -6);

const float TouchInputMapperTest::GEOMETRIC_SCALE =
        avg(float(DISPLAY_WIDTH) / (RAW_X_MAX - RAW_X_MIN + 1),
                float(DISPLAY_HEIGHT) / (RAW_Y_MAX - RAW_Y_MIN + 1));

const VirtualKeyDefinition TouchInputMapperTest::VIRTUAL_KEYS[2] = {
        { KEY_HOME, 60, DISPLAY_HEIGHT + 15, 20, 20 },
        { KEY_MENU, DISPLAY_HEIGHT - 60, DISPLAY_WIDTH + 15, 20, 20 },
};

void TouchInputMapperTest::prepareDisplay(ui::Rotation orientation, std::optional<uint8_t> port) {
    setDisplayInfoAndReconfigure(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, orientation, UNIQUE_ID,
                                 port, ViewportType::INTERNAL);
}

void TouchInputMapperTest::prepareSecondaryDisplay(ViewportType type, std::optional<uint8_t> port) {
    setDisplayInfoAndReconfigure(SECONDARY_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                 ui::ROTATION_0, SECONDARY_UNIQUE_ID, port, type);
}

void TouchInputMapperTest::prepareVirtualDisplay(ui::Rotation orientation) {
    setDisplayInfoAndReconfigure(VIRTUAL_DISPLAY_ID, VIRTUAL_DISPLAY_WIDTH, VIRTUAL_DISPLAY_HEIGHT,
                                 orientation, VIRTUAL_DISPLAY_UNIQUE_ID, NO_PORT,
                                 ViewportType::VIRTUAL);
}

void TouchInputMapperTest::prepareVirtualKeys() {
    mFakeEventHub->addVirtualKeyDefinition(EVENTHUB_ID, VIRTUAL_KEYS[0]);
    mFakeEventHub->addVirtualKeyDefinition(EVENTHUB_ID, VIRTUAL_KEYS[1]);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_HOME, 0, AKEYCODE_HOME, POLICY_FLAG_WAKE);
    mFakeEventHub->addKey(EVENTHUB_ID, KEY_MENU, 0, AKEYCODE_MENU, POLICY_FLAG_WAKE);
}

void TouchInputMapperTest::prepareLocationCalibration() {
    mFakePolicy->setTouchAffineTransformation(AFFINE_TRANSFORM);
}

int32_t TouchInputMapperTest::toRawX(float displayX) {
    return int32_t(displayX * (RAW_X_MAX - RAW_X_MIN + 1) / DISPLAY_WIDTH + RAW_X_MIN);
}

int32_t TouchInputMapperTest::toRawY(float displayY) {
    return int32_t(displayY * (RAW_Y_MAX - RAW_Y_MIN + 1) / DISPLAY_HEIGHT + RAW_Y_MIN);
}

int32_t TouchInputMapperTest::toRotatedRawX(float displayX) {
    return int32_t(displayX * (RAW_X_MAX - RAW_X_MIN + 1) / DISPLAY_HEIGHT + RAW_X_MIN);
}

int32_t TouchInputMapperTest::toRotatedRawY(float displayY) {
    return int32_t(displayY * (RAW_Y_MAX - RAW_Y_MIN + 1) / DISPLAY_WIDTH + RAW_Y_MIN);
}

float TouchInputMapperTest::toCookedX(float rawX, float rawY) {
    AFFINE_TRANSFORM.applyTo(rawX, rawY);
    return rawX;
}

float TouchInputMapperTest::toCookedY(float rawX, float rawY) {
    AFFINE_TRANSFORM.applyTo(rawX, rawY);
    return rawY;
}

float TouchInputMapperTest::toDisplayX(int32_t rawX) {
    return toDisplayX(rawX, DISPLAY_WIDTH);
}

float TouchInputMapperTest::toDisplayX(int32_t rawX, int32_t displayWidth) {
    return float(rawX - RAW_X_MIN) * displayWidth / (RAW_X_MAX - RAW_X_MIN + 1);
}

float TouchInputMapperTest::toDisplayY(int32_t rawY) {
    return toDisplayY(rawY, DISPLAY_HEIGHT);
}

float TouchInputMapperTest::toDisplayY(int32_t rawY, int32_t displayHeight) {
    return float(rawY - RAW_Y_MIN) * displayHeight / (RAW_Y_MAX - RAW_Y_MIN + 1);
}


// --- SingleTouchInputMapperTest ---

class SingleTouchInputMapperTest : public TouchInputMapperTest {
protected:
    void prepareButtons();
    void prepareAxes(int axes);

    void processDown(SingleTouchInputMapper& mapper, int32_t x, int32_t y);
    void processMove(SingleTouchInputMapper& mapper, int32_t x, int32_t y);
    void processUp(SingleTouchInputMapper& mappery);
    void processPressure(SingleTouchInputMapper& mapper, int32_t pressure);
    void processToolMajor(SingleTouchInputMapper& mapper, int32_t toolMajor);
    void processDistance(SingleTouchInputMapper& mapper, int32_t distance);
    void processTilt(SingleTouchInputMapper& mapper, int32_t tiltX, int32_t tiltY);
    void processKey(SingleTouchInputMapper& mapper, int32_t code, int32_t value);
    void processSync(SingleTouchInputMapper& mapper);
};

void SingleTouchInputMapperTest::prepareButtons() {
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_TOUCH, 0, AKEYCODE_UNKNOWN, 0);
}

void SingleTouchInputMapperTest::prepareAxes(int axes) {
    if (axes & POSITION) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_X, RAW_X_MIN, RAW_X_MAX, 0, 0);
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_Y, RAW_Y_MIN, RAW_Y_MAX, 0, 0);
    }
    if (axes & PRESSURE) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_PRESSURE, RAW_PRESSURE_MIN,
                                       RAW_PRESSURE_MAX, 0, 0);
    }
    if (axes & TOOL) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_TOOL_WIDTH, RAW_TOOL_MIN, RAW_TOOL_MAX, 0,
                                       0);
    }
    if (axes & DISTANCE) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_DISTANCE, RAW_DISTANCE_MIN,
                                       RAW_DISTANCE_MAX, 0, 0);
    }
    if (axes & TILT) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_TILT_X, RAW_TILT_MIN, RAW_TILT_MAX, 0, 0);
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_TILT_Y, RAW_TILT_MIN, RAW_TILT_MAX, 0, 0);
    }
}

void SingleTouchInputMapperTest::processDown(SingleTouchInputMapper& mapper, int32_t x, int32_t y) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, BTN_TOUCH, 1);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_X, x);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_Y, y);
}

void SingleTouchInputMapperTest::processMove(SingleTouchInputMapper& mapper, int32_t x, int32_t y) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_X, x);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_Y, y);
}

void SingleTouchInputMapperTest::processUp(SingleTouchInputMapper& mapper) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, BTN_TOUCH, 0);
}

void SingleTouchInputMapperTest::processPressure(SingleTouchInputMapper& mapper, int32_t pressure) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_PRESSURE, pressure);
}

void SingleTouchInputMapperTest::processToolMajor(SingleTouchInputMapper& mapper,
                                                  int32_t toolMajor) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_TOOL_WIDTH, toolMajor);
}

void SingleTouchInputMapperTest::processDistance(SingleTouchInputMapper& mapper, int32_t distance) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_DISTANCE, distance);
}

void SingleTouchInputMapperTest::processTilt(SingleTouchInputMapper& mapper, int32_t tiltX,
                                             int32_t tiltY) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_TILT_X, tiltX);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_TILT_Y, tiltY);
}

void SingleTouchInputMapperTest::processKey(SingleTouchInputMapper& mapper, int32_t code,
                                            int32_t value) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, code, value);
}

void SingleTouchInputMapperTest::processSync(SingleTouchInputMapper& mapper) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_SYN, SYN_REPORT, 0);
}

TEST_F(SingleTouchInputMapperTest, GetSources_WhenDeviceTypeIsNotSpecifiedAndNotACursor_ReturnsPointer) {
    prepareButtons();
    prepareAxes(POSITION);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    ASSERT_EQ(AINPUT_SOURCE_MOUSE, mapper.getSources());
}

TEST_F(SingleTouchInputMapperTest, GetSources_WhenDeviceTypeIsTouchScreen_ReturnsTouchScreen) {
    prepareButtons();
    prepareAxes(POSITION);
    addConfigurationProperty("touch.deviceType", "touchScreen");
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, mapper.getSources());
}

TEST_F(SingleTouchInputMapperTest, GetKeyCodeState) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    prepareVirtualKeys();
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    // Unknown key.
    ASSERT_EQ(AKEY_STATE_UNKNOWN, mapper.getKeyCodeState(AINPUT_SOURCE_ANY, AKEYCODE_A));

    // Virtual key is down.
    int32_t x = toRawX(VIRTUAL_KEYS[0].centerX);
    int32_t y = toRawY(VIRTUAL_KEYS[0].centerY);
    processDown(mapper, x, y);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled());

    ASSERT_EQ(AKEY_STATE_VIRTUAL, mapper.getKeyCodeState(AINPUT_SOURCE_ANY, AKEYCODE_HOME));

    // Virtual key is up.
    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled());

    ASSERT_EQ(AKEY_STATE_UP, mapper.getKeyCodeState(AINPUT_SOURCE_ANY, AKEYCODE_HOME));
}

TEST_F(SingleTouchInputMapperTest, GetScanCodeState) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    prepareVirtualKeys();
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    // Unknown key.
    ASSERT_EQ(AKEY_STATE_UNKNOWN, mapper.getScanCodeState(AINPUT_SOURCE_ANY, KEY_A));

    // Virtual key is down.
    int32_t x = toRawX(VIRTUAL_KEYS[0].centerX);
    int32_t y = toRawY(VIRTUAL_KEYS[0].centerY);
    processDown(mapper, x, y);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled());

    ASSERT_EQ(AKEY_STATE_VIRTUAL, mapper.getScanCodeState(AINPUT_SOURCE_ANY, KEY_HOME));

    // Virtual key is up.
    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled());

    ASSERT_EQ(AKEY_STATE_UP, mapper.getScanCodeState(AINPUT_SOURCE_ANY, KEY_HOME));
}

TEST_F(SingleTouchInputMapperTest, MarkSupportedKeyCodes) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    prepareVirtualKeys();
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    uint8_t flags[2] = { 0, 0 };
    ASSERT_TRUE(
            mapper.markSupportedKeyCodes(AINPUT_SOURCE_ANY, {AKEYCODE_HOME, AKEYCODE_A}, flags));
    ASSERT_TRUE(flags[0]);
    ASSERT_FALSE(flags[1]);
}

TEST_F(SingleTouchInputMapperTest, Process_WhenVirtualKeyIsPressedAndReleasedNormally_SendsKeyDownAndKeyUp) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    prepareVirtualKeys();
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    mReader->getContext()->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);

    NotifyKeyArgs args;

    // Press virtual key.
    int32_t x = toRawX(VIRTUAL_KEYS[0].centerX);
    int32_t y = toRawY(VIRTUAL_KEYS[0].centerY);
    processDown(mapper, x, y);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(ARBITRARY_TIME, args.eventTime);
    ASSERT_EQ(DEVICE_ID, args.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, args.source);
    ASSERT_EQ(POLICY_FLAG_VIRTUAL, args.policyFlags);
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, args.action);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM | AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY, args.flags);
    ASSERT_EQ(AKEYCODE_HOME, args.keyCode);
    ASSERT_EQ(KEY_HOME, args.scanCode);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, args.metaState);
    ASSERT_EQ(ARBITRARY_TIME, args.downTime);

    // Release virtual key.
    processUp(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(ARBITRARY_TIME, args.eventTime);
    ASSERT_EQ(DEVICE_ID, args.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, args.source);
    ASSERT_EQ(POLICY_FLAG_VIRTUAL, args.policyFlags);
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, args.action);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM | AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY, args.flags);
    ASSERT_EQ(AKEYCODE_HOME, args.keyCode);
    ASSERT_EQ(KEY_HOME, args.scanCode);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, args.metaState);
    ASSERT_EQ(ARBITRARY_TIME, args.downTime);

    // Should not have sent any motions.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasNotCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_WhenVirtualKeyIsPressedAndMovedOutOfBounds_SendsKeyDownAndKeyCancel) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    prepareVirtualKeys();
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    mReader->getContext()->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);

    NotifyKeyArgs keyArgs;

    // Press virtual key.
    int32_t x = toRawX(VIRTUAL_KEYS[0].centerX);
    int32_t y = toRawY(VIRTUAL_KEYS[0].centerY);
    processDown(mapper, x, y);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(ARBITRARY_TIME, keyArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, keyArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, keyArgs.source);
    ASSERT_EQ(POLICY_FLAG_VIRTUAL, keyArgs.policyFlags);
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, keyArgs.action);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM | AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY, keyArgs.flags);
    ASSERT_EQ(AKEYCODE_HOME, keyArgs.keyCode);
    ASSERT_EQ(KEY_HOME, keyArgs.scanCode);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, keyArgs.metaState);
    ASSERT_EQ(ARBITRARY_TIME, keyArgs.downTime);

    // Move out of bounds.  This should generate a cancel and a pointer down since we moved
    // into the display area.
    y -= 100;
    processMove(mapper, x, y);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(ARBITRARY_TIME, keyArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, keyArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_KEYBOARD, keyArgs.source);
    ASSERT_EQ(POLICY_FLAG_VIRTUAL, keyArgs.policyFlags);
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, keyArgs.action);
    ASSERT_EQ(AKEY_EVENT_FLAG_FROM_SYSTEM | AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY
            | AKEY_EVENT_FLAG_CANCELED, keyArgs.flags);
    ASSERT_EQ(AKEYCODE_HOME, keyArgs.keyCode);
    ASSERT_EQ(KEY_HOME, keyArgs.scanCode);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, keyArgs.metaState);
    ASSERT_EQ(ARBITRARY_TIME, keyArgs.downTime);

    NotifyMotionArgs motionArgs;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x), toDisplayY(y), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Keep moving out of bounds.  Should generate a pointer move.
    y -= 50;
    processMove(mapper, x, y);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x), toDisplayY(y), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Release out of bounds.  Should generate a pointer up.
    processUp(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x), toDisplayY(y), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Should not have sent any more keys or motions.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_WhenTouchStartsOutsideDisplayAndMovesIn_SendsDownAsTouchEntersDisplay) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    prepareVirtualKeys();
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    mReader->getContext()->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);

    NotifyMotionArgs motionArgs;

    // Initially go down out of bounds.
    int32_t x = -10;
    int32_t y = -10;
    processDown(mapper, x, y);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

    // Move into the display area.  Should generate a pointer down.
    x = 50;
    y = 75;
    processMove(mapper, x, y);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x), toDisplayY(y), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Release.  Should generate a pointer up.
    processUp(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x), toDisplayY(y), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Should not have sent any more keys or motions.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_NormalSingleTouchGesture_VirtualDisplay) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    addConfigurationProperty("touch.displayId", VIRTUAL_DISPLAY_UNIQUE_ID);

    prepareVirtualDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    prepareVirtualKeys();
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    mReader->getContext()->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);

    NotifyMotionArgs motionArgs;

    // Down.
    int32_t x = 100;
    int32_t y = 125;
    processDown(mapper, x, y);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(VIRTUAL_DISPLAY_ID, motionArgs.displayId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x, VIRTUAL_DISPLAY_WIDTH), toDisplayY(y, VIRTUAL_DISPLAY_HEIGHT),
            1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION_VIRTUAL, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION_VIRTUAL, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Move.
    x += 50;
    y += 75;
    processMove(mapper, x, y);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(VIRTUAL_DISPLAY_ID, motionArgs.displayId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x, VIRTUAL_DISPLAY_WIDTH), toDisplayY(y, VIRTUAL_DISPLAY_HEIGHT),
            1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION_VIRTUAL, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION_VIRTUAL, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Up.
    processUp(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(VIRTUAL_DISPLAY_ID, motionArgs.displayId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x, VIRTUAL_DISPLAY_WIDTH), toDisplayY(y, VIRTUAL_DISPLAY_HEIGHT),
            1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION_VIRTUAL, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION_VIRTUAL, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Should not have sent any more keys or motions.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_NormalSingleTouchGesture) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    prepareVirtualKeys();
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    mReader->getContext()->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);

    NotifyMotionArgs motionArgs;

    // Down.
    int32_t x = 100;
    int32_t y = 125;
    processDown(mapper, x, y);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x), toDisplayY(y), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Move.
    x += 50;
    y += 75;
    processMove(mapper, x, y);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x), toDisplayY(y), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Up.
    processUp(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x), toDisplayY(y), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Should not have sent any more keys or motions.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_WhenOrientationAware_DoesNotRotateMotions) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareButtons();
    prepareAxes(POSITION);
    // InputReader works in the un-rotated coordinate space, so orientation-aware devices do not
    // need to be rotated. Touchscreens are orientation-aware by default.
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    NotifyMotionArgs args;

    // Rotation 90.
    prepareDisplay(ui::ROTATION_90);
    processDown(mapper, toRawX(50), toRawY(75));
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    ASSERT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_WhenNotOrientationAware_RotatesMotions) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareButtons();
    prepareAxes(POSITION);
    // Since InputReader works in the un-rotated coordinate space, only devices that are not
    // orientation-aware are affected by display rotation.
    addConfigurationProperty("touch.orientationAware", "0");
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    NotifyMotionArgs args;

    // Rotation 0.
    clearViewports();
    prepareDisplay(ui::ROTATION_0);
    processDown(mapper, toRawX(50), toRawY(75));
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    ASSERT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());

    // Rotation 90.
    clearViewports();
    prepareDisplay(ui::ROTATION_90);
    processDown(mapper, toRotatedRawX(75), RAW_Y_MAX - toRotatedRawY(50) + RAW_Y_MIN);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    ASSERT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());

    // Rotation 180.
    clearViewports();
    prepareDisplay(ui::ROTATION_180);
    processDown(mapper, RAW_X_MAX - toRawX(50) + RAW_X_MIN, RAW_Y_MAX - toRawY(75) + RAW_Y_MIN);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    ASSERT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());

    // Rotation 270.
    clearViewports();
    prepareDisplay(ui::ROTATION_270);
    processDown(mapper, RAW_X_MAX - toRotatedRawX(75) + RAW_X_MIN, toRotatedRawY(50));
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    ASSERT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_WhenOrientation0_RotatesMotions) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareButtons();
    prepareAxes(POSITION);
    addConfigurationProperty("touch.orientationAware", "1");
    addConfigurationProperty("touch.orientation", "ORIENTATION_0");
    clearViewports();
    prepareDisplay(ui::ROTATION_0);
    auto& mapper = constructAndAddMapper<SingleTouchInputMapper>();
    NotifyMotionArgs args;

    // Orientation 0.
    processDown(mapper, toRawX(50), toRawY(75));
    processSync(mapper);

    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    EXPECT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    EXPECT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_WhenOrientation90_RotatesMotions) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareButtons();
    prepareAxes(POSITION);
    addConfigurationProperty("touch.orientationAware", "1");
    addConfigurationProperty("touch.orientation", "ORIENTATION_90");
    clearViewports();
    prepareDisplay(ui::ROTATION_0);
    auto& mapper = constructAndAddMapper<SingleTouchInputMapper>();
    NotifyMotionArgs args;

    // Orientation 90.
    processDown(mapper, RAW_X_MAX - toRotatedRawX(75) + RAW_X_MIN, toRotatedRawY(50));
    processSync(mapper);

    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    EXPECT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    EXPECT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_WhenOrientation180_RotatesMotions) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareButtons();
    prepareAxes(POSITION);
    addConfigurationProperty("touch.orientationAware", "1");
    addConfigurationProperty("touch.orientation", "ORIENTATION_180");
    clearViewports();
    prepareDisplay(ui::ROTATION_0);
    auto& mapper = constructAndAddMapper<SingleTouchInputMapper>();
    NotifyMotionArgs args;

    // Orientation 180.
    processDown(mapper, RAW_X_MAX - toRawX(50) + RAW_X_MIN, RAW_Y_MAX - toRawY(75) + RAW_Y_MIN);
    processSync(mapper);

    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    EXPECT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    EXPECT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_WhenOrientation270_RotatesMotions) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareButtons();
    prepareAxes(POSITION);
    addConfigurationProperty("touch.orientationAware", "1");
    addConfigurationProperty("touch.orientation", "ORIENTATION_270");
    clearViewports();
    prepareDisplay(ui::ROTATION_0);
    auto& mapper = constructAndAddMapper<SingleTouchInputMapper>();
    NotifyMotionArgs args;

    // Orientation 270.
    processDown(mapper, toRotatedRawX(75), RAW_Y_MAX - toRotatedRawY(50) + RAW_Y_MIN);
    processSync(mapper);

    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    EXPECT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    EXPECT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_WhenOrientationSpecified_RotatesMotionWithDisplay) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareButtons();
    prepareAxes(POSITION);
    // Since InputReader works in the un-rotated coordinate space, only devices that are not
    // orientation-aware are affected by display rotation.
    addConfigurationProperty("touch.orientationAware", "0");
    addConfigurationProperty("touch.orientation", "ORIENTATION_90");
    auto& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    NotifyMotionArgs args;

    // Orientation 90, Rotation 0.
    clearViewports();
    prepareDisplay(ui::ROTATION_0);
    processDown(mapper, RAW_X_MAX - toRotatedRawX(75) + RAW_X_MIN, toRotatedRawY(50));
    processSync(mapper);

    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    EXPECT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    EXPECT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());

    // Orientation 90, Rotation 90.
    clearViewports();
    prepareDisplay(ui::ROTATION_90);
    processDown(mapper, toRawX(50), toRawY(75));
    processSync(mapper);

    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    EXPECT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    EXPECT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());

    // Orientation 90, Rotation 180.
    clearViewports();
    prepareDisplay(ui::ROTATION_180);
    processDown(mapper, toRotatedRawX(75), RAW_Y_MAX - toRotatedRawY(50) + RAW_Y_MIN);
    processSync(mapper);

    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    EXPECT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    EXPECT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());

    // Orientation 90, Rotation 270.
    clearViewports();
    prepareDisplay(ui::ROTATION_270);
    processDown(mapper, RAW_X_MAX - toRawX(50) + RAW_X_MIN, RAW_Y_MAX - toRawY(75) + RAW_Y_MIN);
    processSync(mapper);

    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    EXPECT_NEAR(50, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    EXPECT_NEAR(75, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    processUp(mapper);
    processSync(mapper);
    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());
}

TEST_F(SingleTouchInputMapperTest, Process_IgnoresTouchesOutsidePhysicalFrame) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareButtons();
    prepareAxes(POSITION);
    addConfigurationProperty("touch.orientationAware", "1");
    prepareDisplay(ui::ROTATION_0);
    auto& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    // Set a physical frame in the display viewport.
    auto viewport = mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
    viewport->physicalLeft = 20;
    viewport->physicalTop = 600;
    viewport->physicalRight = 30;
    viewport->physicalBottom = 610;
    mFakePolicy->updateViewport(*viewport);
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);

    // Start the touch.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, BTN_TOUCH, 1);
    processSync(mapper);

    // Expect all input starting outside the physical frame to be ignored.
    const std::array<Point, 6> outsidePoints = {
            {{0, 0}, {19, 605}, {31, 605}, {25, 599}, {25, 611}, {DISPLAY_WIDTH, DISPLAY_HEIGHT}}};
    for (const auto& p : outsidePoints) {
        processMove(mapper, toRawX(p.x), toRawY(p.y));
        processSync(mapper);
        EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    }

    // Move the touch into the physical frame.
    processMove(mapper, toRawX(25), toRawY(605));
    processSync(mapper);
    NotifyMotionArgs args;
    EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    EXPECT_EQ(AMOTION_EVENT_ACTION_DOWN, args.action);
    EXPECT_NEAR(25, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
    EXPECT_NEAR(605, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);

    // Once the touch down is reported, continue reporting input, even if it is outside the frame.
    for (const auto& p : outsidePoints) {
        processMove(mapper, toRawX(p.x), toRawY(p.y));
        processSync(mapper);
        EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
        EXPECT_EQ(AMOTION_EVENT_ACTION_MOVE, args.action);
        EXPECT_NEAR(p.x, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X), 1);
        EXPECT_NEAR(p.y, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y), 1);
    }

    processUp(mapper);
    processSync(mapper);
    EXPECT_NO_FATAL_FAILURE(
            mFakeListener->assertNotifyMotionWasCalled(WithMotionAction(AMOTION_EVENT_ACTION_UP)));
}

TEST_F(SingleTouchInputMapperTest, Process_DoesntCheckPhysicalFrameForTouchpads) {
    std::shared_ptr<FakePointerController> fakePointerController =
            std::make_shared<FakePointerController>();
    mFakePolicy->setPointerController(fakePointerController);

    addConfigurationProperty("touch.deviceType", "pointer");
    prepareAxes(POSITION);
    prepareDisplay(ui::ROTATION_0);
    auto& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    // Set a physical frame in the display viewport.
    auto viewport = mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
    viewport->physicalLeft = 20;
    viewport->physicalTop = 600;
    viewport->physicalRight = 30;
    viewport->physicalBottom = 610;
    mFakePolicy->updateViewport(*viewport);
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);

    // Start the touch.
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, BTN_TOUCH, 1);
    processSync(mapper);

    // Expect all input starting outside the physical frame to result in NotifyMotionArgs being
    // produced.
    const std::array<Point, 6> outsidePoints = {
            {{0, 0}, {19, 605}, {31, 605}, {25, 599}, {25, 611}, {DISPLAY_WIDTH, DISPLAY_HEIGHT}}};
    for (const auto& p : outsidePoints) {
        processMove(mapper, toRawX(p.x), toRawY(p.y));
        processSync(mapper);
        EXPECT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled());
    }
}

TEST_F(SingleTouchInputMapperTest, Process_AllAxes_DefaultCalibration) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION | PRESSURE | TOOL | DISTANCE | TILT);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    // These calculations are based on the input device calibration documentation.
    int32_t rawX = 100;
    int32_t rawY = 200;
    int32_t rawPressure = 10;
    int32_t rawToolMajor = 12;
    int32_t rawDistance = 2;
    int32_t rawTiltX = 30;
    int32_t rawTiltY = 110;

    float x = toDisplayX(rawX);
    float y = toDisplayY(rawY);
    float pressure = float(rawPressure) / RAW_PRESSURE_MAX;
    float size = float(rawToolMajor) / RAW_TOOL_MAX;
    float tool = float(rawToolMajor) * GEOMETRIC_SCALE;
    float distance = float(rawDistance);

    float tiltCenter = (RAW_TILT_MAX + RAW_TILT_MIN) * 0.5f;
    float tiltScale = M_PI / 180;
    float tiltXAngle = (rawTiltX - tiltCenter) * tiltScale;
    float tiltYAngle = (rawTiltY - tiltCenter) * tiltScale;
    float orientation = atan2f(-sinf(tiltXAngle), sinf(tiltYAngle));
    float tilt = acosf(cosf(tiltXAngle) * cosf(tiltYAngle));

    processDown(mapper, rawX, rawY);
    processPressure(mapper, rawPressure);
    processToolMajor(mapper, rawToolMajor);
    processDistance(mapper, rawDistance);
    processTilt(mapper, rawTiltX, rawTiltY);
    processSync(mapper);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(args.pointerCoords[0],
            x, y, pressure, size, tool, tool, tool, tool, orientation, distance));
    ASSERT_EQ(tilt, args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_TILT));
}

TEST_F(SingleTouchInputMapperTest, Process_XYAxes_AffineCalibration) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareLocationCalibration();
    prepareButtons();
    prepareAxes(POSITION);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    int32_t rawX = 100;
    int32_t rawY = 200;

    float x = toDisplayX(toCookedX(rawX, rawY));
    float y = toDisplayY(toCookedY(rawX, rawY));

    processDown(mapper, rawX, rawY);
    processSync(mapper);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(args.pointerCoords[0],
            x, y, 1, 0, 0, 0, 0, 0, 0, 0));
}

TEST_F(SingleTouchInputMapperTest, Process_ShouldHandleAllButtons) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    NotifyMotionArgs motionArgs;
    NotifyKeyArgs keyArgs;

    processDown(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    // press BTN_LEFT, release BTN_LEFT
    processKey(mapper, BTN_LEFT, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_PRIMARY, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_PRIMARY, motionArgs.buttonState);

    processKey(mapper, BTN_LEFT, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    // press BTN_RIGHT + BTN_MIDDLE, release BTN_RIGHT, release BTN_MIDDLE
    processKey(mapper, BTN_RIGHT, 1);
    processKey(mapper, BTN_MIDDLE, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_SECONDARY | AMOTION_EVENT_BUTTON_TERTIARY,
            motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_TERTIARY, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_SECONDARY | AMOTION_EVENT_BUTTON_TERTIARY,
            motionArgs.buttonState);

    processKey(mapper, BTN_RIGHT, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_TERTIARY, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_TERTIARY, motionArgs.buttonState);

    processKey(mapper, BTN_MIDDLE, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    // press BTN_BACK, release BTN_BACK
    processKey(mapper, BTN_BACK, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, keyArgs.action);
    ASSERT_EQ(AKEYCODE_BACK, keyArgs.keyCode);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_BACK, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_BACK, motionArgs.buttonState);

    processKey(mapper, BTN_BACK, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, keyArgs.action);
    ASSERT_EQ(AKEYCODE_BACK, keyArgs.keyCode);

    // press BTN_SIDE, release BTN_SIDE
    processKey(mapper, BTN_SIDE, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, keyArgs.action);
    ASSERT_EQ(AKEYCODE_BACK, keyArgs.keyCode);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_BACK, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_BACK, motionArgs.buttonState);

    processKey(mapper, BTN_SIDE, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, keyArgs.action);
    ASSERT_EQ(AKEYCODE_BACK, keyArgs.keyCode);

    // press BTN_FORWARD, release BTN_FORWARD
    processKey(mapper, BTN_FORWARD, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, keyArgs.action);
    ASSERT_EQ(AKEYCODE_FORWARD, keyArgs.keyCode);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_FORWARD, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_FORWARD, motionArgs.buttonState);

    processKey(mapper, BTN_FORWARD, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, keyArgs.action);
    ASSERT_EQ(AKEYCODE_FORWARD, keyArgs.keyCode);

    // press BTN_EXTRA, release BTN_EXTRA
    processKey(mapper, BTN_EXTRA, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, keyArgs.action);
    ASSERT_EQ(AKEYCODE_FORWARD, keyArgs.keyCode);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_FORWARD, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_FORWARD, motionArgs.buttonState);

    processKey(mapper, BTN_EXTRA, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, keyArgs.action);
    ASSERT_EQ(AKEYCODE_FORWARD, keyArgs.keyCode);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasNotCalled());

    // press BTN_STYLUS, release BTN_STYLUS
    processKey(mapper, BTN_STYLUS, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY, motionArgs.buttonState);

    processKey(mapper, BTN_STYLUS, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    // press BTN_STYLUS2, release BTN_STYLUS2
    processKey(mapper, BTN_STYLUS2, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_STYLUS_SECONDARY, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_STYLUS_SECONDARY, motionArgs.buttonState);

    processKey(mapper, BTN_STYLUS2, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    // release touch
    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);
}

TEST_F(SingleTouchInputMapperTest, Process_ShouldHandleAllToolTypes) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // default tool type is finger
    processDown(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // eraser
    processKey(mapper, BTN_TOOL_RUBBER, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::ERASER, motionArgs.pointerProperties[0].toolType);

    // stylus
    processKey(mapper, BTN_TOOL_RUBBER, 0);
    processKey(mapper, BTN_TOOL_PEN, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::STYLUS, motionArgs.pointerProperties[0].toolType);

    // brush
    processKey(mapper, BTN_TOOL_PEN, 0);
    processKey(mapper, BTN_TOOL_BRUSH, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::STYLUS, motionArgs.pointerProperties[0].toolType);

    // pencil
    processKey(mapper, BTN_TOOL_BRUSH, 0);
    processKey(mapper, BTN_TOOL_PENCIL, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::STYLUS, motionArgs.pointerProperties[0].toolType);

    // air-brush
    processKey(mapper, BTN_TOOL_PENCIL, 0);
    processKey(mapper, BTN_TOOL_AIRBRUSH, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::STYLUS, motionArgs.pointerProperties[0].toolType);

    // mouse
    processKey(mapper, BTN_TOOL_AIRBRUSH, 0);
    processKey(mapper, BTN_TOOL_MOUSE, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::MOUSE, motionArgs.pointerProperties[0].toolType);

    // lens
    processKey(mapper, BTN_TOOL_MOUSE, 0);
    processKey(mapper, BTN_TOOL_LENS, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::MOUSE, motionArgs.pointerProperties[0].toolType);

    // double-tap
    processKey(mapper, BTN_TOOL_LENS, 0);
    processKey(mapper, BTN_TOOL_DOUBLETAP, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // triple-tap
    processKey(mapper, BTN_TOOL_DOUBLETAP, 0);
    processKey(mapper, BTN_TOOL_TRIPLETAP, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // quad-tap
    processKey(mapper, BTN_TOOL_TRIPLETAP, 0);
    processKey(mapper, BTN_TOOL_QUADTAP, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // finger
    processKey(mapper, BTN_TOOL_QUADTAP, 0);
    processKey(mapper, BTN_TOOL_FINGER, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // stylus trumps finger
    processKey(mapper, BTN_TOOL_PEN, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::STYLUS, motionArgs.pointerProperties[0].toolType);

    // eraser trumps stylus
    processKey(mapper, BTN_TOOL_RUBBER, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::ERASER, motionArgs.pointerProperties[0].toolType);

    // mouse trumps eraser
    processKey(mapper, BTN_TOOL_MOUSE, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::MOUSE, motionArgs.pointerProperties[0].toolType);

    // back to default tool type
    processKey(mapper, BTN_TOOL_MOUSE, 0);
    processKey(mapper, BTN_TOOL_RUBBER, 0);
    processKey(mapper, BTN_TOOL_PEN, 0);
    processKey(mapper, BTN_TOOL_FINGER, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
}

TEST_F(SingleTouchInputMapperTest, Process_WhenBtnTouchPresent_HoversIfItsValueIsZero) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_TOOL_FINGER, 0, AKEYCODE_UNKNOWN, 0);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // initially hovering because BTN_TOUCH not sent yet, pressure defaults to 0
    processKey(mapper, BTN_TOOL_FINGER, 1);
    processMove(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_ENTER, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(100), toDisplayY(200), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(100), toDisplayY(200), 0, 0, 0, 0, 0, 0, 0, 0));

    // move a little
    processMove(mapper, 150, 250);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    // down when BTN_TOUCH is pressed, pressure defaults to 1
    processKey(mapper, BTN_TOUCH, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_EXIT, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 1, 0, 0, 0, 0, 0, 0, 0));

    // up when BTN_TOUCH is released, hover restored
    processKey(mapper, BTN_TOUCH, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 1, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_ENTER, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    // exit hover when pointer goes away
    processKey(mapper, BTN_TOOL_FINGER, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_EXIT, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));
}

TEST_F(SingleTouchInputMapperTest, Process_WhenAbsPressureIsPresent_HoversIfItsValueIsZero) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION | PRESSURE);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // initially hovering because pressure is 0
    processDown(mapper, 100, 200);
    processPressure(mapper, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_ENTER, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(100), toDisplayY(200), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(100), toDisplayY(200), 0, 0, 0, 0, 0, 0, 0, 0));

    // move a little
    processMove(mapper, 150, 250);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    // down when pressure is non-zero
    processPressure(mapper, RAW_PRESSURE_MAX);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_EXIT, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 1, 0, 0, 0, 0, 0, 0, 0));

    // up when pressure becomes 0, hover restored
    processPressure(mapper, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 1, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_ENTER, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    // exit hover when pointer goes away
    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_EXIT, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));
}

TEST_F(SingleTouchInputMapperTest, Reset_CancelsOngoingGesture) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION | PRESSURE);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    // Touch down.
    processDown(mapper, 100, 200);
    processPressure(mapper, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_DOWN)));

    // Reset the mapper. This should cancel the ongoing gesture.
    resetMapper(mapper, ARBITRARY_TIME);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_CANCEL)));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(SingleTouchInputMapperTest, Reset_RecreatesTouchState) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION | PRESSURE);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    // Set the initial state for the touch pointer.
    mFakeEventHub->setAbsoluteAxisValue(EVENTHUB_ID, ABS_X, 100);
    mFakeEventHub->setAbsoluteAxisValue(EVENTHUB_ID, ABS_Y, 200);
    mFakeEventHub->setAbsoluteAxisValue(EVENTHUB_ID, ABS_PRESSURE, RAW_PRESSURE_MAX);
    mFakeEventHub->setScanCodeState(EVENTHUB_ID, BTN_TOUCH, 1);

    // Reset the mapper. When the mapper is reset, we expect it to attempt to recreate the touch
    // state by reading the current axis values. Since there was no ongoing gesture, calling reset
    // does not generate any events.
    resetMapper(mapper, ARBITRARY_TIME);

    // Send a sync to simulate an empty touch frame where nothing changes. The mapper should use
    // the recreated touch state to generate a down event.
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithPressure(1.f))));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(SingleTouchInputMapperTest,
       Process_WhenViewportDisplayIdChanged_TouchIsCanceledAndDeviceIsReset) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();
    NotifyMotionArgs motionArgs;

    // Down.
    processDown(mapper, 100, 200);
    processSync(mapper);

    // We should receive a down event
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);

    // Change display id
    clearViewports();
    prepareSecondaryDisplay(ViewportType::INTERNAL);

    // We should receive a cancel event
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_CANCEL, motionArgs.action);
    // Then receive reset called
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled());
}

TEST_F(SingleTouchInputMapperTest,
       Process_WhenViewportActiveStatusChanged_TouchIsCanceledAndDeviceIsReset) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled());
    NotifyMotionArgs motionArgs;

    // Start a new gesture.
    processDown(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);

    // Make the viewport inactive. This will put the device in disabled mode.
    auto viewport = mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
    viewport->isActive = false;
    mFakePolicy->updateViewport(*viewport);
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);

    // We should receive a cancel event for the ongoing gesture.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_CANCEL, motionArgs.action);
    // Then we should be notified that the device was reset.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled());

    // No events are generated while the viewport is inactive.
    processMove(mapper, 101, 201);
    processSync(mapper);
    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

    // Start a new gesture while the viewport is still inactive.
    processDown(mapper, 300, 400);
    mFakeEventHub->setAbsoluteAxisValue(EVENTHUB_ID, ABS_X, 300);
    mFakeEventHub->setAbsoluteAxisValue(EVENTHUB_ID, ABS_Y, 400);
    mFakeEventHub->setScanCodeState(EVENTHUB_ID, BTN_TOUCH, 1);
    processSync(mapper);

    // Make the viewport active again. The device should resume processing events.
    viewport->isActive = true;
    mFakePolicy->updateViewport(*viewport);
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);

    // The device is reset because it changes back to direct mode, without generating any events.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

    // In the next sync, the touch state that was recreated when the device was reset is reported.
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_DOWN)));

    // No more events.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasNotCalled());
}

TEST_F(SingleTouchInputMapperTest, ButtonIsReleasedOnTouchUp) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled());

    // Press a stylus button.
    processKey(mapper, BTN_STYLUS, 1);
    processSync(mapper);

    // Start a touch gesture and ensure the BUTTON_PRESS event is generated.
    processDown(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithCoords(toDisplayX(100), toDisplayY(200)),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                  WithCoords(toDisplayX(100), toDisplayY(200)),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));

    // Release the touch gesture. Ensure that the BUTTON_RELEASE event is generated even though
    // the button has not actually been released, since there will be no pointers through which the
    // button state can be reported. The event is generated at the location of the pointer before
    // it went up.
    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                  WithCoords(toDisplayX(100), toDisplayY(200)), WithButtonState(0))));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                  WithCoords(toDisplayX(100), toDisplayY(200)), WithButtonState(0))));
}

TEST_F(SingleTouchInputMapperTest, StylusButtonMotionEventsDisabled) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);

    mFakePolicy->setStylusButtonMotionEventsEnabled(false);

    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled());

    // Press a stylus button.
    processKey(mapper, BTN_STYLUS, 1);
    processSync(mapper);

    // Start a touch gesture and ensure that the stylus button is not reported.
    processDown(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithButtonState(0))));

    // Release and press the stylus button again.
    processKey(mapper, BTN_STYLUS, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithButtonState(0))));
    processKey(mapper, BTN_STYLUS, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithButtonState(0))));

    // Release the touch gesture.
    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP), WithButtonState(0))));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(SingleTouchInputMapperTest, WhenDeviceTypeIsSetToTouchNavigation_setsCorrectType) {
    mFakePolicy->addDeviceTypeAssociation(DEVICE_LOCATION, "touchNavigation");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled());

    ASSERT_EQ(AINPUT_SOURCE_TOUCH_NAVIGATION, mapper.getSources());
}

TEST_F(SingleTouchInputMapperTest, Process_WhenConfigEnabled_ShouldShowDirectStylusPointer) {
    std::shared_ptr<FakePointerController> fakePointerController =
            std::make_shared<FakePointerController>();
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_TOOL_PEN, 0, AKEYCODE_UNKNOWN, 0);
    mFakePolicy->setPointerController(fakePointerController);
    mFakePolicy->setStylusPointerIconEnabled(true);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    processKey(mapper, BTN_TOOL_PEN, 1);
    processMove(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                  WithToolType(ToolType::STYLUS),
                  WithPointerCoords(0, toDisplayX(100), toDisplayY(200)))));
    ASSERT_TRUE(fakePointerController->isPointerShown());
    ASSERT_NO_FATAL_FAILURE(
            fakePointerController->assertPosition(toDisplayX(100), toDisplayY(200)));
}

TEST_F(SingleTouchInputMapperTest, Process_WhenConfigDisabled_ShouldNotShowDirectStylusPointer) {
    std::shared_ptr<FakePointerController> fakePointerController =
            std::make_shared<FakePointerController>();
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_TOOL_PEN, 0, AKEYCODE_UNKNOWN, 0);
    mFakePolicy->setPointerController(fakePointerController);
    mFakePolicy->setStylusPointerIconEnabled(false);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    processKey(mapper, BTN_TOOL_PEN, 1);
    processMove(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                  WithToolType(ToolType::STYLUS),
                  WithPointerCoords(0, toDisplayX(100), toDisplayY(200)))));
    ASSERT_FALSE(fakePointerController->isPointerShown());
}

TEST_F(SingleTouchInputMapperTest, WhenDeviceTypeIsChangedToTouchNavigation_updatesDeviceType) {
    // Initialize the device without setting device source to touch navigation.
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    // Ensure that the device is created as a touchscreen, not touch navigation.
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, mapper.getSources());

    // Add device type association after the device was created.
    mFakePolicy->addDeviceTypeAssociation(DEVICE_LOCATION, "touchNavigation");

    // Send update to the mapper.
    std::list<NotifyArgs> unused2 =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               InputReaderConfiguration::Change::DEVICE_TYPE /*changes*/);

    // Check whether device type update was successful.
    ASSERT_EQ(AINPUT_SOURCE_TOUCH_NAVIGATION, mDevice->getSources());
}

TEST_F(SingleTouchInputMapperTest, HoverEventsOutsidePhysicalFrameAreIgnored) {
    // Initialize the device without setting device source to touch navigation.
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareButtons();
    prepareAxes(POSITION);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_TOOL_PEN, 0, AKEYCODE_UNKNOWN, 0);

    // Set a physical frame in the display viewport.
    auto viewport = mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
    viewport->physicalLeft = 0;
    viewport->physicalTop = 0;
    viewport->physicalRight = DISPLAY_WIDTH / 2;
    viewport->physicalBottom = DISPLAY_HEIGHT / 2;
    mFakePolicy->updateViewport(*viewport);
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);

    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    // Hovering inside the physical frame produces events.
    processKey(mapper, BTN_TOOL_PEN, 1);
    processMove(mapper, RAW_X_MIN + 1, RAW_Y_MIN + 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER)));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE)));

    // Leaving the physical frame ends the hovering gesture.
    processMove(mapper, RAW_X_MAX - 1, RAW_Y_MAX - 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT)));

    // Moving outside the physical frame does not produce events.
    processMove(mapper, RAW_X_MAX - 2, RAW_Y_MAX - 2);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

    // Re-entering the physical frame produces events.
    processMove(mapper, RAW_X_MIN, RAW_Y_MIN);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER)));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE)));
}

// --- TouchDisplayProjectionTest ---

class TouchDisplayProjectionTest : public SingleTouchInputMapperTest {
public:
    // The values inside DisplayViewport are expected to be pre-rotated. This updates the current
    // DisplayViewport to pre-rotate the values. The viewport's physical display will be set to the
    // rotated equivalent of the given un-rotated physical display bounds.
    void configurePhysicalDisplay(ui::Rotation orientation, Rect naturalPhysicalDisplay,
                                  int32_t naturalDisplayWidth = DISPLAY_WIDTH,
                                  int32_t naturalDisplayHeight = DISPLAY_HEIGHT) {
        uint32_t inverseRotationFlags;
        auto rotatedWidth = naturalDisplayWidth;
        auto rotatedHeight = naturalDisplayHeight;
        switch (orientation) {
            case ui::ROTATION_90:
                inverseRotationFlags = ui::Transform::ROT_270;
                std::swap(rotatedWidth, rotatedHeight);
                break;
            case ui::ROTATION_180:
                inverseRotationFlags = ui::Transform::ROT_180;
                break;
            case ui::ROTATION_270:
                inverseRotationFlags = ui::Transform::ROT_90;
                std::swap(rotatedWidth, rotatedHeight);
                break;
            case ui::ROTATION_0:
                inverseRotationFlags = ui::Transform::ROT_0;
                break;
        }

        const ui::Transform rotation(inverseRotationFlags, rotatedWidth, rotatedHeight);
        const Rect rotatedPhysicalDisplay = rotation.transform(naturalPhysicalDisplay);

        std::optional<DisplayViewport> internalViewport =
                *mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
        DisplayViewport& v = *internalViewport;
        v.displayId = DISPLAY_ID;
        v.orientation = orientation;

        v.logicalLeft = 0;
        v.logicalTop = 0;
        v.logicalRight = 100;
        v.logicalBottom = 100;

        v.physicalLeft = rotatedPhysicalDisplay.left;
        v.physicalTop = rotatedPhysicalDisplay.top;
        v.physicalRight = rotatedPhysicalDisplay.right;
        v.physicalBottom = rotatedPhysicalDisplay.bottom;

        v.deviceWidth = rotatedWidth;
        v.deviceHeight = rotatedHeight;

        v.isActive = true;
        v.uniqueId = UNIQUE_ID;
        v.type = ViewportType::INTERNAL;
        mFakePolicy->updateViewport(v);
        configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);
    }

    void assertReceivedMove(const Point& point) {
        NotifyMotionArgs motionArgs;
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
        ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
        ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
        ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0], point.x, point.y,
                                                    1, 0, 0, 0, 0, 0, 0, 0));
    }
};

TEST_F(TouchDisplayProjectionTest, IgnoresTouchesOutsidePhysicalDisplay) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);

    prepareButtons();
    prepareAxes(POSITION);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // Configure the DisplayViewport such that the logical display maps to a subsection of
    // the display panel called the physical display. Here, the physical display is bounded by the
    // points (10, 20) and (70, 160) inside the display space, which is of the size 400 x 800.
    static const Rect kPhysicalDisplay{10, 20, 70, 160};
    static const std::array<Point, 6> kPointsOutsidePhysicalDisplay{
            {{-10, -10}, {0, 0}, {5, 100}, {50, 15}, {75, 100}, {50, 165}}};

    for (auto orientation : {ui::ROTATION_0, ui::ROTATION_90, ui::ROTATION_180, ui::ROTATION_270}) {
        configurePhysicalDisplay(orientation, kPhysicalDisplay);

        // Touches outside the physical display should be ignored, and should not generate any
        // events. Ensure touches at the following points that lie outside of the physical display
        // area do not generate any events.
        for (const auto& point : kPointsOutsidePhysicalDisplay) {
            processDown(mapper, toRawX(point.x), toRawY(point.y));
            processSync(mapper);
            processUp(mapper);
            processSync(mapper);
            ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled())
                    << "Unexpected event generated for touch outside physical display at point: "
                    << point.x << ", " << point.y;
        }
    }
}

TEST_F(TouchDisplayProjectionTest, EmitsTouchDownAfterEnteringPhysicalDisplay) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);

    prepareButtons();
    prepareAxes(POSITION);
    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // Configure the DisplayViewport such that the logical display maps to a subsection of
    // the display panel called the physical display. Here, the physical display is bounded by the
    // points (10, 20) and (70, 160) inside the display space, which is of the size 400 x 800.
    static const Rect kPhysicalDisplay{10, 20, 70, 160};

    for (auto orientation : {ui::ROTATION_0, ui::ROTATION_90, ui::ROTATION_180, ui::ROTATION_270}) {
        configurePhysicalDisplay(orientation, kPhysicalDisplay);

        // Touches that start outside the physical display should be ignored until it enters the
        // physical display bounds, at which point it should generate a down event. Start a touch at
        // the point (5, 100), which is outside the physical display bounds.
        static const Point kOutsidePoint{5, 100};
        processDown(mapper, toRawX(kOutsidePoint.x), toRawY(kOutsidePoint.y));
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

        // Move the touch into the physical display area. This should generate a pointer down.
        processMove(mapper, toRawX(11), toRawY(21));
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
        ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
        ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
        ASSERT_NO_FATAL_FAILURE(
                assertPointerCoords(motionArgs.pointerCoords[0], 11, 21, 1, 0, 0, 0, 0, 0, 0, 0));

        // Move the touch inside the physical display area. This should generate a pointer move.
        processMove(mapper, toRawX(69), toRawY(159));
        processSync(mapper);
        assertReceivedMove({69, 159});

        // Move outside the physical display area. Since the pointer is already down, this should
        // now continue generating events.
        processMove(mapper, toRawX(kOutsidePoint.x), toRawY(kOutsidePoint.y));
        processSync(mapper);
        assertReceivedMove(kOutsidePoint);

        // Release. This should generate a pointer up.
        processUp(mapper);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
        ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
        ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0], kOutsidePoint.x,
                                                    kOutsidePoint.y, 1, 0, 0, 0, 0, 0, 0, 0));

        // Ensure no more events were generated.
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasNotCalled());
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    }
}

// --- TouchscreenPrecisionTests ---

// This test suite is used to ensure that touchscreen devices are scaled and configured correctly
// in various orientations and with different display rotations. We configure the touchscreen to
// have a higher resolution than that of the display by an integer scale factor in each axis so that
// we can enforce that coordinates match precisely as expected.
class TouchscreenPrecisionTestsFixture : public TouchDisplayProjectionTest,
                                         public ::testing::WithParamInterface<ui::Rotation> {
public:
    void SetUp() override {
        SingleTouchInputMapperTest::SetUp();

        // Prepare the raw axes to have twice the resolution of the display in the X axis and
        // four times the resolution of the display in the Y axis.
        prepareButtons();
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_X, PRECISION_RAW_X_MIN, PRECISION_RAW_X_MAX,
                                       PRECISION_RAW_X_FLAT, PRECISION_RAW_X_FUZZ,
                                       PRECISION_RAW_X_RES);
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_Y, PRECISION_RAW_Y_MIN, PRECISION_RAW_Y_MAX,
                                       PRECISION_RAW_Y_FLAT, PRECISION_RAW_Y_FUZZ,
                                       PRECISION_RAW_Y_RES);
    }

    static const int32_t PRECISION_RAW_X_MIN = TouchInputMapperTest::RAW_X_MIN;
    static const int32_t PRECISION_RAW_X_MAX = PRECISION_RAW_X_MIN + DISPLAY_WIDTH * 2 - 1;
    static const int32_t PRECISION_RAW_Y_MIN = TouchInputMapperTest::RAW_Y_MIN;
    static const int32_t PRECISION_RAW_Y_MAX = PRECISION_RAW_Y_MIN + DISPLAY_HEIGHT * 4 - 1;

    static const int32_t PRECISION_RAW_X_RES = 50;  // units per millimeter
    static const int32_t PRECISION_RAW_Y_RES = 100; // units per millimeter

    static const int32_t PRECISION_RAW_X_FLAT = 16;
    static const int32_t PRECISION_RAW_Y_FLAT = 32;

    static const int32_t PRECISION_RAW_X_FUZZ = 4;
    static const int32_t PRECISION_RAW_Y_FUZZ = 8;

    static const std::array<Point, 4> kRawCorners;
};

const std::array<Point, 4> TouchscreenPrecisionTestsFixture::kRawCorners = {{
        {PRECISION_RAW_X_MIN, PRECISION_RAW_Y_MIN}, // left-top
        {PRECISION_RAW_X_MAX, PRECISION_RAW_Y_MIN}, // right-top
        {PRECISION_RAW_X_MAX, PRECISION_RAW_Y_MAX}, // right-bottom
        {PRECISION_RAW_X_MIN, PRECISION_RAW_Y_MAX}, // left-bottom
}};

// Tests for how the touchscreen is oriented relative to the natural orientation of the display.
// For example, if a touchscreen is configured with an orientation of 90 degrees, it is a portrait
// touchscreen panel that is used on a device whose natural display orientation is in landscape.
TEST_P(TouchscreenPrecisionTestsFixture, OrientationPrecision) {
    enum class Orientation {
        ORIENTATION_0 = ui::toRotationInt(ui::ROTATION_0),
        ORIENTATION_90 = ui::toRotationInt(ui::ROTATION_90),
        ORIENTATION_180 = ui::toRotationInt(ui::ROTATION_180),
        ORIENTATION_270 = ui::toRotationInt(ui::ROTATION_270),
        ftl_last = ORIENTATION_270,
    };
    using Orientation::ORIENTATION_0, Orientation::ORIENTATION_90, Orientation::ORIENTATION_180,
            Orientation::ORIENTATION_270;
    static const std::map<Orientation, std::array<vec2, 4> /*mappedCorners*/> kMappedCorners = {
            {ORIENTATION_0, {{{0, 0}, {479.5, 0}, {479.5, 799.75}, {0, 799.75}}}},
            {ORIENTATION_90, {{{0, 479.5}, {0, 0}, {799.75, 0}, {799.75, 479.5}}}},
            {ORIENTATION_180, {{{479.5, 799.75}, {0, 799.75}, {0, 0}, {479.5, 0}}}},
            {ORIENTATION_270, {{{799.75, 0}, {799.75, 479.5}, {0, 479.5}, {0, 0}}}},
    };

    const auto touchscreenOrientation = static_cast<Orientation>(ui::toRotationInt(GetParam()));

    // Configure the touchscreen as being installed in the one of the four different orientations
    // relative to the display.
    addConfigurationProperty("touch.deviceType", "touchScreen");
    addConfigurationProperty("touch.orientation", ftl::enum_string(touchscreenOrientation).c_str());
    prepareDisplay(ui::ROTATION_0);

    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    // If the touchscreen is installed in a rotated orientation relative to the display (i.e. in
    // orientations of either 90 or 270) this means the display's natural resolution will be
    // flipped.
    const bool displayRotated =
            touchscreenOrientation == ORIENTATION_90 || touchscreenOrientation == ORIENTATION_270;
    const int32_t width = displayRotated ? DISPLAY_HEIGHT : DISPLAY_WIDTH;
    const int32_t height = displayRotated ? DISPLAY_WIDTH : DISPLAY_HEIGHT;
    const Rect physicalFrame{0, 0, width, height};
    configurePhysicalDisplay(ui::ROTATION_0, physicalFrame, width, height);

    const auto& expectedPoints = kMappedCorners.at(touchscreenOrientation);
    const float expectedPrecisionX = displayRotated ? 4 : 2;
    const float expectedPrecisionY = displayRotated ? 2 : 4;

    // Test all four corners.
    for (int i = 0; i < 4; i++) {
        const auto& raw = kRawCorners[i];
        processDown(mapper, raw.x, raw.y);
        processSync(mapper);
        const auto& expected = expectedPoints[i];
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                      WithCoords(expected.x, expected.y),
                      WithPrecision(expectedPrecisionX, expectedPrecisionY))))
                << "Failed to process raw point (" << raw.x << ", " << raw.y << ") "
                << "with touchscreen orientation "
                << ftl::enum_string(touchscreenOrientation).c_str() << ", expected point ("
                << expected.x << ", " << expected.y << ").";
        processUp(mapper);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                      WithCoords(expected.x, expected.y))));
    }
}

TEST_P(TouchscreenPrecisionTestsFixture, RotationPrecisionWhenOrientationAware) {
    static const std::map<ui::Rotation /*rotation*/, std::array<vec2, 4> /*mappedCorners*/>
            kMappedCorners = {
                    {ui::ROTATION_0, {{{0, 0}, {479.5, 0}, {479.5, 799.75}, {0, 799.75}}}},
                    {ui::ROTATION_90, {{{0.5, 0}, {480, 0}, {480, 799.75}, {0.5, 799.75}}}},
                    {ui::ROTATION_180, {{{0.5, 0.25}, {480, 0.25}, {480, 800}, {0.5, 800}}}},
                    {ui::ROTATION_270, {{{0, 0.25}, {479.5, 0.25}, {479.5, 800}, {0, 800}}}},
            };

    const ui::Rotation displayRotation = GetParam();

    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(displayRotation);

    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    const auto& expectedPoints = kMappedCorners.at(displayRotation);

    // Test all four corners.
    for (int i = 0; i < 4; i++) {
        const auto& expected = expectedPoints[i];
        const auto& raw = kRawCorners[i];
        processDown(mapper, raw.x, raw.y);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                      WithCoords(expected.x, expected.y), WithPrecision(2, 4))))
                << "Failed to process raw point (" << raw.x << ", " << raw.y << ") "
                << "with display rotation " << ui::toCString(displayRotation)
                << ", expected point (" << expected.x << ", " << expected.y << ").";
        processUp(mapper);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                      WithCoords(expected.x, expected.y))));
    }
}

TEST_P(TouchscreenPrecisionTestsFixture, RotationPrecisionOrientationAwareInOri270) {
    static const std::map<ui::Rotation /*orientation*/, std::array<vec2, 4> /*mappedCorners*/>
            kMappedCorners = {
                    {ui::ROTATION_0, {{{799.75, 0}, {799.75, 479.5}, {0, 479.5}, {0, 0}}}},
                    {ui::ROTATION_90, {{{800, 0}, {800, 479.5}, {0.25, 479.5}, {0.25, 0}}}},
                    {ui::ROTATION_180, {{{800, 0.5}, {800, 480}, {0.25, 480}, {0.25, 0.5}}}},
                    {ui::ROTATION_270, {{{799.75, 0.5}, {799.75, 480}, {0, 480}, {0, 0.5}}}},
            };

    const ui::Rotation displayRotation = GetParam();

    addConfigurationProperty("touch.deviceType", "touchScreen");
    addConfigurationProperty("touch.orientation", "ORIENTATION_270");

    SingleTouchInputMapper& mapper = constructAndAddMapper<SingleTouchInputMapper>();

    // Ori 270, so width and height swapped
    const Rect physicalFrame{0, 0, DISPLAY_HEIGHT, DISPLAY_WIDTH};
    prepareDisplay(displayRotation);
    configurePhysicalDisplay(displayRotation, physicalFrame, DISPLAY_HEIGHT, DISPLAY_WIDTH);

    const auto& expectedPoints = kMappedCorners.at(displayRotation);

    // Test all four corners.
    for (int i = 0; i < 4; i++) {
        const auto& expected = expectedPoints[i];
        const auto& raw = kRawCorners[i];
        processDown(mapper, raw.x, raw.y);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                      WithCoords(expected.x, expected.y), WithPrecision(4, 2))))
                << "Failed to process raw point (" << raw.x << ", " << raw.y << ") "
                << "with display rotation " << ui::toCString(displayRotation)
                << ", expected point (" << expected.x << ", " << expected.y << ").";
        processUp(mapper);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                      WithCoords(expected.x, expected.y))));
    }
}

TEST_P(TouchscreenPrecisionTestsFixture, MotionRangesAreOrientedInRotatedDisplay) {
    const ui::Rotation displayRotation = GetParam();

    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(displayRotation);

    __attribute__((unused)) SingleTouchInputMapper& mapper =
            constructAndAddMapper<SingleTouchInputMapper>();

    const InputDeviceInfo deviceInfo = mDevice->getDeviceInfo();
    // MotionRanges use display pixels as their units
    const auto* xRange = deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_X, AINPUT_SOURCE_TOUCHSCREEN);
    const auto* yRange = deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_Y, AINPUT_SOURCE_TOUCHSCREEN);

    // The MotionRanges should be oriented in the rotated display's coordinate space
    const bool displayRotated =
            displayRotation == ui::ROTATION_90 || displayRotation == ui::ROTATION_270;

    constexpr float MAX_X = 479.5;
    constexpr float MAX_Y = 799.75;
    EXPECT_EQ(xRange->min, 0.f);
    EXPECT_EQ(yRange->min, 0.f);
    EXPECT_EQ(xRange->max, displayRotated ? MAX_Y : MAX_X);
    EXPECT_EQ(yRange->max, displayRotated ? MAX_X : MAX_Y);

    EXPECT_EQ(xRange->flat, 8.f);
    EXPECT_EQ(yRange->flat, 8.f);

    EXPECT_EQ(xRange->fuzz, 2.f);
    EXPECT_EQ(yRange->fuzz, 2.f);

    EXPECT_EQ(xRange->resolution, 25.f); // pixels per millimeter
    EXPECT_EQ(yRange->resolution, 25.f); // pixels per millimeter
}

// Run the precision tests for all rotations.
INSTANTIATE_TEST_SUITE_P(TouchscreenPrecisionTests, TouchscreenPrecisionTestsFixture,
                         ::testing::Values(ui::ROTATION_0, ui::ROTATION_90, ui::ROTATION_180,
                                           ui::ROTATION_270),
                         [](const testing::TestParamInfo<ui::Rotation>& testParamInfo) {
                             return ftl::enum_string(testParamInfo.param);
                         });

// --- ExternalStylusFusionTest ---

class ExternalStylusFusionTest : public SingleTouchInputMapperTest {
public:
    SingleTouchInputMapper& initializeInputMapperWithExternalStylus() {
        addConfigurationProperty("touch.deviceType", "touchScreen");
        prepareDisplay(ui::ROTATION_0);
        prepareButtons();
        prepareAxes(POSITION);
        auto& mapper = constructAndAddMapper<SingleTouchInputMapper>();

        mStylusState.when = ARBITRARY_TIME;
        mStylusState.pressure = 0.f;
        mStylusState.toolType = ToolType::STYLUS;
        mReader->getContext()->setExternalStylusDevices({mExternalStylusDeviceInfo});
        configureDevice(InputReaderConfiguration::Change::EXTERNAL_STYLUS_PRESENCE);
        processExternalStylusState(mapper);
        return mapper;
    }

    std::list<NotifyArgs> processExternalStylusState(InputMapper& mapper) {
        std::list<NotifyArgs> generatedArgs = mapper.updateExternalStylusState(mStylusState);
        for (const NotifyArgs& args : generatedArgs) {
            mFakeListener->notify(args);
        }
        // Loop the reader to flush the input listener queue.
        mReader->loopOnce();
        return generatedArgs;
    }

protected:
    StylusState mStylusState{};

    void testStartFusedStylusGesture(SingleTouchInputMapper& mapper) {
        auto toolTypeSource =
                AllOf(WithSource(STYLUS_FUSION_SOURCE), WithToolType(ToolType::STYLUS));

        // The first pointer is withheld.
        processDown(mapper, 100, 200);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
        ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasRequested(
                ARBITRARY_TIME + EXTERNAL_STYLUS_DATA_TIMEOUT));

        // The external stylus reports pressure. The withheld finger pointer is released as a
        // stylus.
        mStylusState.pressure = 1.f;
        processExternalStylusState(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_DOWN))));
        ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());

        // Subsequent pointer events are not withheld.
        processMove(mapper, 101, 201);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_MOVE))));

        ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    }

    void testSuccessfulFusionGesture(SingleTouchInputMapper& mapper) {
        ASSERT_NO_FATAL_FAILURE(testStartFusedStylusGesture(mapper));

        // Releasing the touch pointer ends the gesture.
        processUp(mapper);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP), WithSource(STYLUS_FUSION_SOURCE),
                      WithToolType(ToolType::STYLUS))));

        mStylusState.pressure = 0.f;
        processExternalStylusState(mapper);
        ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    }

    void testUnsuccessfulFusionGesture(SingleTouchInputMapper& mapper) {
        // When stylus fusion is not successful, events should be reported with the original source.
        // In this case, it is from a touchscreen.
        auto toolTypeSource =
                AllOf(WithSource(AINPUT_SOURCE_TOUCHSCREEN), WithToolType(ToolType::FINGER));

        // The first pointer is withheld when an external stylus is connected,
        // and a timeout is requested.
        processDown(mapper, 100, 200);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
        ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasRequested(
                ARBITRARY_TIME + EXTERNAL_STYLUS_DATA_TIMEOUT));

        // If the timeout expires early, it is requested again.
        handleTimeout(mapper, ARBITRARY_TIME + 1);
        ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasRequested(
                ARBITRARY_TIME + EXTERNAL_STYLUS_DATA_TIMEOUT));

        // When the timeout expires, the withheld touch is released as a finger pointer.
        handleTimeout(mapper, ARBITRARY_TIME + EXTERNAL_STYLUS_DATA_TIMEOUT);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_DOWN))));

        // Subsequent pointer events are not withheld.
        processMove(mapper, 101, 201);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_MOVE))));
        processUp(mapper);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_UP))));

        ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    }

private:
    InputDeviceInfo mExternalStylusDeviceInfo{};
};

TEST_F(ExternalStylusFusionTest, UsesBluetoothStylusSource) {
    SingleTouchInputMapper& mapper = initializeInputMapperWithExternalStylus();
    ASSERT_EQ(STYLUS_FUSION_SOURCE, mapper.getSources());
}

TEST_F(ExternalStylusFusionTest, UnsuccessfulFusion) {
    SingleTouchInputMapper& mapper = initializeInputMapperWithExternalStylus();
    ASSERT_NO_FATAL_FAILURE(testUnsuccessfulFusionGesture(mapper));
}

TEST_F(ExternalStylusFusionTest, SuccessfulFusion_TouchFirst) {
    SingleTouchInputMapper& mapper = initializeInputMapperWithExternalStylus();
    ASSERT_NO_FATAL_FAILURE(testSuccessfulFusionGesture(mapper));
}

// Test a successful stylus fusion gesture where the pressure is reported by the external
// before the touch is reported by the touchscreen.
TEST_F(ExternalStylusFusionTest, SuccessfulFusion_PressureFirst) {
    SingleTouchInputMapper& mapper = initializeInputMapperWithExternalStylus();
    auto toolTypeSource = AllOf(WithSource(STYLUS_FUSION_SOURCE), WithToolType(ToolType::STYLUS));

    // The external stylus reports pressure first. It is ignored for now.
    mStylusState.pressure = 1.f;
    processExternalStylusState(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());

    // When the touch goes down afterwards, it is reported as a stylus pointer.
    processDown(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_DOWN))));
    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());

    processMove(mapper, 101, 201);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_MOVE))));
    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_UP))));

    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(ExternalStylusFusionTest, FusionIsRepeatedForEachNewGesture) {
    SingleTouchInputMapper& mapper = initializeInputMapperWithExternalStylus();

    ASSERT_NO_FATAL_FAILURE(testSuccessfulFusionGesture(mapper));
    ASSERT_NO_FATAL_FAILURE(testUnsuccessfulFusionGesture(mapper));

    ASSERT_NO_FATAL_FAILURE(testSuccessfulFusionGesture(mapper));
    ASSERT_NO_FATAL_FAILURE(testSuccessfulFusionGesture(mapper));
    ASSERT_NO_FATAL_FAILURE(testUnsuccessfulFusionGesture(mapper));
    ASSERT_NO_FATAL_FAILURE(testUnsuccessfulFusionGesture(mapper));
}

TEST_F(ExternalStylusFusionTest, FusedPointerReportsPressureChanges) {
    SingleTouchInputMapper& mapper = initializeInputMapperWithExternalStylus();
    auto toolTypeSource = AllOf(WithSource(STYLUS_FUSION_SOURCE), WithToolType(ToolType::STYLUS));

    mStylusState.pressure = 0.8f;
    processExternalStylusState(mapper);
    processDown(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithPressure(0.8f))));
    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());

    // The external stylus reports a pressure change. We wait for some time for a touch event.
    mStylusState.pressure = 0.6f;
    processExternalStylusState(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(
            mReader->getContext()->assertTimeoutWasRequested(ARBITRARY_TIME + TOUCH_DATA_TIMEOUT));

    // If a touch is reported within the timeout, it reports the updated pressure.
    processMove(mapper, 101, 201);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithPressure(0.6f))));
    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());

    // There is another pressure change.
    mStylusState.pressure = 0.5f;
    processExternalStylusState(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(
            mReader->getContext()->assertTimeoutWasRequested(ARBITRARY_TIME + TOUCH_DATA_TIMEOUT));

    // If a touch is not reported within the timeout, a move event is generated to report
    // the new pressure.
    handleTimeout(mapper, ARBITRARY_TIME + TOUCH_DATA_TIMEOUT);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithPressure(0.5f))));

    // If a zero pressure is reported before the touch goes up, the previous pressure value is
    // repeated indefinitely.
    mStylusState.pressure = 0.0f;
    processExternalStylusState(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(
            mReader->getContext()->assertTimeoutWasRequested(ARBITRARY_TIME + TOUCH_DATA_TIMEOUT));
    processMove(mapper, 102, 202);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithPressure(0.5f))));
    processMove(mapper, 103, 203);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithPressure(0.5f))));

    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP), WithSource(STYLUS_FUSION_SOURCE),
                  WithToolType(ToolType::STYLUS))));

    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(ExternalStylusFusionTest, FusedPointerReportsToolTypeChanges) {
    SingleTouchInputMapper& mapper = initializeInputMapperWithExternalStylus();
    auto source = WithSource(STYLUS_FUSION_SOURCE);

    mStylusState.pressure = 1.f;
    mStylusState.toolType = ToolType::ERASER;
    processExternalStylusState(mapper);
    processDown(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(source, WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithToolType(ToolType::ERASER))));
    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());

    // The external stylus reports a tool change. We wait for some time for a touch event.
    mStylusState.toolType = ToolType::STYLUS;
    processExternalStylusState(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(
            mReader->getContext()->assertTimeoutWasRequested(ARBITRARY_TIME + TOUCH_DATA_TIMEOUT));

    // If a touch is reported within the timeout, it reports the updated pressure.
    processMove(mapper, 101, 201);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(source, WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithToolType(ToolType::STYLUS))));
    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());

    // There is another tool type change.
    mStylusState.toolType = ToolType::FINGER;
    processExternalStylusState(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(
            mReader->getContext()->assertTimeoutWasRequested(ARBITRARY_TIME + TOUCH_DATA_TIMEOUT));

    // If a touch is not reported within the timeout, a move event is generated to report
    // the new tool type.
    handleTimeout(mapper, ARBITRARY_TIME + TOUCH_DATA_TIMEOUT);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(source, WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithToolType(ToolType::FINGER))));

    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(source, WithMotionAction(AMOTION_EVENT_ACTION_UP),
                  WithToolType(ToolType::FINGER))));

    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(ExternalStylusFusionTest, FusedPointerReportsButtons) {
    SingleTouchInputMapper& mapper = initializeInputMapperWithExternalStylus();
    auto toolTypeSource = AllOf(WithSource(STYLUS_FUSION_SOURCE), WithToolType(ToolType::STYLUS));

    ASSERT_NO_FATAL_FAILURE(testStartFusedStylusGesture(mapper));

    // The external stylus reports a button change. We wait for some time for a touch event.
    mStylusState.buttons = AMOTION_EVENT_BUTTON_STYLUS_PRIMARY;
    processExternalStylusState(mapper);
    ASSERT_NO_FATAL_FAILURE(
            mReader->getContext()->assertTimeoutWasRequested(ARBITRARY_TIME + TOUCH_DATA_TIMEOUT));

    // If a touch is reported within the timeout, it reports the updated button state.
    processMove(mapper, 101, 201);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));
    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());

    // The button is now released.
    mStylusState.buttons = 0;
    processExternalStylusState(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(
            mReader->getContext()->assertTimeoutWasRequested(ARBITRARY_TIME + TOUCH_DATA_TIMEOUT));

    // If a touch is not reported within the timeout, a move event is generated to report
    // the new button state.
    handleTimeout(mapper, ARBITRARY_TIME + TOUCH_DATA_TIMEOUT);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE),
                  WithButtonState(0))));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithButtonState(0))));

    processUp(mapper);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(toolTypeSource, WithMotionAction(AMOTION_EVENT_ACTION_UP), WithButtonState(0))));

    ASSERT_NO_FATAL_FAILURE(mReader->getContext()->assertTimeoutWasNotRequested());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

// --- MultiTouchInputMapperTest ---

class MultiTouchInputMapperTest : public TouchInputMapperTest {
protected:
    void prepareAxes(int axes);

    void processPosition(MultiTouchInputMapper& mapper, int32_t x, int32_t y);
    void processTouchMajor(MultiTouchInputMapper& mapper, int32_t touchMajor);
    void processTouchMinor(MultiTouchInputMapper& mapper, int32_t touchMinor);
    void processToolMajor(MultiTouchInputMapper& mapper, int32_t toolMajor);
    void processToolMinor(MultiTouchInputMapper& mapper, int32_t toolMinor);
    void processOrientation(MultiTouchInputMapper& mapper, int32_t orientation);
    void processPressure(MultiTouchInputMapper& mapper, int32_t pressure);
    void processDistance(MultiTouchInputMapper& mapper, int32_t distance);
    void processId(MultiTouchInputMapper& mapper, int32_t id);
    void processSlot(MultiTouchInputMapper& mapper, int32_t slot);
    void processToolType(MultiTouchInputMapper& mapper, int32_t toolType);
    void processKey(MultiTouchInputMapper& mapper, int32_t code, int32_t value);
    void processHidUsage(MultiTouchInputMapper& mapper, int32_t usageCode, int32_t value);
    void processMTSync(MultiTouchInputMapper& mapper);
    void processSync(MultiTouchInputMapper& mapper, nsecs_t eventTime = ARBITRARY_TIME,
                     nsecs_t readTime = READ_TIME);
};

void MultiTouchInputMapperTest::prepareAxes(int axes) {
    if (axes & POSITION) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, RAW_X_MIN, RAW_X_MAX, 0, 0);
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, RAW_Y_MIN, RAW_Y_MAX, 0, 0);
    }
    if (axes & TOUCH) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOUCH_MAJOR, RAW_TOUCH_MIN,
                                       RAW_TOUCH_MAX, 0, 0);
        if (axes & MINOR) {
            mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOUCH_MINOR, RAW_TOUCH_MIN,
                                           RAW_TOUCH_MAX, 0, 0);
        }
    }
    if (axes & TOOL) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MAJOR, RAW_TOOL_MIN, RAW_TOOL_MAX,
                                       0, 0);
        if (axes & MINOR) {
            mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MINOR, RAW_TOOL_MIN,
                                           RAW_TOOL_MAX, 0, 0);
        }
    }
    if (axes & ORIENTATION) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_ORIENTATION, RAW_ORIENTATION_MIN,
                                       RAW_ORIENTATION_MAX, 0, 0);
    }
    if (axes & PRESSURE) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_PRESSURE, RAW_PRESSURE_MIN,
                                       RAW_PRESSURE_MAX, 0, 0);
    }
    if (axes & DISTANCE) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_DISTANCE, RAW_DISTANCE_MIN,
                                       RAW_DISTANCE_MAX, 0, 0);
    }
    if (axes & ID) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TRACKING_ID, RAW_ID_MIN, RAW_ID_MAX, 0,
                                       0);
    }
    if (axes & SLOT) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_SLOT, RAW_SLOT_MIN, RAW_SLOT_MAX, 0, 0);
        mFakeEventHub->setAbsoluteAxisValue(EVENTHUB_ID, ABS_MT_SLOT, 0);
    }
    if (axes & TOOL_TYPE) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOOL_TYPE, 0, MT_TOOL_MAX, 0, 0);
    }
}

void MultiTouchInputMapperTest::processPosition(MultiTouchInputMapper& mapper, int32_t x,
                                                int32_t y) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_POSITION_X, x);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_POSITION_Y, y);
}

void MultiTouchInputMapperTest::processTouchMajor(MultiTouchInputMapper& mapper,
                                                  int32_t touchMajor) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_TOUCH_MAJOR, touchMajor);
}

void MultiTouchInputMapperTest::processTouchMinor(MultiTouchInputMapper& mapper,
                                                  int32_t touchMinor) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_TOUCH_MINOR, touchMinor);
}

void MultiTouchInputMapperTest::processToolMajor(MultiTouchInputMapper& mapper, int32_t toolMajor) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_WIDTH_MAJOR, toolMajor);
}

void MultiTouchInputMapperTest::processToolMinor(MultiTouchInputMapper& mapper, int32_t toolMinor) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_WIDTH_MINOR, toolMinor);
}

void MultiTouchInputMapperTest::processOrientation(MultiTouchInputMapper& mapper,
                                                   int32_t orientation) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_ORIENTATION, orientation);
}

void MultiTouchInputMapperTest::processPressure(MultiTouchInputMapper& mapper, int32_t pressure) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_PRESSURE, pressure);
}

void MultiTouchInputMapperTest::processDistance(MultiTouchInputMapper& mapper, int32_t distance) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_DISTANCE, distance);
}

void MultiTouchInputMapperTest::processId(MultiTouchInputMapper& mapper, int32_t id) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_TRACKING_ID, id);
}

void MultiTouchInputMapperTest::processSlot(MultiTouchInputMapper& mapper, int32_t slot) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_SLOT, slot);
}

void MultiTouchInputMapperTest::processToolType(MultiTouchInputMapper& mapper, int32_t toolType) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, ABS_MT_TOOL_TYPE, toolType);
}

void MultiTouchInputMapperTest::processKey(MultiTouchInputMapper& mapper, int32_t code,
                                           int32_t value) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, code, value);
}

void MultiTouchInputMapperTest::processHidUsage(MultiTouchInputMapper& mapper, int32_t usageCode,
                                                int32_t value) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_MSC, MSC_SCAN, usageCode);
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_KEY, KEY_UNKNOWN, value);
}

void MultiTouchInputMapperTest::processMTSync(MultiTouchInputMapper& mapper) {
    process(mapper, ARBITRARY_TIME, READ_TIME, EV_SYN, SYN_MT_REPORT, 0);
}

void MultiTouchInputMapperTest::processSync(MultiTouchInputMapper& mapper, nsecs_t eventTime,
                                            nsecs_t readTime) {
    process(mapper, eventTime, readTime, EV_SYN, SYN_REPORT, 0);
}

TEST_F(MultiTouchInputMapperTest, Process_NormalMultiTouchGesture_WithoutTrackingIds) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION);
    prepareVirtualKeys();
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    mReader->getContext()->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);

    NotifyMotionArgs motionArgs;

    // Two fingers down at once.
    int32_t x1 = 100, y1 = 125, x2 = 300, y2 = 500;
    processPosition(mapper, x1, y1);
    processMTSync(mapper);
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(ACTION_POINTER_1_DOWN, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Move.
    x1 += 10; y1 += 15; x2 += 5; y2 -= 10;
    processPosition(mapper, x1, y1);
    processMTSync(mapper);
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // First finger up.
    x2 += 15; y2 -= 20;
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(ACTION_POINTER_0_UP, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(1, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Move.
    x2 += 20; y2 -= 25;
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(1, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // New finger down.
    int32_t x3 = 700, y3 = 300;
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processPosition(mapper, x3, y3);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(ACTION_POINTER_0_DOWN, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Second finger up.
    x3 += 30; y3 -= 20;
    processPosition(mapper, x3, y3);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(ACTION_POINTER_1_UP, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Last finger up.
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.eventTime);
    ASSERT_EQ(DEVICE_ID, motionArgs.deviceId);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, motionArgs.source);
    ASSERT_EQ(uint32_t(0), motionArgs.policyFlags);
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_EQ(0, motionArgs.flags);
    ASSERT_EQ(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON, motionArgs.metaState);
    ASSERT_EQ(0, motionArgs.buttonState);
    ASSERT_EQ(0, motionArgs.edgeFlags);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NEAR(X_PRECISION, motionArgs.xPrecision, EPSILON);
    ASSERT_NEAR(Y_PRECISION, motionArgs.yPrecision, EPSILON);
    ASSERT_EQ(ARBITRARY_TIME, motionArgs.downTime);

    // Should not have sent any more keys or motions.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(MultiTouchInputMapperTest, AxisResolution_IsPopulated) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);

    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, RAW_X_MIN, RAW_X_MAX, /*flat*/ 0,
                                   /*fuzz*/ 0, /*resolution*/ 10);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, RAW_Y_MIN, RAW_Y_MAX, /*flat*/ 0,
                                   /*fuzz*/ 0, /*resolution*/ 11);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOUCH_MAJOR, RAW_TOUCH_MIN, RAW_TOUCH_MAX,
                                   /*flat*/ 0, /*fuzz*/ 0, /*resolution*/ 12);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_TOUCH_MINOR, RAW_TOUCH_MIN, RAW_TOUCH_MAX,
                                   /*flat*/ 0, /*fuzz*/ 0, /*resolution*/ 13);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MAJOR, RAW_TOOL_MIN, RAW_TOOL_MAX,
                                   /*flat*/ 0, /*flat*/ 0, /*resolution*/ 14);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_WIDTH_MINOR, RAW_TOOL_MIN, RAW_TOOL_MAX,
                                   /*flat*/ 0, /*flat*/ 0, /*resolution*/ 15);

    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // X and Y axes
    assertAxisResolution(mapper, AMOTION_EVENT_AXIS_X, 10 / X_PRECISION);
    assertAxisResolution(mapper, AMOTION_EVENT_AXIS_Y, 11 / Y_PRECISION);
    // Touch major and minor
    assertAxisResolution(mapper, AMOTION_EVENT_AXIS_TOUCH_MAJOR, 12 * GEOMETRIC_SCALE);
    assertAxisResolution(mapper, AMOTION_EVENT_AXIS_TOUCH_MINOR, 13 * GEOMETRIC_SCALE);
    // Tool major and minor
    assertAxisResolution(mapper, AMOTION_EVENT_AXIS_TOOL_MAJOR, 14 * GEOMETRIC_SCALE);
    assertAxisResolution(mapper, AMOTION_EVENT_AXIS_TOOL_MINOR, 15 * GEOMETRIC_SCALE);
}

TEST_F(MultiTouchInputMapperTest, TouchMajorAndMinorAxes_DoNotAppearIfNotSupported) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);

    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, RAW_X_MIN, RAW_X_MAX, /*flat*/ 0,
                                   /*fuzz*/ 0, /*resolution*/ 10);
    mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, RAW_Y_MIN, RAW_Y_MAX, /*flat*/ 0,
                                   /*fuzz*/ 0, /*resolution*/ 11);

    // We do not add ABS_MT_TOUCH_MAJOR / MINOR or ABS_MT_WIDTH_MAJOR / MINOR axes

    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // Touch major and minor
    assertAxisNotPresent(mapper, AMOTION_EVENT_AXIS_TOUCH_MAJOR);
    assertAxisNotPresent(mapper, AMOTION_EVENT_AXIS_TOUCH_MINOR);
    // Tool major and minor
    assertAxisNotPresent(mapper, AMOTION_EVENT_AXIS_TOOL_MAJOR);
    assertAxisNotPresent(mapper, AMOTION_EVENT_AXIS_TOOL_MINOR);
}

TEST_F(MultiTouchInputMapperTest, Process_NormalMultiTouchGesture_WithTrackingIds) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID);
    prepareVirtualKeys();
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    mReader->getContext()->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);

    NotifyMotionArgs motionArgs;

    // Two fingers down at once.
    int32_t x1 = 100, y1 = 125, x2 = 300, y2 = 500;
    processPosition(mapper, x1, y1);
    processId(mapper, 1);
    processMTSync(mapper);
    processPosition(mapper, x2, y2);
    processId(mapper, 2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_1_DOWN, motionArgs.action);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    // Move.
    x1 += 10; y1 += 15; x2 += 5; y2 -= 10;
    processPosition(mapper, x1, y1);
    processId(mapper, 1);
    processMTSync(mapper);
    processPosition(mapper, x2, y2);
    processId(mapper, 2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    // First finger up.
    x2 += 15; y2 -= 20;
    processPosition(mapper, x2, y2);
    processId(mapper, 2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_0_UP, motionArgs.action);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(1, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    // Move.
    x2 += 20; y2 -= 25;
    processPosition(mapper, x2, y2);
    processId(mapper, 2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(1, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    // New finger down.
    int32_t x3 = 700, y3 = 300;
    processPosition(mapper, x2, y2);
    processId(mapper, 2);
    processMTSync(mapper);
    processPosition(mapper, x3, y3);
    processId(mapper, 3);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_0_DOWN, motionArgs.action);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    // Second finger up.
    x3 += 30; y3 -= 20;
    processPosition(mapper, x3, y3);
    processId(mapper, 3);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_1_UP, motionArgs.action);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));

    // Last finger up.
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));

    // Should not have sent any more keys or motions.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(MultiTouchInputMapperTest, Process_NormalMultiTouchGesture_WithSlots) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT);
    prepareVirtualKeys();
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    mReader->getContext()->setGlobalMetaState(AMETA_SHIFT_LEFT_ON | AMETA_SHIFT_ON);

    NotifyMotionArgs motionArgs;

    // Two fingers down at once.
    int32_t x1 = 100, y1 = 125, x2 = 300, y2 = 500;
    processPosition(mapper, x1, y1);
    processId(mapper, 1);
    processSlot(mapper, 1);
    processPosition(mapper, x2, y2);
    processId(mapper, 2);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_1_DOWN, motionArgs.action);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    // Move.
    x1 += 10; y1 += 15; x2 += 5; y2 -= 10;
    processSlot(mapper, 0);
    processPosition(mapper, x1, y1);
    processSlot(mapper, 1);
    processPosition(mapper, x2, y2);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    // First finger up.
    x2 += 15; y2 -= 20;
    processSlot(mapper, 0);
    processId(mapper, -1);
    processSlot(mapper, 1);
    processPosition(mapper, x2, y2);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_0_UP, motionArgs.action);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x1), toDisplayY(y1), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(1, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    // Move.
    x2 += 20; y2 -= 25;
    processPosition(mapper, x2, y2);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(1, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    // New finger down.
    int32_t x3 = 700, y3 = 300;
    processPosition(mapper, x2, y2);
    processSlot(mapper, 0);
    processId(mapper, 3);
    processPosition(mapper, x3, y3);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_0_DOWN, motionArgs.action);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    // Second finger up.
    x3 += 30; y3 -= 20;
    processSlot(mapper, 1);
    processId(mapper, -1);
    processSlot(mapper, 0);
    processPosition(mapper, x3, y3);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_1_UP, motionArgs.action);
    ASSERT_EQ(size_t(2), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1, motionArgs.pointerProperties[1].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1],
            toDisplayX(x2), toDisplayY(y2), 1, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));

    // Last finger up.
    processId(mapper, -1);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_EQ(size_t(1), motionArgs.getPointerCount());
    ASSERT_EQ(0, motionArgs.pointerProperties[0].id);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(x3), toDisplayY(y3), 1, 0, 0, 0, 0, 0, 0, 0));

    // Should not have sent any more keys or motions.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasNotCalled());
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(MultiTouchInputMapperTest, Process_AllAxes_WithDefaultCalibration) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | TOUCH | TOOL | PRESSURE | ORIENTATION | ID | MINOR | DISTANCE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // These calculations are based on the input device calibration documentation.
    int32_t rawX = 100;
    int32_t rawY = 200;
    int32_t rawTouchMajor = 7;
    int32_t rawTouchMinor = 6;
    int32_t rawToolMajor = 9;
    int32_t rawToolMinor = 8;
    int32_t rawPressure = 11;
    int32_t rawDistance = 0;
    int32_t rawOrientation = 3;
    int32_t id = 5;

    float x = toDisplayX(rawX);
    float y = toDisplayY(rawY);
    float pressure = float(rawPressure) / RAW_PRESSURE_MAX;
    float size = avg(rawTouchMajor, rawTouchMinor) / RAW_TOUCH_MAX;
    float toolMajor = float(rawToolMajor) * GEOMETRIC_SCALE;
    float toolMinor = float(rawToolMinor) * GEOMETRIC_SCALE;
    float touchMajor = float(rawTouchMajor) * GEOMETRIC_SCALE;
    float touchMinor = float(rawTouchMinor) * GEOMETRIC_SCALE;
    float orientation = float(rawOrientation) / RAW_ORIENTATION_MAX * M_PI_2;
    float distance = float(rawDistance);

    processPosition(mapper, rawX, rawY);
    processTouchMajor(mapper, rawTouchMajor);
    processTouchMinor(mapper, rawTouchMinor);
    processToolMajor(mapper, rawToolMajor);
    processToolMinor(mapper, rawToolMinor);
    processPressure(mapper, rawPressure);
    processOrientation(mapper, rawOrientation);
    processDistance(mapper, rawDistance);
    processId(mapper, id);
    processMTSync(mapper);
    processSync(mapper);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(0, args.pointerProperties[0].id);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(args.pointerCoords[0],
            x, y, pressure, size, touchMajor, touchMinor, toolMajor, toolMinor,
            orientation, distance));
}

TEST_F(MultiTouchInputMapperTest, Process_TouchAndToolAxes_GeometricCalibration) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | TOUCH | TOOL | MINOR);
    addConfigurationProperty("touch.size.calibration", "geometric");
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // These calculations are based on the input device calibration documentation.
    int32_t rawX = 100;
    int32_t rawY = 200;
    int32_t rawTouchMajor = 140;
    int32_t rawTouchMinor = 120;
    int32_t rawToolMajor = 180;
    int32_t rawToolMinor = 160;

    float x = toDisplayX(rawX);
    float y = toDisplayY(rawY);
    float size = avg(rawTouchMajor, rawTouchMinor) / RAW_TOUCH_MAX;
    float toolMajor = float(rawToolMajor) * GEOMETRIC_SCALE;
    float toolMinor = float(rawToolMinor) * GEOMETRIC_SCALE;
    float touchMajor = float(rawTouchMajor) * GEOMETRIC_SCALE;
    float touchMinor = float(rawTouchMinor) * GEOMETRIC_SCALE;

    processPosition(mapper, rawX, rawY);
    processTouchMajor(mapper, rawTouchMajor);
    processTouchMinor(mapper, rawTouchMinor);
    processToolMajor(mapper, rawToolMajor);
    processToolMinor(mapper, rawToolMinor);
    processMTSync(mapper);
    processSync(mapper);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(args.pointerCoords[0],
            x, y, 1.0f, size, touchMajor, touchMinor, toolMajor, toolMinor, 0, 0));
}

TEST_F(MultiTouchInputMapperTest, Process_TouchAndToolAxes_SummedLinearCalibration) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | TOUCH | TOOL);
    addConfigurationProperty("touch.size.calibration", "diameter");
    addConfigurationProperty("touch.size.scale", "10");
    addConfigurationProperty("touch.size.bias", "160");
    addConfigurationProperty("touch.size.isSummed", "1");
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // These calculations are based on the input device calibration documentation.
    // Note: We only provide a single common touch/tool value because the device is assumed
    //       not to emit separate values for each pointer (isSummed = 1).
    int32_t rawX = 100;
    int32_t rawY = 200;
    int32_t rawX2 = 150;
    int32_t rawY2 = 250;
    int32_t rawTouchMajor = 5;
    int32_t rawToolMajor = 8;

    float x = toDisplayX(rawX);
    float y = toDisplayY(rawY);
    float x2 = toDisplayX(rawX2);
    float y2 = toDisplayY(rawY2);
    float size = float(rawTouchMajor) / 2 / RAW_TOUCH_MAX;
    float touch = float(rawTouchMajor) / 2 * 10.0f + 160.0f;
    float tool = float(rawToolMajor) / 2 * 10.0f + 160.0f;

    processPosition(mapper, rawX, rawY);
    processTouchMajor(mapper, rawTouchMajor);
    processToolMajor(mapper, rawToolMajor);
    processMTSync(mapper);
    processPosition(mapper, rawX2, rawY2);
    processTouchMajor(mapper, rawTouchMajor);
    processToolMajor(mapper, rawToolMajor);
    processMTSync(mapper);
    processSync(mapper);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, args.action);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(ACTION_POINTER_1_DOWN, args.action);
    ASSERT_EQ(size_t(2), args.getPointerCount());
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(args.pointerCoords[0],
            x, y, 1.0f, size, touch, touch, tool, tool, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(args.pointerCoords[1],
            x2, y2, 1.0f, size, touch, touch, tool, tool, 0, 0));
}

TEST_F(MultiTouchInputMapperTest, Process_TouchAndToolAxes_AreaCalibration) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | TOUCH | TOOL);
    addConfigurationProperty("touch.size.calibration", "area");
    addConfigurationProperty("touch.size.scale", "43");
    addConfigurationProperty("touch.size.bias", "3");
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // These calculations are based on the input device calibration documentation.
    int32_t rawX = 100;
    int32_t rawY = 200;
    int32_t rawTouchMajor = 5;
    int32_t rawToolMajor = 8;

    float x = toDisplayX(rawX);
    float y = toDisplayY(rawY);
    float size = float(rawTouchMajor) / RAW_TOUCH_MAX;
    float touch = sqrtf(rawTouchMajor) * 43.0f + 3.0f;
    float tool = sqrtf(rawToolMajor) * 43.0f + 3.0f;

    processPosition(mapper, rawX, rawY);
    processTouchMajor(mapper, rawTouchMajor);
    processToolMajor(mapper, rawToolMajor);
    processMTSync(mapper);
    processSync(mapper);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(args.pointerCoords[0],
            x, y, 1.0f, size, touch, touch, tool, tool, 0, 0));
}

TEST_F(MultiTouchInputMapperTest, Process_PressureAxis_AmplitudeCalibration) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | PRESSURE);
    addConfigurationProperty("touch.pressure.calibration", "amplitude");
    addConfigurationProperty("touch.pressure.scale", "0.01");
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    InputDeviceInfo info;
    mapper.populateDeviceInfo(info);
    ASSERT_NO_FATAL_FAILURE(assertMotionRange(info,
            AINPUT_MOTION_RANGE_PRESSURE, AINPUT_SOURCE_TOUCHSCREEN,
            0.0f, RAW_PRESSURE_MAX * 0.01, 0.0f, 0.0f));

    // These calculations are based on the input device calibration documentation.
    int32_t rawX = 100;
    int32_t rawY = 200;
    int32_t rawPressure = 60;

    float x = toDisplayX(rawX);
    float y = toDisplayY(rawY);
    float pressure = float(rawPressure) * 0.01f;

    processPosition(mapper, rawX, rawY);
    processPressure(mapper, rawPressure);
    processMTSync(mapper);
    processSync(mapper);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(args.pointerCoords[0],
            x, y, pressure, 0, 0, 0, 0, 0, 0, 0));
}

TEST_F(MultiTouchInputMapperTest, Process_ShouldHandleAllButtons) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;
    NotifyKeyArgs keyArgs;

    processId(mapper, 1);
    processPosition(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    // press BTN_LEFT, release BTN_LEFT
    processKey(mapper, BTN_LEFT, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_PRIMARY, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_PRIMARY, motionArgs.buttonState);

    processKey(mapper, BTN_LEFT, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    // press BTN_RIGHT + BTN_MIDDLE, release BTN_RIGHT, release BTN_MIDDLE
    processKey(mapper, BTN_RIGHT, 1);
    processKey(mapper, BTN_MIDDLE, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_SECONDARY | AMOTION_EVENT_BUTTON_TERTIARY,
            motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_TERTIARY, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_SECONDARY | AMOTION_EVENT_BUTTON_TERTIARY,
            motionArgs.buttonState);

    processKey(mapper, BTN_RIGHT, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_TERTIARY, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_TERTIARY, motionArgs.buttonState);

    processKey(mapper, BTN_MIDDLE, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    // press BTN_BACK, release BTN_BACK
    processKey(mapper, BTN_BACK, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, keyArgs.action);
    ASSERT_EQ(AKEYCODE_BACK, keyArgs.keyCode);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_BACK, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_BACK, motionArgs.buttonState);

    processKey(mapper, BTN_BACK, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, keyArgs.action);
    ASSERT_EQ(AKEYCODE_BACK, keyArgs.keyCode);

    // press BTN_SIDE, release BTN_SIDE
    processKey(mapper, BTN_SIDE, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, keyArgs.action);
    ASSERT_EQ(AKEYCODE_BACK, keyArgs.keyCode);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_BACK, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_BACK, motionArgs.buttonState);

    processKey(mapper, BTN_SIDE, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, keyArgs.action);
    ASSERT_EQ(AKEYCODE_BACK, keyArgs.keyCode);

    // press BTN_FORWARD, release BTN_FORWARD
    processKey(mapper, BTN_FORWARD, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, keyArgs.action);
    ASSERT_EQ(AKEYCODE_FORWARD, keyArgs.keyCode);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_FORWARD, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_FORWARD, motionArgs.buttonState);

    processKey(mapper, BTN_FORWARD, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, keyArgs.action);
    ASSERT_EQ(AKEYCODE_FORWARD, keyArgs.keyCode);

    // press BTN_EXTRA, release BTN_EXTRA
    processKey(mapper, BTN_EXTRA, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, keyArgs.action);
    ASSERT_EQ(AKEYCODE_FORWARD, keyArgs.keyCode);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_FORWARD, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_FORWARD, motionArgs.buttonState);

    processKey(mapper, BTN_EXTRA, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&keyArgs));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, keyArgs.action);
    ASSERT_EQ(AKEYCODE_FORWARD, keyArgs.keyCode);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasNotCalled());

    // press BTN_STYLUS, release BTN_STYLUS
    processKey(mapper, BTN_STYLUS, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY, motionArgs.buttonState);

    processKey(mapper, BTN_STYLUS, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    // press BTN_STYLUS2, release BTN_STYLUS2
    processKey(mapper, BTN_STYLUS2, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_STYLUS_SECONDARY, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_BUTTON_STYLUS_SECONDARY, motionArgs.buttonState);

    processKey(mapper, BTN_STYLUS2, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);

    // release touch
    processId(mapper, -1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_EQ(0, motionArgs.buttonState);
}

TEST_F(MultiTouchInputMapperTest, Process_ShouldHandleMappedStylusButtons) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    mFakeEventHub->addKey(EVENTHUB_ID, BTN_A, 0, AKEYCODE_STYLUS_BUTTON_PRIMARY, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, 0, 0xabcd, AKEYCODE_STYLUS_BUTTON_SECONDARY, 0);

    // Touch down.
    processId(mapper, 1);
    processPosition(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithButtonState(0))));

    // Press and release button mapped to the primary stylus button.
    processKey(mapper, BTN_A, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY))));

    processKey(mapper, BTN_A, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE), WithButtonState(0))));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithButtonState(0))));

    // Press and release the HID usage mapped to the secondary stylus button.
    processHidUsage(mapper, 0xabcd, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_SECONDARY))));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS),
                  WithButtonState(AMOTION_EVENT_BUTTON_STYLUS_SECONDARY))));

    processHidUsage(mapper, 0xabcd, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE), WithButtonState(0))));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE), WithButtonState(0))));

    // Release touch.
    processId(mapper, -1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP), WithButtonState(0))));
}

TEST_F(MultiTouchInputMapperTest, Process_ShouldHandleAllToolTypes) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | TOOL_TYPE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // default tool type is finger
    processId(mapper, 1);
    processPosition(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // eraser
    processKey(mapper, BTN_TOOL_RUBBER, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::ERASER, motionArgs.pointerProperties[0].toolType);

    // stylus
    processKey(mapper, BTN_TOOL_RUBBER, 0);
    processKey(mapper, BTN_TOOL_PEN, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::STYLUS, motionArgs.pointerProperties[0].toolType);

    // brush
    processKey(mapper, BTN_TOOL_PEN, 0);
    processKey(mapper, BTN_TOOL_BRUSH, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::STYLUS, motionArgs.pointerProperties[0].toolType);

    // pencil
    processKey(mapper, BTN_TOOL_BRUSH, 0);
    processKey(mapper, BTN_TOOL_PENCIL, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::STYLUS, motionArgs.pointerProperties[0].toolType);

    // air-brush
    processKey(mapper, BTN_TOOL_PENCIL, 0);
    processKey(mapper, BTN_TOOL_AIRBRUSH, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::STYLUS, motionArgs.pointerProperties[0].toolType);

    // mouse
    processKey(mapper, BTN_TOOL_AIRBRUSH, 0);
    processKey(mapper, BTN_TOOL_MOUSE, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::MOUSE, motionArgs.pointerProperties[0].toolType);

    // lens
    processKey(mapper, BTN_TOOL_MOUSE, 0);
    processKey(mapper, BTN_TOOL_LENS, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::MOUSE, motionArgs.pointerProperties[0].toolType);

    // double-tap
    processKey(mapper, BTN_TOOL_LENS, 0);
    processKey(mapper, BTN_TOOL_DOUBLETAP, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // triple-tap
    processKey(mapper, BTN_TOOL_DOUBLETAP, 0);
    processKey(mapper, BTN_TOOL_TRIPLETAP, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // quad-tap
    processKey(mapper, BTN_TOOL_TRIPLETAP, 0);
    processKey(mapper, BTN_TOOL_QUADTAP, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // finger
    processKey(mapper, BTN_TOOL_QUADTAP, 0);
    processKey(mapper, BTN_TOOL_FINGER, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // stylus trumps finger
    processKey(mapper, BTN_TOOL_PEN, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::STYLUS, motionArgs.pointerProperties[0].toolType);

    // eraser trumps stylus
    processKey(mapper, BTN_TOOL_RUBBER, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::ERASER, motionArgs.pointerProperties[0].toolType);

    // mouse trumps eraser
    processKey(mapper, BTN_TOOL_MOUSE, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::MOUSE, motionArgs.pointerProperties[0].toolType);

    // MT tool type trumps BTN tool types: MT_TOOL_FINGER
    processToolType(mapper, MT_TOOL_FINGER); // this is the first time we send MT_TOOL_TYPE
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // MT tool type trumps BTN tool types: MT_TOOL_PEN
    processToolType(mapper, MT_TOOL_PEN);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::STYLUS, motionArgs.pointerProperties[0].toolType);

    // back to default tool type
    processToolType(mapper, -1); // use a deliberately undefined tool type, for testing
    processKey(mapper, BTN_TOOL_MOUSE, 0);
    processKey(mapper, BTN_TOOL_RUBBER, 0);
    processKey(mapper, BTN_TOOL_PEN, 0);
    processKey(mapper, BTN_TOOL_FINGER, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
}

TEST_F(MultiTouchInputMapperTest, Process_WhenBtnTouchPresent_HoversIfItsValueIsZero) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_TOUCH, 0, AKEYCODE_UNKNOWN, 0);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // initially hovering because BTN_TOUCH not sent yet, pressure defaults to 0
    processId(mapper, 1);
    processPosition(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_ENTER, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(100), toDisplayY(200), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(100), toDisplayY(200), 0, 0, 0, 0, 0, 0, 0, 0));

    // move a little
    processPosition(mapper, 150, 250);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    // down when BTN_TOUCH is pressed, pressure defaults to 1
    processKey(mapper, BTN_TOUCH, 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_EXIT, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 1, 0, 0, 0, 0, 0, 0, 0));

    // up when BTN_TOUCH is released, hover restored
    processKey(mapper, BTN_TOUCH, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 1, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_ENTER, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    // exit hover when pointer goes away
    processId(mapper, -1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_EXIT, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));
}

TEST_F(MultiTouchInputMapperTest, Process_WhenAbsMTPressureIsPresent_HoversIfItsValueIsZero) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | PRESSURE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // initially hovering because pressure is 0
    processId(mapper, 1);
    processPosition(mapper, 100, 200);
    processPressure(mapper, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_ENTER, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(100), toDisplayY(200), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(100), toDisplayY(200), 0, 0, 0, 0, 0, 0, 0, 0));

    // move a little
    processPosition(mapper, 150, 250);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    // down when pressure becomes non-zero
    processPressure(mapper, RAW_PRESSURE_MAX);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_EXIT, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 1, 0, 0, 0, 0, 0, 0, 0));

    // up when pressure becomes 0, hover restored
    processPressure(mapper, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 1, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_ENTER, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));

    // exit hover when pointer goes away
    processId(mapper, -1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_EXIT, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0],
            toDisplayX(150), toDisplayY(250), 0, 0, 0, 0, 0, 0, 0, 0));
}

/**
 * Set the input device port <--> display port associations, and check that the
 * events are routed to the display that matches the display port.
 * This can be checked by looking at the displayId of the resulting NotifyMotionArgs.
 */
TEST_F(MultiTouchInputMapperTest, Configure_AssignsDisplayPort) {
    const std::string usb2 = "USB2";
    const uint8_t hdmi1 = 0;
    const uint8_t hdmi2 = 1;
    const std::string secondaryUniqueId = "uniqueId2";
    constexpr ViewportType type = ViewportType::EXTERNAL;

    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareAxes(POSITION);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    mFakePolicy->addInputPortAssociation(DEVICE_LOCATION, hdmi1);
    mFakePolicy->addInputPortAssociation(usb2, hdmi2);

    // We are intentionally not adding the viewport for display 1 yet. Since the port association
    // for this input device is specified, and the matching viewport is not present,
    // the input device should be disabled (at the mapper level).

    // Add viewport for display 2 on hdmi2
    prepareSecondaryDisplay(type, hdmi2);
    // Send a touch event
    processPosition(mapper, 100, 100);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

    // Add viewport for display 1 on hdmi1
    prepareDisplay(ui::ROTATION_0, hdmi1);
    // Send a touch event again
    processPosition(mapper, 100, 100);
    processSync(mapper);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(DISPLAY_ID, args.displayId);
}

TEST_F(MultiTouchInputMapperTest, Configure_AssignsDisplayUniqueId) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareAxes(POSITION);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    mFakePolicy->addInputUniqueIdAssociation(DEVICE_LOCATION, VIRTUAL_DISPLAY_UNIQUE_ID);

    prepareDisplay(ui::ROTATION_0);
    prepareVirtualDisplay(ui::ROTATION_0);

    // Send a touch event
    processPosition(mapper, 100, 100);
    processSync(mapper);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(VIRTUAL_DISPLAY_ID, args.displayId);
}

TEST_F(MultiTouchInputMapperTest, Process_Pointer_ShouldHandleDisplayId) {
    // Setup for second display.
    std::shared_ptr<FakePointerController> fakePointerController =
            std::make_shared<FakePointerController>();
    fakePointerController->setBounds(0, 0, DISPLAY_WIDTH - 1, DISPLAY_HEIGHT - 1);
    fakePointerController->setPosition(100, 200);
    mFakePolicy->setPointerController(fakePointerController);

    mFakePolicy->setDefaultPointerDisplayId(SECONDARY_DISPLAY_ID);
    prepareSecondaryDisplay(ViewportType::EXTERNAL);

    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // Check source is mouse that would obtain the PointerController.
    ASSERT_EQ(AINPUT_SOURCE_MOUSE, mapper.getSources());

    NotifyMotionArgs motionArgs;
    processPosition(mapper, 100, 100);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, motionArgs.action);
    ASSERT_EQ(SECONDARY_DISPLAY_ID, motionArgs.displayId);
}

/**
 * Ensure that the readTime is set to the SYN_REPORT value when processing touch events.
 */
TEST_F(MultiTouchInputMapperTest, Process_SendsReadTime) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareAxes(POSITION);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    prepareDisplay(ui::ROTATION_0);
    process(mapper, 10, /*readTime=*/11, EV_ABS, ABS_MT_TRACKING_ID, 1);
    process(mapper, 15, /*readTime=*/16, EV_ABS, ABS_MT_POSITION_X, 100);
    process(mapper, 20, /*readTime=*/21, EV_ABS, ABS_MT_POSITION_Y, 100);
    process(mapper, 25, /*readTime=*/26, EV_SYN, SYN_REPORT, 0);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(26, args.readTime);

    process(mapper, 30, /*readTime=*/31, EV_ABS, ABS_MT_POSITION_X, 110);
    process(mapper, 30, /*readTime=*/32, EV_ABS, ABS_MT_POSITION_Y, 220);
    process(mapper, 30, /*readTime=*/33, EV_SYN, SYN_REPORT, 0);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(33, args.readTime);
}

/**
 * When the viewport is not active (isActive=false), the touch mapper should be disabled and the
 * events should not be delivered to the listener.
 */
TEST_F(MultiTouchInputMapperTest, WhenViewportIsNotActive_TouchesAreDropped) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    // Don't set touch.enableForInactiveViewport to verify the default behavior.
    mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/false, UNIQUE_ID, NO_PORT, ViewportType::INTERNAL);
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);
    prepareAxes(POSITION);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;
    processPosition(mapper, 100, 100);
    processSync(mapper);

    mFakeListener->assertNotifyMotionWasNotCalled();
}

/**
 * When the viewport is not active (isActive=false) and touch.enableForInactiveViewport is true,
 * the touch mapper can process the events and the events can be delivered to the listener.
 */
TEST_F(MultiTouchInputMapperTest, WhenViewportIsNotActive_TouchesAreProcessed) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    addConfigurationProperty("touch.enableForInactiveViewport", "1");
    mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/false, UNIQUE_ID, NO_PORT, ViewportType::INTERNAL);
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);
    prepareAxes(POSITION);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;
    processPosition(mapper, 100, 100);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    EXPECT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
}

/**
 * When the viewport is deactivated (isActive transitions from true to false),
 * and touch.enableForInactiveViewport is false, touches prior to the transition
 * should be cancelled.
 */
TEST_F(MultiTouchInputMapperTest, Process_DeactivateViewport_AbortTouches) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    addConfigurationProperty("touch.enableForInactiveViewport", "0");
    mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/true, UNIQUE_ID, NO_PORT, ViewportType::INTERNAL);
    std::optional<DisplayViewport> optionalDisplayViewport =
            mFakePolicy->getDisplayViewportByUniqueId(UNIQUE_ID);
    ASSERT_TRUE(optionalDisplayViewport.has_value());
    DisplayViewport displayViewport = *optionalDisplayViewport;

    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);
    prepareAxes(POSITION);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // Finger down
    int32_t x = 100, y = 100;
    processPosition(mapper, x, y);
    processSync(mapper);

    NotifyMotionArgs motionArgs;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    EXPECT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);

    // Deactivate display viewport
    displayViewport.isActive = false;
    ASSERT_TRUE(mFakePolicy->updateViewport(displayViewport));
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);

    // The ongoing touch should be canceled immediately
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    EXPECT_EQ(AMOTION_EVENT_ACTION_CANCEL, motionArgs.action);

    // Finger move is ignored
    x += 10, y += 10;
    processPosition(mapper, x, y);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

    // Reactivate display viewport
    displayViewport.isActive = true;
    ASSERT_TRUE(mFakePolicy->updateViewport(displayViewport));
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);

    // Finger move again starts new gesture
    x += 10, y += 10;
    processPosition(mapper, x, y);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    EXPECT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
}

/**
 * When the viewport is deactivated (isActive transitions from true to false),
 * and touch.enableForInactiveViewport is true, touches prior to the transition
 * should not be cancelled.
 */
TEST_F(MultiTouchInputMapperTest, Process_DeactivateViewport_TouchesNotAborted) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    addConfigurationProperty("touch.enableForInactiveViewport", "1");
    mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                    /*isActive=*/true, UNIQUE_ID, NO_PORT, ViewportType::INTERNAL);
    std::optional<DisplayViewport> optionalDisplayViewport =
            mFakePolicy->getDisplayViewportByUniqueId(UNIQUE_ID);
    ASSERT_TRUE(optionalDisplayViewport.has_value());
    DisplayViewport displayViewport = *optionalDisplayViewport;

    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);
    prepareAxes(POSITION);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // Finger down
    int32_t x = 100, y = 100;
    processPosition(mapper, x, y);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_DOWN)));

    // Deactivate display viewport
    displayViewport.isActive = false;
    ASSERT_TRUE(mFakePolicy->updateViewport(displayViewport));
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);

    // The ongoing touch should not be canceled
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

    // Finger move is not ignored
    x += 10, y += 10;
    processPosition(mapper, x, y);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_MOVE)));

    // Reactivate display viewport
    displayViewport.isActive = true;
    ASSERT_TRUE(mFakePolicy->updateViewport(displayViewport));
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);

    // Finger move continues and does not start new gesture
    x += 10, y += 10;
    processPosition(mapper, x, y);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_MOVE)));
}

TEST_F(MultiTouchInputMapperTest, Process_Pointer_ShowTouches) {
    // Setup the first touch screen device.
    prepareAxes(POSITION | ID | SLOT);
    addConfigurationProperty("touch.deviceType", "touchScreen");
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // Create the second touch screen device, and enable multi fingers.
    const std::string USB2 = "USB2";
    const std::string DEVICE_NAME2 = "TOUCHSCREEN2";
    constexpr int32_t SECOND_DEVICE_ID = DEVICE_ID + 1;
    constexpr int32_t SECOND_EVENTHUB_ID = EVENTHUB_ID + 1;
    std::shared_ptr<InputDevice> device2 =
            newDevice(SECOND_DEVICE_ID, DEVICE_NAME2, USB2, SECOND_EVENTHUB_ID,
                      ftl::Flags<InputDeviceClass>(0));

    mFakeEventHub->addAbsoluteAxis(SECOND_EVENTHUB_ID, ABS_MT_POSITION_X, RAW_X_MIN, RAW_X_MAX,
                                   /*flat=*/0, /*fuzz=*/0);
    mFakeEventHub->addAbsoluteAxis(SECOND_EVENTHUB_ID, ABS_MT_POSITION_Y, RAW_Y_MIN, RAW_Y_MAX,
                                   /*flat=*/0, /*fuzz=*/0);
    mFakeEventHub->addAbsoluteAxis(SECOND_EVENTHUB_ID, ABS_MT_TRACKING_ID, RAW_ID_MIN, RAW_ID_MAX,
                                   /*flat=*/0, /*fuzz=*/0);
    mFakeEventHub->addAbsoluteAxis(SECOND_EVENTHUB_ID, ABS_MT_SLOT, RAW_SLOT_MIN, RAW_SLOT_MAX,
                                   /*flat=*/0, /*fuzz=*/0);
    mFakeEventHub->setAbsoluteAxisValue(SECOND_EVENTHUB_ID, ABS_MT_SLOT, /*value=*/0);
    mFakeEventHub->addConfigurationProperty(SECOND_EVENTHUB_ID, String8("touch.deviceType"),
                                            String8("touchScreen"));

    // Setup the second touch screen device.
    device2->addEmptyEventHubDevice(SECOND_EVENTHUB_ID);
    MultiTouchInputMapper& mapper2 = device2->constructAndAddMapper<
            MultiTouchInputMapper>(SECOND_EVENTHUB_ID, mFakePolicy->getReaderConfiguration());
    std::list<NotifyArgs> unused =
            device2->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});
    unused += device2->reset(ARBITRARY_TIME);

    // Setup PointerController.
    std::shared_ptr<FakePointerController> fakePointerController =
            std::make_shared<FakePointerController>();
    mFakePolicy->setPointerController(fakePointerController);

    // Setup policy for associated displays and show touches.
    const uint8_t hdmi1 = 0;
    const uint8_t hdmi2 = 1;
    mFakePolicy->addInputPortAssociation(DEVICE_LOCATION, hdmi1);
    mFakePolicy->addInputPortAssociation(USB2, hdmi2);
    mFakePolicy->setShowTouches(true);

    // Create displays.
    prepareDisplay(ui::ROTATION_0, hdmi1);
    prepareSecondaryDisplay(ViewportType::EXTERNAL, hdmi2);

    // Default device will reconfigure above, need additional reconfiguration for another device.
    unused += device2->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::DISPLAY_INFO |
                                         InputReaderConfiguration::Change::SHOW_TOUCHES);

    // Two fingers down at default display.
    int32_t x1 = 100, y1 = 125, x2 = 300, y2 = 500;
    processPosition(mapper, x1, y1);
    processId(mapper, 1);
    processSlot(mapper, 1);
    processPosition(mapper, x2, y2);
    processId(mapper, 2);
    processSync(mapper);

    std::map<int32_t, std::vector<int32_t>>::const_iterator iter =
            fakePointerController->getSpots().find(DISPLAY_ID);
    ASSERT_TRUE(iter != fakePointerController->getSpots().end());
    ASSERT_EQ(size_t(2), iter->second.size());

    // Two fingers down at second display.
    processPosition(mapper2, x1, y1);
    processId(mapper2, 1);
    processSlot(mapper2, 1);
    processPosition(mapper2, x2, y2);
    processId(mapper2, 2);
    processSync(mapper2);

    iter = fakePointerController->getSpots().find(SECONDARY_DISPLAY_ID);
    ASSERT_TRUE(iter != fakePointerController->getSpots().end());
    ASSERT_EQ(size_t(2), iter->second.size());

    // Disable the show touches configuration and ensure the spots are cleared.
    mFakePolicy->setShowTouches(false);
    unused += device2->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                                 InputReaderConfiguration::Change::SHOW_TOUCHES);

    ASSERT_TRUE(fakePointerController->getSpots().empty());
}

TEST_F(MultiTouchInputMapperTest, VideoFrames_ReceivedByListener) {
    prepareAxes(POSITION);
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;
    // Unrotated video frame
    TouchVideoFrame frame(3, 2, {1, 2, 3, 4, 5, 6}, {1, 2});
    std::vector<TouchVideoFrame> frames{frame};
    mFakeEventHub->setVideoFrames({{EVENTHUB_ID, frames}});
    processPosition(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(frames, motionArgs.videoFrames);

    // Subsequent touch events should not have any videoframes
    // This is implemented separately in FakeEventHub,
    // but that should match the behaviour of TouchVideoDevice.
    processPosition(mapper, 200, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(std::vector<TouchVideoFrame>(), motionArgs.videoFrames);
}

TEST_F(MultiTouchInputMapperTest, VideoFrames_AreNotRotated) {
    prepareAxes(POSITION);
    addConfigurationProperty("touch.deviceType", "touchScreen");
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();
    // Unrotated video frame
    TouchVideoFrame frame(3, 2, {1, 2, 3, 4, 5, 6}, {1, 2});
    NotifyMotionArgs motionArgs;

    // Test all 4 orientations
    for (ui::Rotation orientation : ftl::enum_range<ui::Rotation>()) {
        SCOPED_TRACE("Orientation " + StringPrintf("%i", orientation));
        clearViewports();
        prepareDisplay(orientation);
        std::vector<TouchVideoFrame> frames{frame};
        mFakeEventHub->setVideoFrames({{EVENTHUB_ID, frames}});
        processPosition(mapper, 100, 200);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
        ASSERT_EQ(frames, motionArgs.videoFrames);
    }
}

TEST_F(MultiTouchInputMapperTest, VideoFrames_WhenNotOrientationAware_AreRotated) {
    prepareAxes(POSITION);
    addConfigurationProperty("touch.deviceType", "touchScreen");
    // Since InputReader works in the un-rotated coordinate space, only devices that are not
    // orientation-aware are affected by display rotation.
    addConfigurationProperty("touch.orientationAware", "0");
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();
    // Unrotated video frame
    TouchVideoFrame frame(3, 2, {1, 2, 3, 4, 5, 6}, {1, 2});
    NotifyMotionArgs motionArgs;

    // Test all 4 orientations
    for (ui::Rotation orientation : ftl::enum_range<ui::Rotation>()) {
        SCOPED_TRACE("Orientation " + StringPrintf("%i", orientation));
        clearViewports();
        prepareDisplay(orientation);
        std::vector<TouchVideoFrame> frames{frame};
        mFakeEventHub->setVideoFrames({{EVENTHUB_ID, frames}});
        processPosition(mapper, 100, 200);
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
        // We expect the raw coordinates of the MotionEvent to be rotated in the inverse direction
        // compared to the display. This is so that when the window transform (which contains the
        // display rotation) is applied later by InputDispatcher, the coordinates end up in the
        // window's coordinate space.
        frames[0].rotate(getInverseRotation(orientation));
        ASSERT_EQ(frames, motionArgs.videoFrames);

        // Release finger.
        processSync(mapper);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    }
}

TEST_F(MultiTouchInputMapperTest, VideoFrames_MultipleFramesAreNotRotated) {
    prepareAxes(POSITION);
    addConfigurationProperty("touch.deviceType", "touchScreen");
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();
    // Unrotated video frames. There's no rule that they must all have the same dimensions,
    // so mix these.
    TouchVideoFrame frame1(3, 2, {1, 2, 3, 4, 5, 6}, {1, 2});
    TouchVideoFrame frame2(3, 3, {0, 1, 2, 3, 4, 5, 6, 7, 8}, {1, 3});
    TouchVideoFrame frame3(2, 2, {10, 20, 10, 0}, {1, 4});
    std::vector<TouchVideoFrame> frames{frame1, frame2, frame3};
    NotifyMotionArgs motionArgs;

    prepareDisplay(ui::ROTATION_90);
    mFakeEventHub->setVideoFrames({{EVENTHUB_ID, frames}});
    processPosition(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(frames, motionArgs.videoFrames);
}

TEST_F(MultiTouchInputMapperTest, VideoFrames_WhenNotOrientationAware_MultipleFramesAreRotated) {
    prepareAxes(POSITION);
    addConfigurationProperty("touch.deviceType", "touchScreen");
    // Since InputReader works in the un-rotated coordinate space, only devices that are not
    // orientation-aware are affected by display rotation.
    addConfigurationProperty("touch.orientationAware", "0");
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();
    // Unrotated video frames. There's no rule that they must all have the same dimensions,
    // so mix these.
    TouchVideoFrame frame1(3, 2, {1, 2, 3, 4, 5, 6}, {1, 2});
    TouchVideoFrame frame2(3, 3, {0, 1, 2, 3, 4, 5, 6, 7, 8}, {1, 3});
    TouchVideoFrame frame3(2, 2, {10, 20, 10, 0}, {1, 4});
    std::vector<TouchVideoFrame> frames{frame1, frame2, frame3};
    NotifyMotionArgs motionArgs;

    prepareDisplay(ui::ROTATION_90);
    mFakeEventHub->setVideoFrames({{EVENTHUB_ID, frames}});
    processPosition(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    std::for_each(frames.begin(), frames.end(), [](TouchVideoFrame& frame) {
        // We expect the raw coordinates of the MotionEvent to be rotated in the inverse direction
        // compared to the display. This is so that when the window transform (which contains the
        // display rotation) is applied later by InputDispatcher, the coordinates end up in the
        // window's coordinate space.
        frame.rotate(getInverseRotation(ui::ROTATION_90));
    });
    ASSERT_EQ(frames, motionArgs.videoFrames);
}

/**
 * If we had defined port associations, but the viewport is not ready, the touch device would be
 * expected to be disabled, and it should be enabled after the viewport has found.
 */
TEST_F(MultiTouchInputMapperTest, Configure_EnabledForAssociatedDisplay) {
    constexpr uint8_t hdmi2 = 1;
    const std::string secondaryUniqueId = "uniqueId2";
    constexpr ViewportType type = ViewportType::EXTERNAL;

    mFakePolicy->addInputPortAssociation(DEVICE_LOCATION, hdmi2);

    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareAxes(POSITION);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    ASSERT_EQ(mDevice->isEnabled(), false);

    // Add display on hdmi2, the device should be enabled and can receive touch event.
    prepareSecondaryDisplay(type, hdmi2);
    ASSERT_EQ(mDevice->isEnabled(), true);

    // Send a touch event.
    processPosition(mapper, 100, 100);
    processSync(mapper);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(SECONDARY_DISPLAY_ID, args.displayId);
}

TEST_F(MultiTouchInputMapperTest, Process_ShouldHandleSingleTouch) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | TOOL_TYPE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    constexpr int32_t x1 = 100, y1 = 200, x2 = 120, y2 = 220, x3 = 140, y3 = 240;
    // finger down
    processId(mapper, 1);
    processPosition(mapper, x1, y1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // finger move
    processId(mapper, 1);
    processPosition(mapper, x2, y2);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // finger up.
    processId(mapper, -1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // new finger down
    processId(mapper, 1);
    processPosition(mapper, x3, y3);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
}

/**
 * Test single touch should be canceled when received the MT_TOOL_PALM event, and the following
 * MOVE and UP events should be ignored.
 */
TEST_F(MultiTouchInputMapperTest, Process_ShouldHandlePalmToolType_SinglePointer) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | TOOL_TYPE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // default tool type is finger
    constexpr int32_t x1 = 100, y1 = 200, x2 = 120, y2 = 220, x3 = 140, y3 = 240;
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // Tool changed to MT_TOOL_PALM expect sending the cancel event.
    processToolType(mapper, MT_TOOL_PALM);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_CANCEL, motionArgs.action);

    // Ignore the following MOVE and UP events if had detect a palm event.
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

    // finger up.
    processId(mapper, INVALID_TRACKING_ID);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

    // new finger down
    processId(mapper, FIRST_TRACKING_ID);
    processToolType(mapper, MT_TOOL_FINGER);
    processPosition(mapper, x3, y3);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
}

/**
 * Test multi-touch should sent POINTER_UP when received the MT_TOOL_PALM event from some finger,
 * and the rest active fingers could still be allowed to receive the events
 */
TEST_F(MultiTouchInputMapperTest, Process_ShouldHandlePalmToolType_TwoPointers) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | TOOL_TYPE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // default tool type is finger
    constexpr int32_t x1 = 100, y1 = 200, x2 = 120, y2 = 220;
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // Second finger down.
    processSlot(mapper, SECOND_SLOT);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_1_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[1].toolType);

    // If the tool type of the first finger changes to MT_TOOL_PALM,
    // we expect to receive ACTION_POINTER_UP with cancel flag.
    processSlot(mapper, FIRST_SLOT);
    processId(mapper, FIRST_TRACKING_ID);
    processToolType(mapper, MT_TOOL_PALM);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_0_UP, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_FLAG_CANCELED, motionArgs.flags);

    // The following MOVE events of second finger should be processed.
    processSlot(mapper, SECOND_SLOT);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2 + 1, y2 + 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(uint32_t(1), motionArgs.getPointerCount());

    // First finger up. It used to be in palm mode, and we already generated ACTION_POINTER_UP for
    // it. Second finger receive move.
    processSlot(mapper, FIRST_SLOT);
    processId(mapper, INVALID_TRACKING_ID);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(uint32_t(1), motionArgs.getPointerCount());

    // Second finger keeps moving.
    processSlot(mapper, SECOND_SLOT);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2 + 2, y2 + 2);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(uint32_t(1), motionArgs.getPointerCount());

    // Second finger up.
    processId(mapper, INVALID_TRACKING_ID);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_NE(AMOTION_EVENT_FLAG_CANCELED, motionArgs.flags);
}

/**
 * Test multi-touch should sent POINTER_UP when received the MT_TOOL_PALM event, if only 1 finger
 * is active, it should send CANCEL after receiving the MT_TOOL_PALM event.
 */
TEST_F(MultiTouchInputMapperTest, Process_ShouldHandlePalmToolType_ShouldCancelWhenAllTouchIsPalm) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | TOOL_TYPE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    constexpr int32_t x1 = 100, y1 = 200, x2 = 120, y2 = 220, x3 = 140, y3 = 240;
    // First finger down.
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // Second finger down.
    processSlot(mapper, SECOND_SLOT);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_1_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // If the tool type of the first finger changes to MT_TOOL_PALM,
    // we expect to receive ACTION_POINTER_UP with cancel flag.
    processSlot(mapper, FIRST_SLOT);
    processId(mapper, FIRST_TRACKING_ID);
    processToolType(mapper, MT_TOOL_PALM);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_0_UP, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_FLAG_CANCELED, motionArgs.flags);

    // Second finger keeps moving.
    processSlot(mapper, SECOND_SLOT);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2 + 1, y2 + 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);

    // second finger becomes palm, receive cancel due to only 1 finger is active.
    processId(mapper, SECOND_TRACKING_ID);
    processToolType(mapper, MT_TOOL_PALM);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_CANCEL, motionArgs.action);

    // third finger down.
    processSlot(mapper, THIRD_SLOT);
    processId(mapper, THIRD_TRACKING_ID);
    processToolType(mapper, MT_TOOL_FINGER);
    processPosition(mapper, x3, y3);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(uint32_t(1), motionArgs.getPointerCount());

    // third finger move
    processId(mapper, THIRD_TRACKING_ID);
    processPosition(mapper, x3 + 1, y3 + 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);

    // first finger up, third finger receive move.
    processSlot(mapper, FIRST_SLOT);
    processId(mapper, INVALID_TRACKING_ID);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(uint32_t(1), motionArgs.getPointerCount());

    // second finger up, third finger receive move.
    processSlot(mapper, SECOND_SLOT);
    processId(mapper, INVALID_TRACKING_ID);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(uint32_t(1), motionArgs.getPointerCount());

    // third finger up.
    processSlot(mapper, THIRD_SLOT);
    processId(mapper, INVALID_TRACKING_ID);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_NE(AMOTION_EVENT_FLAG_CANCELED, motionArgs.flags);
}

/**
 * Test multi-touch should sent POINTER_UP when received the MT_TOOL_PALM event from some finger,
 * and the active finger could still be allowed to receive the events
 */
TEST_F(MultiTouchInputMapperTest, Process_ShouldHandlePalmToolType_KeepFirstPointer) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | TOOL_TYPE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // default tool type is finger
    constexpr int32_t x1 = 100, y1 = 200, x2 = 120, y2 = 220;
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // Second finger down.
    processSlot(mapper, SECOND_SLOT);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_1_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);

    // If the tool type of the second finger changes to MT_TOOL_PALM,
    // we expect to receive ACTION_POINTER_UP with cancel flag.
    processId(mapper, SECOND_TRACKING_ID);
    processToolType(mapper, MT_TOOL_PALM);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_1_UP, motionArgs.action);
    ASSERT_EQ(AMOTION_EVENT_FLAG_CANCELED, motionArgs.flags);

    // The following MOVE event should be processed.
    processSlot(mapper, FIRST_SLOT);
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1 + 1, y1 + 1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(uint32_t(1), motionArgs.getPointerCount());

    // second finger up.
    processSlot(mapper, SECOND_SLOT);
    processId(mapper, INVALID_TRACKING_ID);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);

    // first finger keep moving
    processSlot(mapper, FIRST_SLOT);
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1 + 2, y1 + 2);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);

    // first finger up.
    processId(mapper, INVALID_TRACKING_ID);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_NE(AMOTION_EVENT_FLAG_CANCELED, motionArgs.flags);
}

/**
 * Test multi-touch should sent ACTION_POINTER_UP/ACTION_UP when received the INVALID_TRACKING_ID,
 * to prevent the driver side may send unexpected data after set tracking id as INVALID_TRACKING_ID
 * cause slot be valid again.
 */
TEST_F(MultiTouchInputMapperTest, Process_MultiTouch_WithInvalidTrackingId) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | PRESSURE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    constexpr int32_t x1 = 100, y1 = 200, x2 = 0, y2 = 0;
    // First finger down.
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processPressure(mapper, RAW_PRESSURE_MAX);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(uint32_t(1), motionArgs.getPointerCount());

    // First finger move.
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1 + 1, y1 + 1);
    processPressure(mapper, RAW_PRESSURE_MAX);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(uint32_t(1), motionArgs.getPointerCount());

    // Second finger down.
    processSlot(mapper, SECOND_SLOT);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processPressure(mapper, RAW_PRESSURE_MAX);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_1_DOWN, motionArgs.action);
    ASSERT_EQ(uint32_t(2), motionArgs.getPointerCount());

    // second finger up with some unexpected data.
    processSlot(mapper, SECOND_SLOT);
    processId(mapper, INVALID_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ACTION_POINTER_1_UP, motionArgs.action);
    ASSERT_EQ(uint32_t(2), motionArgs.getPointerCount());

    // first finger up with some unexpected data.
    processSlot(mapper, FIRST_SLOT);
    processId(mapper, INVALID_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processPressure(mapper, RAW_PRESSURE_MAX);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, motionArgs.action);
    ASSERT_EQ(uint32_t(1), motionArgs.getPointerCount());
}

TEST_F(MultiTouchInputMapperTest, Reset_RepopulatesMultiTouchState) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | PRESSURE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // First finger down.
    constexpr int32_t x1 = 100, y1 = 200, x2 = 300, y2 = 400;
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processPressure(mapper, RAW_PRESSURE_MAX);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_DOWN)));

    // Second finger down.
    processSlot(mapper, SECOND_SLOT);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processPressure(mapper, RAW_PRESSURE_MAX);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(
            mFakeListener->assertNotifyMotionWasCalled(WithMotionAction(ACTION_POINTER_1_DOWN)));

    // Set MT Slot state to be repopulated for the required slots
    std::vector<int32_t> mtSlotValues(RAW_SLOT_MAX + 1, -1);
    mtSlotValues[0] = FIRST_TRACKING_ID;
    mtSlotValues[1] = SECOND_TRACKING_ID;
    mFakeEventHub->setMtSlotValues(EVENTHUB_ID, ABS_MT_TRACKING_ID, mtSlotValues);

    mtSlotValues[0] = x1;
    mtSlotValues[1] = x2;
    mFakeEventHub->setMtSlotValues(EVENTHUB_ID, ABS_MT_POSITION_X, mtSlotValues);

    mtSlotValues[0] = y1;
    mtSlotValues[1] = y2;
    mFakeEventHub->setMtSlotValues(EVENTHUB_ID, ABS_MT_POSITION_Y, mtSlotValues);

    mtSlotValues[0] = RAW_PRESSURE_MAX;
    mtSlotValues[1] = RAW_PRESSURE_MAX;
    mFakeEventHub->setMtSlotValues(EVENTHUB_ID, ABS_MT_PRESSURE, mtSlotValues);

    // Reset the mapper. When the mapper is reset, we expect the current multi-touch state to be
    // repopulated. Resetting should cancel the ongoing gesture.
    resetMapper(mapper, ARBITRARY_TIME);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_CANCEL)));

    // Send a sync to simulate an empty touch frame where nothing changes. The mapper should use
    // the existing touch state to generate a down event.
    processPosition(mapper, 301, 302);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithPressure(1.f))));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(ACTION_POINTER_1_DOWN), WithPressure(1.f))));

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(MultiTouchInputMapperTest, Reset_PreservesLastTouchState_NoPointersDown) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | PRESSURE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // First finger touches down and releases.
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, 100, 200);
    processPressure(mapper, RAW_PRESSURE_MAX);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            WithMotionAction(AMOTION_EVENT_ACTION_DOWN)));
    processId(mapper, INVALID_TRACKING_ID);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(
            mFakeListener->assertNotifyMotionWasCalled(WithMotionAction(AMOTION_EVENT_ACTION_UP)));

    // Reset the mapper. When the mapper is reset, we expect it to restore the latest
    // raw state where no pointers are down.
    resetMapper(mapper, ARBITRARY_TIME);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

    // Send an empty sync frame. Since there are no pointers, no events are generated.
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

TEST_F(MultiTouchInputMapperTest, StylusSourceIsAddedDynamicallyFromToolType) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | PRESSURE | TOOL_TYPE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled());

    // Even if the device supports reporting the ABS_MT_TOOL_TYPE axis, which could give it the
    // ability to report MT_TOOL_PEN, we do not report the device as coming from a stylus source.
    // Due to limitations in the evdev protocol, we cannot say for certain that a device is capable
    // of reporting stylus events just because it supports ABS_MT_TOOL_TYPE.
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, mapper.getSources());

    // However, if the device ever ends up reporting an event with MT_TOOL_PEN, it should be
    // reported with the stylus source.
    processId(mapper, FIRST_TRACKING_ID);
    processToolType(mapper, MT_TOOL_PEN);
    processPosition(mapper, 100, 200);
    processPressure(mapper, RAW_PRESSURE_MAX);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithSource(AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_STYLUS),
                  WithToolType(ToolType::STYLUS))));

    // Now that we know the device supports styluses, ensure that the device is re-configured with
    // the stylus source.
    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_STYLUS, mapper.getSources());
    {
        const auto& devices = mReader->getInputDevices();
        auto deviceInfo =
                std::find_if(devices.begin(), devices.end(),
                             [](const InputDeviceInfo& info) { return info.getId() == DEVICE_ID; });
        LOG_ALWAYS_FATAL_IF(deviceInfo == devices.end(), "Cannot find InputDevice");
        ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_STYLUS, deviceInfo->getSources());
    }

    // Ensure the device was not reset to prevent interruptions of any ongoing gestures.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasNotCalled());

    processId(mapper, INVALID_TRACKING_ID);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                  WithSource(AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_STYLUS),
                  WithToolType(ToolType::STYLUS))));
}

TEST_F(MultiTouchInputMapperTest, Process_WhenConfigEnabled_ShouldShowDirectStylusPointer) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | TOOL_TYPE | PRESSURE);
    // Add BTN_TOOL_PEN to statically show stylus support, since using ABS_MT_TOOL_TYPE can only
    // indicate stylus presence dynamically.
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_TOOL_PEN, 0, AKEYCODE_UNKNOWN, 0);
    std::shared_ptr<FakePointerController> fakePointerController =
            std::make_shared<FakePointerController>();
    mFakePolicy->setPointerController(fakePointerController);
    mFakePolicy->setStylusPointerIconEnabled(true);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    processId(mapper, FIRST_TRACKING_ID);
    processPressure(mapper, RAW_PRESSURE_MIN);
    processPosition(mapper, 100, 200);
    processToolType(mapper, MT_TOOL_PEN);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                  WithToolType(ToolType::STYLUS),
                  WithPointerCoords(0, toDisplayX(100), toDisplayY(200)))));
    ASSERT_TRUE(fakePointerController->isPointerShown());
    ASSERT_NO_FATAL_FAILURE(
            fakePointerController->assertPosition(toDisplayX(100), toDisplayY(200)));
}

TEST_F(MultiTouchInputMapperTest, Process_WhenConfigDisabled_ShouldNotShowDirectStylusPointer) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | TOOL_TYPE | PRESSURE);
    // Add BTN_TOOL_PEN to statically show stylus support, since using ABS_MT_TOOL_TYPE can only
    // indicate stylus presence dynamically.
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_TOOL_PEN, 0, AKEYCODE_UNKNOWN, 0);
    std::shared_ptr<FakePointerController> fakePointerController =
            std::make_shared<FakePointerController>();
    mFakePolicy->setPointerController(fakePointerController);
    mFakePolicy->setStylusPointerIconEnabled(false);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    processId(mapper, FIRST_TRACKING_ID);
    processPressure(mapper, RAW_PRESSURE_MIN);
    processPosition(mapper, 100, 200);
    processToolType(mapper, MT_TOOL_PEN);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                  WithToolType(ToolType::STYLUS),
                  WithPointerCoords(0, toDisplayX(100), toDisplayY(200)))));
    ASSERT_FALSE(fakePointerController->isPointerShown());
}

// --- MultiTouchInputMapperTest_ExternalDevice ---

class MultiTouchInputMapperTest_ExternalDevice : public MultiTouchInputMapperTest {
protected:
    void SetUp() override { InputMapperTest::SetUp(DEVICE_CLASSES | InputDeviceClass::EXTERNAL); }
};

/**
 * Expect fallback to internal viewport if device is external and external viewport is not present.
 */
TEST_F(MultiTouchInputMapperTest_ExternalDevice, Viewports_Fallback) {
    prepareAxes(POSITION);
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    ASSERT_EQ(AINPUT_SOURCE_TOUCHSCREEN, mapper.getSources());

    NotifyMotionArgs motionArgs;

    // Expect the event to be sent to the internal viewport,
    // because an external viewport is not present.
    processPosition(mapper, 100, 100);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ADISPLAY_ID_DEFAULT, motionArgs.displayId);

    // Expect the event to be sent to the external viewport if it is present.
    prepareSecondaryDisplay(ViewportType::EXTERNAL);
    processPosition(mapper, 100, 100);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(SECONDARY_DISPLAY_ID, motionArgs.displayId);
}

TEST_F(MultiTouchInputMapperTest, Process_TouchpadCapture) {
    // we need a pointer controller for mouse mode of touchpad (start pointer at 0,0)
    std::shared_ptr<FakePointerController> fakePointerController =
            std::make_shared<FakePointerController>();
    fakePointerController->setBounds(0, 0, DISPLAY_WIDTH - 1, DISPLAY_HEIGHT - 1);
    fakePointerController->setPosition(0, 0);

    // prepare device and capture
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_LEFT, 0, AKEYCODE_UNKNOWN, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_TOUCH, 0, AKEYCODE_UNKNOWN, 0);
    mFakePolicy->setPointerCapture(true);
    mFakePolicy->setPointerController(fakePointerController);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // captured touchpad should be a touchpad source
    NotifyDeviceResetArgs resetArgs;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_EQ(AINPUT_SOURCE_TOUCHPAD, mapper.getSources());

    InputDeviceInfo deviceInfo = mDevice->getDeviceInfo();

    const InputDeviceInfo::MotionRange* relRangeX =
            deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_RELATIVE_X, AINPUT_SOURCE_TOUCHPAD);
    ASSERT_NE(relRangeX, nullptr);
    ASSERT_EQ(relRangeX->min, -(RAW_X_MAX - RAW_X_MIN));
    ASSERT_EQ(relRangeX->max, RAW_X_MAX - RAW_X_MIN);
    const InputDeviceInfo::MotionRange* relRangeY =
            deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_RELATIVE_Y, AINPUT_SOURCE_TOUCHPAD);
    ASSERT_NE(relRangeY, nullptr);
    ASSERT_EQ(relRangeY->min, -(RAW_Y_MAX - RAW_Y_MIN));
    ASSERT_EQ(relRangeY->max, RAW_Y_MAX - RAW_Y_MIN);

    // run captured pointer tests - note that this is unscaled, so input listener events should be
    //                              identical to what the hardware sends (accounting for any
    //                              calibration).
    // FINGER 0 DOWN
    processSlot(mapper, 0);
    processId(mapper, 1);
    processPosition(mapper, 100 + RAW_X_MIN, 100 + RAW_Y_MIN);
    processKey(mapper, BTN_TOUCH, 1);
    processSync(mapper);

    // expect coord[0] to contain initial location of touch 0
    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, args.action);
    ASSERT_EQ(1U, args.getPointerCount());
    ASSERT_EQ(0, args.pointerProperties[0].id);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHPAD, args.source);
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(args.pointerCoords[0], 100, 100, 1, 0, 0, 0, 0, 0, 0, 0));

    // FINGER 1 DOWN
    processSlot(mapper, 1);
    processId(mapper, 2);
    processPosition(mapper, 560 + RAW_X_MIN, 154 + RAW_Y_MIN);
    processSync(mapper);

    // expect coord[0] to contain previous location, coord[1] to contain new touch 1 location
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(ACTION_POINTER_1_DOWN, args.action);
    ASSERT_EQ(2U, args.getPointerCount());
    ASSERT_EQ(0, args.pointerProperties[0].id);
    ASSERT_EQ(1, args.pointerProperties[1].id);
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(args.pointerCoords[0], 100, 100, 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(args.pointerCoords[1], 560, 154, 1, 0, 0, 0, 0, 0, 0, 0));

    // FINGER 1 MOVE
    processPosition(mapper, 540 + RAW_X_MIN, 690 + RAW_Y_MIN);
    processSync(mapper);

    // expect coord[0] to contain previous location, coord[1] to contain new touch 1 location
    // from move
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, args.action);
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(args.pointerCoords[0], 100, 100, 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(args.pointerCoords[1], 540, 690, 1, 0, 0, 0, 0, 0, 0, 0));

    // FINGER 0 MOVE
    processSlot(mapper, 0);
    processPosition(mapper, 50 + RAW_X_MIN, 800 + RAW_Y_MIN);
    processSync(mapper);

    // expect coord[0] to contain new touch 0 location, coord[1] to contain previous location
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, args.action);
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(args.pointerCoords[0], 50, 800, 1, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(args.pointerCoords[1], 540, 690, 1, 0, 0, 0, 0, 0, 0, 0));

    // BUTTON DOWN
    processKey(mapper, BTN_LEFT, 1);
    processSync(mapper);

    // touchinputmapper design sends a move before button press
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, args.action);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, args.action);

    // BUTTON UP
    processKey(mapper, BTN_LEFT, 0);
    processSync(mapper);

    // touchinputmapper design sends a move after button release
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, args.action);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, args.action);

    // FINGER 0 UP
    processId(mapper, -1);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_POINTER_UP | 0x0000, args.action);

    // FINGER 1 MOVE
    processSlot(mapper, 1);
    processPosition(mapper, 320 + RAW_X_MIN, 900 + RAW_Y_MIN);
    processSync(mapper);

    // expect coord[0] to contain new location of touch 1, and properties[0].id to contain 1
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, args.action);
    ASSERT_EQ(1U, args.getPointerCount());
    ASSERT_EQ(1, args.pointerProperties[0].id);
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(args.pointerCoords[0], 320, 900, 1, 0, 0, 0, 0, 0, 0, 0));

    // FINGER 1 UP
    processId(mapper, -1);
    processKey(mapper, BTN_TOUCH, 0);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, args.action);

    // non captured touchpad should be a mouse source
    mFakePolicy->setPointerCapture(false);
    configureDevice(InputReaderConfiguration::Change::POINTER_CAPTURE);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled(&resetArgs));
    ASSERT_EQ(AINPUT_SOURCE_MOUSE, mapper.getSources());
}

TEST_F(MultiTouchInputMapperTest, Process_UnCapturedTouchpadPointer) {
    std::shared_ptr<FakePointerController> fakePointerController =
            std::make_shared<FakePointerController>();
    fakePointerController->setBounds(0, 0, DISPLAY_WIDTH - 1, DISPLAY_HEIGHT - 1);
    fakePointerController->setPosition(0, 0);

    // prepare device and capture
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_LEFT, 0, AKEYCODE_UNKNOWN, 0);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_TOUCH, 0, AKEYCODE_UNKNOWN, 0);
    mFakePolicy->setPointerController(fakePointerController);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();
    // run uncaptured pointer tests - pushes out generic events
    // FINGER 0 DOWN
    processId(mapper, 3);
    processPosition(mapper, 100, 100);
    processKey(mapper, BTN_TOUCH, 1);
    processSync(mapper);

    // start at (100,100), cursor should be at (0,0) * scale
    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, args.action);
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(args.pointerCoords[0], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));

    // FINGER 0 MOVE
    processPosition(mapper, 200, 200);
    processSync(mapper);

    // compute scaling to help with touch position checking
    float rawDiagonal = hypotf(RAW_X_MAX - RAW_X_MIN, RAW_Y_MAX - RAW_Y_MIN);
    float displayDiagonal = hypotf(DISPLAY_WIDTH, DISPLAY_HEIGHT);
    float scale =
            mFakePolicy->getPointerGestureMovementSpeedRatio() * displayDiagonal / rawDiagonal;

    // translate from (100,100) -> (200,200), cursor should have changed to (100,100) * scale)
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_HOVER_MOVE, args.action);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(args.pointerCoords[0], 100 * scale, 100 * scale, 0,
                                                0, 0, 0, 0, 0, 0, 0));

    // BUTTON DOWN
    processKey(mapper, BTN_LEFT, 1);
    processSync(mapper);

    // touchinputmapper design sends a move before button press
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, args.action);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_PRESS, args.action);

    // BUTTON UP
    processKey(mapper, BTN_LEFT, 0);
    processSync(mapper);

    // touchinputmapper design sends a move after button release
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_BUTTON_RELEASE, args.action);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(AMOTION_EVENT_ACTION_UP, args.action);
}

TEST_F(MultiTouchInputMapperTest, WhenCapturedAndNotCaptured_GetSources) {
    std::shared_ptr<FakePointerController> fakePointerController =
            std::make_shared<FakePointerController>();

    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_LEFT, 0, AKEYCODE_UNKNOWN, 0);
    mFakePolicy->setPointerController(fakePointerController);
    mFakePolicy->setPointerCapture(false);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    // uncaptured touchpad should be a pointer device
    ASSERT_EQ(AINPUT_SOURCE_MOUSE, mapper.getSources());

    // captured touchpad should be a touchpad device
    mFakePolicy->setPointerCapture(true);
    configureDevice(InputReaderConfiguration::Change::POINTER_CAPTURE);
    ASSERT_EQ(AINPUT_SOURCE_TOUCHPAD, mapper.getSources());
}

// --- BluetoothMultiTouchInputMapperTest ---

class BluetoothMultiTouchInputMapperTest : public MultiTouchInputMapperTest {
protected:
    void SetUp() override {
        InputMapperTest::SetUp(DEVICE_CLASSES | InputDeviceClass::EXTERNAL, BUS_BLUETOOTH);
    }
};

TEST_F(BluetoothMultiTouchInputMapperTest, TimestampSmoothening) {
    addConfigurationProperty("touch.deviceType", "touchScreen");
    prepareDisplay(ui::ROTATION_0);
    prepareAxes(POSITION | ID | SLOT | PRESSURE);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    nsecs_t kernelEventTime = ARBITRARY_TIME;
    nsecs_t expectedEventTime = ARBITRARY_TIME;
    // Touch down.
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, 100, 200);
    processPressure(mapper, RAW_PRESSURE_MAX);
    processSync(mapper, ARBITRARY_TIME);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN), WithEventTime(ARBITRARY_TIME))));

    // Process several events that come in quick succession, according to their timestamps.
    for (int i = 0; i < 3; i++) {
        constexpr static nsecs_t delta = ms2ns(1);
        static_assert(delta < MIN_BLUETOOTH_TIMESTAMP_DELTA);
        kernelEventTime += delta;
        expectedEventTime += MIN_BLUETOOTH_TIMESTAMP_DELTA;

        processPosition(mapper, 101 + i, 201 + i);
        processSync(mapper, kernelEventTime);
        ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                      WithEventTime(expectedEventTime))));
    }

    // Release the touch.
    processId(mapper, INVALID_TRACKING_ID);
    processPressure(mapper, RAW_PRESSURE_MIN);
    processSync(mapper, ARBITRARY_TIME + ms2ns(50));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                  WithEventTime(ARBITRARY_TIME + ms2ns(50)))));
}

// --- MultiTouchPointerModeTest ---

class MultiTouchPointerModeTest : public MultiTouchInputMapperTest {
protected:
    float mPointerMovementScale;
    float mPointerXZoomScale;
    void preparePointerMode(int xAxisResolution, int yAxisResolution) {
        addConfigurationProperty("touch.deviceType", "pointer");
        std::shared_ptr<FakePointerController> fakePointerController =
                std::make_shared<FakePointerController>();
        fakePointerController->setBounds(0, 0, DISPLAY_WIDTH - 1, DISPLAY_HEIGHT - 1);
        fakePointerController->setPosition(0, 0);
        prepareDisplay(ui::ROTATION_0);

        prepareAxes(POSITION);
        prepareAbsoluteAxisResolution(xAxisResolution, yAxisResolution);
        // In order to enable swipe and freeform gesture in pointer mode, pointer capture
        // needs to be disabled, and the pointer gesture needs to be enabled.
        mFakePolicy->setPointerCapture(false);
        mFakePolicy->setPointerGestureEnabled(true);
        mFakePolicy->setPointerController(fakePointerController);

        float rawDiagonal = hypotf(RAW_X_MAX - RAW_X_MIN, RAW_Y_MAX - RAW_Y_MIN);
        float displayDiagonal = hypotf(DISPLAY_WIDTH, DISPLAY_HEIGHT);
        mPointerMovementScale =
                mFakePolicy->getPointerGestureMovementSpeedRatio() * displayDiagonal / rawDiagonal;
        mPointerXZoomScale =
                mFakePolicy->getPointerGestureZoomSpeedRatio() * displayDiagonal / rawDiagonal;
    }

    void prepareAbsoluteAxisResolution(int xAxisResolution, int yAxisResolution) {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_X, RAW_X_MIN, RAW_X_MAX,
                                       /*flat*/ 0,
                                       /*fuzz*/ 0, /*resolution*/ xAxisResolution);
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_MT_POSITION_Y, RAW_Y_MIN, RAW_Y_MAX,
                                       /*flat*/ 0,
                                       /*fuzz*/ 0, /*resolution*/ yAxisResolution);
    }
};

/**
 * Two fingers down on a pointer mode touch pad. The width
 * of the two finger is larger than 1/4 of the touch pack diagnal length. However, it
 * is smaller than the fixed min physical length 30mm. Two fingers' distance must
 * be greater than the both value to be freeform gesture, so that after two
 * fingers start to move downwards, the gesture should be swipe.
 */
TEST_F(MultiTouchPointerModeTest, PointerGestureMaxSwipeWidthSwipe) {
    // The min freeform gesture width is 25units/mm x 30mm = 750
    // which is greater than fraction of the diagnal length of the touchpad (349).
    // Thus, MaxSwipWidth is 750.
    preparePointerMode(/*xResolution=*/25, /*yResolution=*/25);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();
    NotifyMotionArgs motionArgs;

    // Two fingers down at once.
    // The two fingers are 450 units apart, expects the current gesture to be PRESS
    // Pointer's initial position is used the [0,0] coordinate.
    int32_t x1 = 100, y1 = 125, x2 = 550, y2 = 125;

    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processMTSync(mapper);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(1U, motionArgs.getPointerCount());
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(MotionClassification::NONE, motionArgs.classification);
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(motionArgs.pointerCoords[0], 0, 0, 1, 0, 0, 0, 0, 0, 0, 0));

    // It should be recognized as a SWIPE gesture when two fingers start to move down,
    // that there should be 1 pointer.
    int32_t movingDistance = 200;
    y1 += movingDistance;
    y2 += movingDistance;

    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processMTSync(mapper);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(1U, motionArgs.getPointerCount());
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(MotionClassification::TWO_FINGER_SWIPE, motionArgs.classification);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0], 0,
                                                movingDistance * mPointerMovementScale, 1, 0, 0, 0,
                                                0, 0, 0, 0));
}

/**
 * Two fingers down on a pointer mode touch pad. The width of the two finger is larger
 * than the minimum freeform gesture width, 30mm. However, it is smaller than 1/4 of
 * the touch pack diagnal length. Two fingers' distance must be greater than the both
 * value to be freeform gesture, so that after two fingers start to move downwards,
 * the gesture should be swipe.
 */
TEST_F(MultiTouchPointerModeTest, PointerGestureMaxSwipeWidthLowResolutionSwipe) {
    // The min freeform gesture width is 5units/mm x 30mm = 150
    // which is greater than fraction of the diagnal length of the touchpad (349).
    // Thus, MaxSwipWidth is the fraction of the diagnal length, 349.
    preparePointerMode(/*xResolution=*/5, /*yResolution=*/5);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();
    NotifyMotionArgs motionArgs;

    // Two fingers down at once.
    // The two fingers are 250 units apart, expects the current gesture to be PRESS
    // Pointer's initial position is used the [0,0] coordinate.
    int32_t x1 = 100, y1 = 125, x2 = 350, y2 = 125;

    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processMTSync(mapper);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(1U, motionArgs.getPointerCount());
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(MotionClassification::NONE, motionArgs.classification);
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(motionArgs.pointerCoords[0], 0, 0, 1, 0, 0, 0, 0, 0, 0, 0));

    // It should be recognized as a SWIPE gesture when two fingers start to move down,
    // and there should be 1 pointer.
    int32_t movingDistance = 200;
    y1 += movingDistance;
    y2 += movingDistance;

    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processMTSync(mapper);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(1U, motionArgs.getPointerCount());
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(MotionClassification::TWO_FINGER_SWIPE, motionArgs.classification);
    // New coordinate is the scaled relative coordinate from the initial coordinate.
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0], 0,
                                                movingDistance * mPointerMovementScale, 1, 0, 0, 0,
                                                0, 0, 0, 0));
}

/**
 * Touch the touch pad with two fingers with a distance wider than the minimum freeform
 * gesture width and 1/4 of the diagnal length of the touchpad. Expect to receive
 * freeform gestures after two fingers start to move downwards.
 */
TEST_F(MultiTouchPointerModeTest, PointerGestureMaxSwipeWidthFreeform) {
    preparePointerMode(/*xResolution=*/25, /*yResolution=*/25);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();

    NotifyMotionArgs motionArgs;

    // Two fingers down at once. Wider than the max swipe width.
    // The gesture is expected to be PRESS, then transformed to FREEFORM
    int32_t x1 = 100, y1 = 125, x2 = 900, y2 = 125;

    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processMTSync(mapper);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(1U, motionArgs.getPointerCount());
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(MotionClassification::NONE, motionArgs.classification);
    // One pointer for PRESS, and its coordinate is used as the origin for pointer coordinates.
    ASSERT_NO_FATAL_FAILURE(
            assertPointerCoords(motionArgs.pointerCoords[0], 0, 0, 1, 0, 0, 0, 0, 0, 0, 0));

    int32_t movingDistance = 200;

    // Move two fingers down, expect a cancel event because gesture is changing to freeform,
    // then two down events for two pointers.
    y1 += movingDistance;
    y2 += movingDistance;

    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processMTSync(mapper);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    // The previous PRESS gesture is cancelled, because it is transformed to freeform
    ASSERT_EQ(1U, motionArgs.getPointerCount());
    ASSERT_EQ(AMOTION_EVENT_ACTION_CANCEL, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(1U, motionArgs.getPointerCount());
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(MotionClassification::NONE, motionArgs.classification);
    ASSERT_EQ(2U, motionArgs.getPointerCount());
    ASSERT_EQ(AMOTION_EVENT_ACTION_POINTER_DOWN, motionArgs.action & AMOTION_EVENT_ACTION_MASK);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(MotionClassification::NONE, motionArgs.classification);
    // Two pointers' scaled relative coordinates from their initial centroid.
    // Initial y coordinates are 0 as y1 and y2 have the same value.
    float cookedX1 = (x1 - x2) / 2 * mPointerXZoomScale;
    float cookedX2 = (x2 - x1) / 2 * mPointerXZoomScale;
    // When pointers move,  the new coordinates equal to the initial coordinates plus
    // scaled moving distance.
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0], cookedX1,
                                                movingDistance * mPointerMovementScale, 1, 0, 0, 0,
                                                0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1], cookedX2,
                                                movingDistance * mPointerMovementScale, 1, 0, 0, 0,
                                                0, 0, 0, 0));

    // Move two fingers down again, expect one MOVE motion event.
    y1 += movingDistance;
    y2 += movingDistance;

    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processMTSync(mapper);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(2U, motionArgs.getPointerCount());
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(ToolType::FINGER, motionArgs.pointerProperties[0].toolType);
    ASSERT_EQ(MotionClassification::NONE, motionArgs.classification);
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[0], cookedX1,
                                                movingDistance * 2 * mPointerMovementScale, 1, 0, 0,
                                                0, 0, 0, 0, 0));
    ASSERT_NO_FATAL_FAILURE(assertPointerCoords(motionArgs.pointerCoords[1], cookedX2,
                                                movingDistance * 2 * mPointerMovementScale, 1, 0, 0,
                                                0, 0, 0, 0, 0));
}

TEST_F(MultiTouchPointerModeTest, TwoFingerSwipeOffsets) {
    preparePointerMode(/*xResolution=*/25, /*yResolution=*/25);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();
    NotifyMotionArgs motionArgs;

    // Place two fingers down.
    int32_t x1 = 100, y1 = 125, x2 = 550, y2 = 125;

    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processMTSync(mapper);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(1U, motionArgs.getPointerCount());
    ASSERT_EQ(AMOTION_EVENT_ACTION_DOWN, motionArgs.action);
    ASSERT_EQ(MotionClassification::NONE, motionArgs.classification);
    ASSERT_EQ(0, motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_GESTURE_X_OFFSET));
    ASSERT_EQ(0, motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_GESTURE_Y_OFFSET));

    // Move the two fingers down and to the left.
    int32_t movingDistance = 200;
    x1 -= movingDistance;
    y1 += movingDistance;
    x2 -= movingDistance;
    y2 += movingDistance;

    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, x1, y1);
    processMTSync(mapper);
    processId(mapper, SECOND_TRACKING_ID);
    processPosition(mapper, x2, y2);
    processMTSync(mapper);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&motionArgs));
    ASSERT_EQ(1U, motionArgs.getPointerCount());
    ASSERT_EQ(AMOTION_EVENT_ACTION_MOVE, motionArgs.action);
    ASSERT_EQ(MotionClassification::TWO_FINGER_SWIPE, motionArgs.classification);
    ASSERT_LT(motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_GESTURE_X_OFFSET), 0);
    ASSERT_GT(motionArgs.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_GESTURE_Y_OFFSET), 0);
}

TEST_F(MultiTouchPointerModeTest, WhenViewportActiveStatusChanged_PointerGestureIsReset) {
    preparePointerMode(/*xResolution=*/25, /*yResolution=*/25);
    mFakeEventHub->addKey(EVENTHUB_ID, BTN_TOOL_PEN, 0, AKEYCODE_UNKNOWN, 0);
    MultiTouchInputMapper& mapper = constructAndAddMapper<MultiTouchInputMapper>();
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyDeviceResetWasCalled());

    // Start a stylus gesture.
    processKey(mapper, BTN_TOOL_PEN, 1);
    processId(mapper, FIRST_TRACKING_ID);
    processPosition(mapper, 100, 200);
    processSync(mapper);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                  WithSource(AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_STYLUS),
                  WithToolType(ToolType::STYLUS))));
    // TODO(b/257078296): Pointer mode generates extra event.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                  WithSource(AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_STYLUS),
                  WithToolType(ToolType::STYLUS))));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());

    // Make the viewport inactive. This will put the device in disabled mode, and the ongoing stylus
    // gesture should be disabled.
    auto viewport = mFakePolicy->getDisplayViewportByType(ViewportType::INTERNAL);
    viewport->isActive = false;
    mFakePolicy->updateViewport(*viewport);
    configureDevice(InputReaderConfiguration::Change::DISPLAY_INFO);
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_CANCEL),
                  WithSource(AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_STYLUS),
                  WithToolType(ToolType::STYLUS))));
    // TODO(b/257078296): Pointer mode generates extra event.
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_CANCEL),
                  WithSource(AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_STYLUS),
                  WithToolType(ToolType::STYLUS))));
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasNotCalled());
}

// --- JoystickInputMapperTest ---

class JoystickInputMapperTest : public InputMapperTest {
protected:
    static const int32_t RAW_X_MIN;
    static const int32_t RAW_X_MAX;
    static const int32_t RAW_Y_MIN;
    static const int32_t RAW_Y_MAX;

    void SetUp() override {
        InputMapperTest::SetUp(InputDeviceClass::JOYSTICK | InputDeviceClass::EXTERNAL);
    }
    void prepareAxes() {
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_X, RAW_X_MIN, RAW_X_MAX, 0, 0);
        mFakeEventHub->addAbsoluteAxis(EVENTHUB_ID, ABS_Y, RAW_Y_MIN, RAW_Y_MAX, 0, 0);
    }

    void processAxis(JoystickInputMapper& mapper, int32_t axis, int32_t value) {
        process(mapper, ARBITRARY_TIME, READ_TIME, EV_ABS, axis, value);
    }

    void processSync(JoystickInputMapper& mapper) {
        process(mapper, ARBITRARY_TIME, READ_TIME, EV_SYN, SYN_REPORT, 0);
    }

    void prepareVirtualDisplay(ui::Rotation orientation) {
        setDisplayInfoAndReconfigure(VIRTUAL_DISPLAY_ID, VIRTUAL_DISPLAY_WIDTH,
                                     VIRTUAL_DISPLAY_HEIGHT, orientation, VIRTUAL_DISPLAY_UNIQUE_ID,
                                     NO_PORT, ViewportType::VIRTUAL);
    }
};

const int32_t JoystickInputMapperTest::RAW_X_MIN = -32767;
const int32_t JoystickInputMapperTest::RAW_X_MAX = 32767;
const int32_t JoystickInputMapperTest::RAW_Y_MIN = -32767;
const int32_t JoystickInputMapperTest::RAW_Y_MAX = 32767;

TEST_F(JoystickInputMapperTest, Configure_AssignsDisplayUniqueId) {
    prepareAxes();
    JoystickInputMapper& mapper = constructAndAddMapper<JoystickInputMapper>();

    mFakePolicy->addInputUniqueIdAssociation(DEVICE_LOCATION, VIRTUAL_DISPLAY_UNIQUE_ID);

    prepareVirtualDisplay(ui::ROTATION_0);

    // Send an axis event
    processAxis(mapper, ABS_X, 100);
    processSync(mapper);

    NotifyMotionArgs args;
    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(VIRTUAL_DISPLAY_ID, args.displayId);

    // Send another axis event
    processAxis(mapper, ABS_Y, 100);
    processSync(mapper);

    ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyMotionWasCalled(&args));
    ASSERT_EQ(VIRTUAL_DISPLAY_ID, args.displayId);
}

// --- PeripheralControllerTest ---

class PeripheralControllerTest : public testing::Test {
protected:
    static const char* DEVICE_NAME;
    static const char* DEVICE_LOCATION;
    static const int32_t DEVICE_ID;
    static const int32_t DEVICE_GENERATION;
    static const int32_t DEVICE_CONTROLLER_NUMBER;
    static const ftl::Flags<InputDeviceClass> DEVICE_CLASSES;
    static const int32_t EVENTHUB_ID;

    std::shared_ptr<FakeEventHub> mFakeEventHub;
    sp<FakeInputReaderPolicy> mFakePolicy;
    std::unique_ptr<TestInputListener> mFakeListener;
    std::unique_ptr<InstrumentedInputReader> mReader;
    std::shared_ptr<InputDevice> mDevice;

    virtual void SetUp(ftl::Flags<InputDeviceClass> classes) {
        mFakeEventHub = std::make_unique<FakeEventHub>();
        mFakePolicy = sp<FakeInputReaderPolicy>::make();
        mFakeListener = std::make_unique<TestInputListener>();
        mReader = std::make_unique<InstrumentedInputReader>(mFakeEventHub, mFakePolicy,
                                                            *mFakeListener);
        mDevice = newDevice(DEVICE_ID, DEVICE_NAME, DEVICE_LOCATION, EVENTHUB_ID, classes);
    }

    void SetUp() override { SetUp(DEVICE_CLASSES); }

    void TearDown() override {
        mFakeListener.reset();
        mFakePolicy.clear();
    }

    std::shared_ptr<InputDevice> newDevice(int32_t deviceId, const std::string& name,
                                           const std::string& location, int32_t eventHubId,
                                           ftl::Flags<InputDeviceClass> classes) {
        InputDeviceIdentifier identifier;
        identifier.name = name;
        identifier.location = location;
        std::shared_ptr<InputDevice> device =
                std::make_shared<InputDevice>(mReader->getContext(), deviceId, DEVICE_GENERATION,
                                              identifier);
        mReader->pushNextDevice(device);
        mFakeEventHub->addDevice(eventHubId, name, classes);
        mReader->loopOnce();
        return device;
    }

    template <class T, typename... Args>
    T& addControllerAndConfigure(Args... args) {
        T& controller = mDevice->addController<T>(EVENTHUB_ID, args...);

        return controller;
    }
};

const char* PeripheralControllerTest::DEVICE_NAME = "device";
const char* PeripheralControllerTest::DEVICE_LOCATION = "BLUETOOTH";
const int32_t PeripheralControllerTest::DEVICE_ID = END_RESERVED_ID + 1000;
const int32_t PeripheralControllerTest::DEVICE_GENERATION = 2;
const int32_t PeripheralControllerTest::DEVICE_CONTROLLER_NUMBER = 0;
const ftl::Flags<InputDeviceClass> PeripheralControllerTest::DEVICE_CLASSES =
        ftl::Flags<InputDeviceClass>(0); // not needed for current tests
const int32_t PeripheralControllerTest::EVENTHUB_ID = 1;

// --- BatteryControllerTest ---
class BatteryControllerTest : public PeripheralControllerTest {
protected:
    void SetUp() override {
        PeripheralControllerTest::SetUp(DEVICE_CLASSES | InputDeviceClass::BATTERY);
    }
};

TEST_F(BatteryControllerTest, GetBatteryCapacity) {
    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();

    ASSERT_TRUE(controller.getBatteryCapacity(FakeEventHub::DEFAULT_BATTERY));
    ASSERT_EQ(controller.getBatteryCapacity(FakeEventHub::DEFAULT_BATTERY).value_or(-1),
              FakeEventHub::BATTERY_CAPACITY);
}

TEST_F(BatteryControllerTest, GetBatteryStatus) {
    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();

    ASSERT_TRUE(controller.getBatteryStatus(FakeEventHub::DEFAULT_BATTERY));
    ASSERT_EQ(controller.getBatteryStatus(FakeEventHub::DEFAULT_BATTERY).value_or(-1),
              FakeEventHub::BATTERY_STATUS);
}

// --- LightControllerTest ---
class LightControllerTest : public PeripheralControllerTest {
protected:
    void SetUp() override {
        PeripheralControllerTest::SetUp(DEVICE_CLASSES | InputDeviceClass::LIGHT);
    }
};

TEST_F(LightControllerTest, MonoLight) {
    RawLightInfo infoMono = {.id = 1,
                             .name = "mono_light",
                             .maxBrightness = 255,
                             .flags = InputLightClass::BRIGHTNESS,
                             .path = ""};
    mFakeEventHub->addRawLightInfo(infoMono.id, std::move(infoMono));

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(InputDeviceLightType::INPUT, lights[0].type);
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::BRIGHTNESS));

    ASSERT_TRUE(controller.setLightColor(lights[0].id, LIGHT_BRIGHTNESS));
    ASSERT_EQ(controller.getLightColor(lights[0].id).value_or(-1), LIGHT_BRIGHTNESS);
}

TEST_F(LightControllerTest, MonoKeyboardBacklight) {
    RawLightInfo infoMono = {.id = 1,
                             .name = "mono_keyboard_backlight",
                             .maxBrightness = 255,
                             .flags = InputLightClass::BRIGHTNESS |
                                     InputLightClass::KEYBOARD_BACKLIGHT,
                             .path = ""};
    mFakeEventHub->addRawLightInfo(infoMono.id, std::move(infoMono));

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(InputDeviceLightType::KEYBOARD_BACKLIGHT, lights[0].type);
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::BRIGHTNESS));

    ASSERT_TRUE(controller.setLightColor(lights[0].id, LIGHT_BRIGHTNESS));
    ASSERT_EQ(controller.getLightColor(lights[0].id).value_or(-1), LIGHT_BRIGHTNESS);
}

TEST_F(LightControllerTest, Ignore_MonoLight_WithPreferredBacklightLevels) {
    RawLightInfo infoMono = {.id = 1,
                             .name = "mono_light",
                             .maxBrightness = 255,
                             .flags = InputLightClass::BRIGHTNESS,
                             .path = ""};
    mFakeEventHub->addRawLightInfo(infoMono.id, std::move(infoMono));
    mFakeEventHub->addConfigurationProperty(EVENTHUB_ID, "keyboard.backlight.brightnessLevels",
                                            "0,100,200");

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    std::list<NotifyArgs> unused =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});

    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(0U, lights[0].preferredBrightnessLevels.size());
}

TEST_F(LightControllerTest, KeyboardBacklight_WithNoPreferredBacklightLevels) {
    RawLightInfo infoMono = {.id = 1,
                             .name = "mono_keyboard_backlight",
                             .maxBrightness = 255,
                             .flags = InputLightClass::BRIGHTNESS |
                                     InputLightClass::KEYBOARD_BACKLIGHT,
                             .path = ""};
    mFakeEventHub->addRawLightInfo(infoMono.id, std::move(infoMono));

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    std::list<NotifyArgs> unused =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});

    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(0U, lights[0].preferredBrightnessLevels.size());
}

TEST_F(LightControllerTest, KeyboardBacklight_WithPreferredBacklightLevels) {
    RawLightInfo infoMono = {.id = 1,
                             .name = "mono_keyboard_backlight",
                             .maxBrightness = 255,
                             .flags = InputLightClass::BRIGHTNESS |
                                     InputLightClass::KEYBOARD_BACKLIGHT,
                             .path = ""};
    mFakeEventHub->addRawLightInfo(infoMono.id, std::move(infoMono));
    mFakeEventHub->addConfigurationProperty(EVENTHUB_ID, "keyboard.backlight.brightnessLevels",
                                            "0,100,200");

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    std::list<NotifyArgs> unused =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});

    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(3U, lights[0].preferredBrightnessLevels.size());
    std::set<BrightnessLevel>::iterator it = lights[0].preferredBrightnessLevels.begin();
    ASSERT_EQ(BrightnessLevel(0), *it);
    std::advance(it, 1);
    ASSERT_EQ(BrightnessLevel(100), *it);
    std::advance(it, 1);
    ASSERT_EQ(BrightnessLevel(200), *it);
}

TEST_F(LightControllerTest, KeyboardBacklight_WithWrongPreferredBacklightLevels) {
    RawLightInfo infoMono = {.id = 1,
                             .name = "mono_keyboard_backlight",
                             .maxBrightness = 255,
                             .flags = InputLightClass::BRIGHTNESS |
                                     InputLightClass::KEYBOARD_BACKLIGHT,
                             .path = ""};
    mFakeEventHub->addRawLightInfo(infoMono.id, std::move(infoMono));
    mFakeEventHub->addConfigurationProperty(EVENTHUB_ID, "keyboard.backlight.brightnessLevels",
                                            "0,100,200,300,400,500");

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    std::list<NotifyArgs> unused =
            mDevice->configure(ARBITRARY_TIME, mFakePolicy->getReaderConfiguration(),
                               /*changes=*/{});

    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(0U, lights[0].preferredBrightnessLevels.size());
}

TEST_F(LightControllerTest, RGBLight) {
    RawLightInfo infoRed = {.id = 1,
                            .name = "red",
                            .maxBrightness = 255,
                            .flags = InputLightClass::BRIGHTNESS | InputLightClass::RED,
                            .path = ""};
    RawLightInfo infoGreen = {.id = 2,
                              .name = "green",
                              .maxBrightness = 255,
                              .flags = InputLightClass::BRIGHTNESS | InputLightClass::GREEN,
                              .path = ""};
    RawLightInfo infoBlue = {.id = 3,
                             .name = "blue",
                             .maxBrightness = 255,
                             .flags = InputLightClass::BRIGHTNESS | InputLightClass::BLUE,
                             .path = ""};
    mFakeEventHub->addRawLightInfo(infoRed.id, std::move(infoRed));
    mFakeEventHub->addRawLightInfo(infoGreen.id, std::move(infoGreen));
    mFakeEventHub->addRawLightInfo(infoBlue.id, std::move(infoBlue));

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(InputDeviceLightType::INPUT, lights[0].type);
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::BRIGHTNESS));
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::RGB));

    ASSERT_TRUE(controller.setLightColor(lights[0].id, LIGHT_COLOR));
    ASSERT_EQ(controller.getLightColor(lights[0].id).value_or(-1), LIGHT_COLOR);
}

TEST_F(LightControllerTest, CorrectRGBKeyboardBacklight) {
    RawLightInfo infoRed = {.id = 1,
                            .name = "red_keyboard_backlight",
                            .maxBrightness = 255,
                            .flags = InputLightClass::BRIGHTNESS | InputLightClass::RED |
                                    InputLightClass::KEYBOARD_BACKLIGHT,
                            .path = ""};
    RawLightInfo infoGreen = {.id = 2,
                              .name = "green_keyboard_backlight",
                              .maxBrightness = 255,
                              .flags = InputLightClass::BRIGHTNESS | InputLightClass::GREEN |
                                      InputLightClass::KEYBOARD_BACKLIGHT,
                              .path = ""};
    RawLightInfo infoBlue = {.id = 3,
                             .name = "blue_keyboard_backlight",
                             .maxBrightness = 255,
                             .flags = InputLightClass::BRIGHTNESS | InputLightClass::BLUE |
                                     InputLightClass::KEYBOARD_BACKLIGHT,
                             .path = ""};
    mFakeEventHub->addRawLightInfo(infoRed.id, std::move(infoRed));
    mFakeEventHub->addRawLightInfo(infoGreen.id, std::move(infoGreen));
    mFakeEventHub->addRawLightInfo(infoBlue.id, std::move(infoBlue));

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(InputDeviceLightType::KEYBOARD_BACKLIGHT, lights[0].type);
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::BRIGHTNESS));
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::RGB));

    ASSERT_TRUE(controller.setLightColor(lights[0].id, LIGHT_COLOR));
    ASSERT_EQ(controller.getLightColor(lights[0].id).value_or(-1), LIGHT_COLOR);
}

TEST_F(LightControllerTest, IncorrectRGBKeyboardBacklight) {
    RawLightInfo infoRed = {.id = 1,
                            .name = "red",
                            .maxBrightness = 255,
                            .flags = InputLightClass::BRIGHTNESS | InputLightClass::RED,
                            .path = ""};
    RawLightInfo infoGreen = {.id = 2,
                              .name = "green",
                              .maxBrightness = 255,
                              .flags = InputLightClass::BRIGHTNESS | InputLightClass::GREEN,
                              .path = ""};
    RawLightInfo infoBlue = {.id = 3,
                             .name = "blue",
                             .maxBrightness = 255,
                             .flags = InputLightClass::BRIGHTNESS | InputLightClass::BLUE,
                             .path = ""};
    RawLightInfo infoGlobal = {.id = 3,
                               .name = "global_keyboard_backlight",
                               .maxBrightness = 255,
                               .flags = InputLightClass::BRIGHTNESS | InputLightClass::GLOBAL |
                                       InputLightClass::KEYBOARD_BACKLIGHT,
                               .path = ""};
    mFakeEventHub->addRawLightInfo(infoRed.id, std::move(infoRed));
    mFakeEventHub->addRawLightInfo(infoGreen.id, std::move(infoGreen));
    mFakeEventHub->addRawLightInfo(infoBlue.id, std::move(infoBlue));
    mFakeEventHub->addRawLightInfo(infoBlue.id, std::move(infoGlobal));

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(InputDeviceLightType::INPUT, lights[0].type);
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::BRIGHTNESS));
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::RGB));

    ASSERT_TRUE(controller.setLightColor(lights[0].id, LIGHT_COLOR));
    ASSERT_EQ(controller.getLightColor(lights[0].id).value_or(-1), LIGHT_COLOR);
}

TEST_F(LightControllerTest, MultiColorRGBLight) {
    RawLightInfo infoColor = {.id = 1,
                              .name = "multi_color",
                              .maxBrightness = 255,
                              .flags = InputLightClass::BRIGHTNESS |
                                      InputLightClass::MULTI_INTENSITY |
                                      InputLightClass::MULTI_INDEX,
                              .path = ""};

    mFakeEventHub->addRawLightInfo(infoColor.id, std::move(infoColor));

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(InputDeviceLightType::INPUT, lights[0].type);
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::BRIGHTNESS));
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::RGB));

    ASSERT_TRUE(controller.setLightColor(lights[0].id, LIGHT_COLOR));
    ASSERT_EQ(controller.getLightColor(lights[0].id).value_or(-1), LIGHT_COLOR);
}

TEST_F(LightControllerTest, MultiColorRGBKeyboardBacklight) {
    RawLightInfo infoColor = {.id = 1,
                              .name = "multi_color_keyboard_backlight",
                              .maxBrightness = 255,
                              .flags = InputLightClass::BRIGHTNESS |
                                      InputLightClass::MULTI_INTENSITY |
                                      InputLightClass::MULTI_INDEX |
                                      InputLightClass::KEYBOARD_BACKLIGHT,
                              .path = ""};

    mFakeEventHub->addRawLightInfo(infoColor.id, std::move(infoColor));

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(InputDeviceLightType::KEYBOARD_BACKLIGHT, lights[0].type);
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::BRIGHTNESS));
    ASSERT_TRUE(lights[0].capabilityFlags.test(InputDeviceLightCapability::RGB));

    ASSERT_TRUE(controller.setLightColor(lights[0].id, LIGHT_COLOR));
    ASSERT_EQ(controller.getLightColor(lights[0].id).value_or(-1), LIGHT_COLOR);
}

TEST_F(LightControllerTest, PlayerIdLight) {
    RawLightInfo info1 = {.id = 1,
                          .name = "player1",
                          .maxBrightness = 255,
                          .flags = InputLightClass::BRIGHTNESS,
                          .path = ""};
    RawLightInfo info2 = {.id = 2,
                          .name = "player2",
                          .maxBrightness = 255,
                          .flags = InputLightClass::BRIGHTNESS,
                          .path = ""};
    RawLightInfo info3 = {.id = 3,
                          .name = "player3",
                          .maxBrightness = 255,
                          .flags = InputLightClass::BRIGHTNESS,
                          .path = ""};
    RawLightInfo info4 = {.id = 4,
                          .name = "player4",
                          .maxBrightness = 255,
                          .flags = InputLightClass::BRIGHTNESS,
                          .path = ""};
    mFakeEventHub->addRawLightInfo(info1.id, std::move(info1));
    mFakeEventHub->addRawLightInfo(info2.id, std::move(info2));
    mFakeEventHub->addRawLightInfo(info3.id, std::move(info3));
    mFakeEventHub->addRawLightInfo(info4.id, std::move(info4));

    PeripheralController& controller = addControllerAndConfigure<PeripheralController>();
    InputDeviceInfo info;
    controller.populateDeviceInfo(&info);
    std::vector<InputDeviceLightInfo> lights = info.getLights();
    ASSERT_EQ(1U, lights.size());
    ASSERT_EQ(InputDeviceLightType::PLAYER_ID, lights[0].type);
    ASSERT_FALSE(lights[0].capabilityFlags.test(InputDeviceLightCapability::BRIGHTNESS));
    ASSERT_FALSE(lights[0].capabilityFlags.test(InputDeviceLightCapability::RGB));

    ASSERT_FALSE(controller.setLightColor(lights[0].id, LIGHT_COLOR));
    ASSERT_TRUE(controller.setLightPlayerId(lights[0].id, LIGHT_PLAYER_ID));
    ASSERT_EQ(controller.getLightPlayerId(lights[0].id).value_or(-1), LIGHT_PLAYER_ID);
}

} // namespace android
