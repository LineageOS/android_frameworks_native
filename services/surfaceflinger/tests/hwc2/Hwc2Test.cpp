/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <array>
#include <unordered_set>
#include <gtest/gtest.h>
#include <dlfcn.h>
#include <hardware/hardware.h>

#define HWC2_INCLUDE_STRINGIFICATION
#define HWC2_USE_CPP11
#include <hardware/hwcomposer2.h>
#undef HWC2_INCLUDE_STRINGIFICATION
#undef HWC2_USE_CPP11

void hwc2TestHotplugCallback(hwc2_callback_data_t callbackData,
        hwc2_display_t display, int32_t connected);

class Hwc2Test : public testing::Test {
public:

    virtual void SetUp()
    {
        hw_module_t const* hwc2Module;

        int err = hw_get_module(HWC_HARDWARE_MODULE_ID, &hwc2Module);
        ASSERT_GE(err, 0) << "failed to get hwc hardware module: "
                << strerror(-err);

        /* The following method will fail if you have not run
         * "adb shell stop" */
        err = hwc2_open(hwc2Module, &mHwc2Device);
        ASSERT_GE(err, 0) << "failed to open hwc hardware module: "
                << strerror(-err);

        populateDisplays();
    }

    virtual void TearDown()
    {
        if (mHwc2Device)
            hwc2_close(mHwc2Device);
    }

    void registerCallback(hwc2_callback_descriptor_t descriptor,
            hwc2_callback_data_t callbackData, hwc2_function_pointer_t pointer,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_REGISTER_CALLBACK>(
                getFunction(HWC2_FUNCTION_REGISTER_CALLBACK));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, descriptor,
                callbackData, pointer));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to register callback";
        }
    }

    void getDisplayType(hwc2_display_t display, hwc2_display_type_t* outType,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_DISPLAY_TYPE>(
                getFunction(HWC2_FUNCTION_GET_DISPLAY_TYPE));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                    reinterpret_cast<int32_t*>(outType)));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get display type";
        }
    }

    /* If the populateDisplays function is still receiving displays and the
     * display is connected, the display handle is stored in mDisplays. */
    void hotplugCallback(hwc2_display_t display, int32_t connected)
    {
        std::lock_guard<std::mutex> lock(mHotplugMutex);

        if (mHotplugStatus != Hwc2TestHotplugStatus::Receiving)
            return;

        if (connected == HWC2_CONNECTION_CONNECTED)
            mDisplays.insert(display);

        mHotplugCv.notify_all();
    }

protected:
    hwc2_function_pointer_t getFunction(hwc2_function_descriptor_t descriptor)
    {
        return mHwc2Device->getFunction(mHwc2Device, descriptor);
    }

    void getCapabilities(std::vector<hwc2_capability_t>* outCapabilities)
    {
        uint32_t num = 0;

        mHwc2Device->getCapabilities(mHwc2Device, &num, nullptr);

        outCapabilities->resize(num);

        mHwc2Device->getCapabilities(mHwc2Device, &num,
                reinterpret_cast<int32_t*>(outCapabilities->data()));
    }

    /* Registers a hotplug callback and waits for hotplug callbacks. This
     * function will have no effect if called more than once. */
    void populateDisplays()
    {
        /* Sets the hotplug status to receiving */
        {
            std::lock_guard<std::mutex> lock(mHotplugMutex);

            if (mHotplugStatus != Hwc2TestHotplugStatus::Init)
                return;
            mHotplugStatus = Hwc2TestHotplugStatus::Receiving;
        }

        /* Registers the callback. This function call cannot be locked because
         * a callback could happen on the same thread */
        ASSERT_NO_FATAL_FAILURE(registerCallback(HWC2_CALLBACK_HOTPLUG, this,
                reinterpret_cast<hwc2_function_pointer_t>(
                hwc2TestHotplugCallback)));

        /* Waits for hotplug events. If a hotplug event has not come within 1
         * second, stop waiting. */
        std::unique_lock<std::mutex> lock(mHotplugMutex);

        while (mHotplugCv.wait_for(lock, std::chrono::seconds(1)) !=
                std::cv_status::timeout) { }

        /* Sets the hotplug status to done. Future calls will have no effect */
        mHotplugStatus = Hwc2TestHotplugStatus::Done;
    }

    void getBadDisplay(hwc2_display_t* outDisplay)
    {
        for (hwc2_display_t display = 0; display < UINT64_MAX; display++) {
            if (mDisplays.count(display) == 0) {
                *outDisplay = display;
                return;
            }
        }
        ASSERT_TRUE(false) << "Unable to find bad display. UINT64_MAX displays"
                " are registered. This should never happen.";
    }

    hwc2_device_t* mHwc2Device = nullptr;

    enum class Hwc2TestHotplugStatus {
        Init = 1,
        Receiving,
        Done,
    };

    std::mutex mHotplugMutex;
    std::condition_variable mHotplugCv;
    Hwc2TestHotplugStatus mHotplugStatus = Hwc2TestHotplugStatus::Init;
    std::unordered_set<hwc2_display_t> mDisplays;
};

void hwc2TestHotplugCallback(hwc2_callback_data_t callbackData,
        hwc2_display_t display, int32_t connection)
{
    if (callbackData)
        static_cast<Hwc2Test*>(callbackData)->hotplugCallback(display,
                connection);
}


static const std::array<hwc2_function_descriptor_t, 42> requiredFunctions = {{
    HWC2_FUNCTION_ACCEPT_DISPLAY_CHANGES,
    HWC2_FUNCTION_CREATE_LAYER,
    HWC2_FUNCTION_CREATE_VIRTUAL_DISPLAY,
    HWC2_FUNCTION_DESTROY_LAYER,
    HWC2_FUNCTION_DESTROY_VIRTUAL_DISPLAY,
    HWC2_FUNCTION_DUMP,
    HWC2_FUNCTION_GET_ACTIVE_CONFIG,
    HWC2_FUNCTION_GET_CHANGED_COMPOSITION_TYPES,
    HWC2_FUNCTION_GET_CLIENT_TARGET_SUPPORT,
    HWC2_FUNCTION_GET_COLOR_MODES,
    HWC2_FUNCTION_GET_DISPLAY_ATTRIBUTE,
    HWC2_FUNCTION_GET_DISPLAY_CONFIGS,
    HWC2_FUNCTION_GET_DISPLAY_NAME,
    HWC2_FUNCTION_GET_DISPLAY_REQUESTS,
    HWC2_FUNCTION_GET_DISPLAY_TYPE,
    HWC2_FUNCTION_GET_DOZE_SUPPORT,
    HWC2_FUNCTION_GET_HDR_CAPABILITIES,
    HWC2_FUNCTION_GET_MAX_VIRTUAL_DISPLAY_COUNT,
    HWC2_FUNCTION_GET_RELEASE_FENCES,
    HWC2_FUNCTION_PRESENT_DISPLAY,
    HWC2_FUNCTION_REGISTER_CALLBACK,
    HWC2_FUNCTION_SET_ACTIVE_CONFIG,
    HWC2_FUNCTION_SET_CLIENT_TARGET,
    HWC2_FUNCTION_SET_COLOR_MODE,
    HWC2_FUNCTION_SET_COLOR_TRANSFORM,
    HWC2_FUNCTION_SET_CURSOR_POSITION,
    HWC2_FUNCTION_SET_LAYER_BLEND_MODE,
    HWC2_FUNCTION_SET_LAYER_BUFFER,
    HWC2_FUNCTION_SET_LAYER_COLOR,
    HWC2_FUNCTION_SET_LAYER_COMPOSITION_TYPE,
    HWC2_FUNCTION_SET_LAYER_DATASPACE,
    HWC2_FUNCTION_SET_LAYER_DISPLAY_FRAME,
    HWC2_FUNCTION_SET_LAYER_PLANE_ALPHA,
    HWC2_FUNCTION_SET_LAYER_SOURCE_CROP,
    HWC2_FUNCTION_SET_LAYER_SURFACE_DAMAGE,
    HWC2_FUNCTION_SET_LAYER_TRANSFORM,
    HWC2_FUNCTION_SET_LAYER_VISIBLE_REGION,
    HWC2_FUNCTION_SET_LAYER_Z_ORDER,
    HWC2_FUNCTION_SET_OUTPUT_BUFFER,
    HWC2_FUNCTION_SET_POWER_MODE,
    HWC2_FUNCTION_SET_VSYNC_ENABLED,
    HWC2_FUNCTION_VALIDATE_DISPLAY,
}};

/* TESTCASE: Tests that the HWC2 supports all required functions. */
TEST_F(Hwc2Test, GET_FUNCTION)
{
    for (hwc2_function_descriptor_t descriptor : requiredFunctions) {
        hwc2_function_pointer_t pfn = getFunction(descriptor);
        EXPECT_TRUE(pfn) << "failed to get function "
                << getFunctionDescriptorName(descriptor);
    }
}

/* TESTCASE: Tests that the HWC2 fails to retrieve and invalid function. */
TEST_F(Hwc2Test, GET_FUNCTION_invalid_function)
{
    hwc2_function_pointer_t pfn = getFunction(HWC2_FUNCTION_INVALID);
    EXPECT_FALSE(pfn) << "failed to get invalid function";
}

/* TESTCASE: Tests that the HWC2 does not return an invalid capability. */
TEST_F(Hwc2Test, GET_CAPABILITIES)
{
    std::vector<hwc2_capability_t> capabilities;

    getCapabilities(&capabilities);

    EXPECT_EQ(std::count(capabilities.begin(), capabilities.end(),
            HWC2_CAPABILITY_INVALID), 0);
}

static const std::array<hwc2_callback_descriptor_t, 3> callbackDescriptors = {{
    HWC2_CALLBACK_HOTPLUG,
    HWC2_CALLBACK_REFRESH,
    HWC2_CALLBACK_VSYNC,
}};

/* TESTCASE: Tests that the HWC2 can successfully register all required
 * callback functions. */
TEST_F(Hwc2Test, REGISTER_CALLBACK)
{
    hwc2_callback_data_t data = reinterpret_cast<hwc2_callback_data_t>(
            const_cast<char*>("data"));

    for (auto descriptor : callbackDescriptors) {
        ASSERT_NO_FATAL_FAILURE(registerCallback(descriptor, data,
                []() { return; }));
    }
}

/* TESTCASE: Test that the HWC2 fails to register invalid callbacks. */
TEST_F(Hwc2Test, REGISTER_CALLBACK_bad_parameter)
{
    hwc2_callback_data_t data = reinterpret_cast<hwc2_callback_data_t>(
            const_cast<char*>("data"));
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(registerCallback(HWC2_CALLBACK_INVALID, data,
            []() { return; }, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_PARAMETER) << "returned wrong error code";
}

/* TESTCASE: Tests that the HWC2 can register a callback with null data. */
TEST_F(Hwc2Test, REGISTER_CALLBACK_null_data)
{
    hwc2_callback_data_t data = nullptr;

    for (auto descriptor : callbackDescriptors) {
        ASSERT_NO_FATAL_FAILURE(registerCallback(descriptor, data,
                []() { return; }));
    }
}

/* TESTCASE: Tests that the HWC2 returns the correct display type for each
 * physical display. */
TEST_F(Hwc2Test, GET_DISPLAY_TYPE)
{
    for (auto display : mDisplays) {
        hwc2_display_type_t type;

        ASSERT_NO_FATAL_FAILURE(getDisplayType(display, &type));
        EXPECT_EQ(type, HWC2_DISPLAY_TYPE_PHYSICAL) << "failed to return"
                " correct display type";
    }
}

/* TESTCASE: Tests that the HWC2 returns an error when the display type of a bad
 * display is requested. */
TEST_F(Hwc2Test, GET_DISPLAY_TYPE_bad_display)
{
    hwc2_display_t display;
    hwc2_display_type_t type;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(getDisplayType(display, &type, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}
