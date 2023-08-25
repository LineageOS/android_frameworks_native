/*
 * Copyright 2023 The Android Open Source Project
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

#include <gestures/PropertyProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "TestConstants.h"
#include "include/gestures.h"

namespace android {

using testing::ElementsAre;

class PropertyProviderTest : public testing::Test {
protected:
    PropertyProvider mProvider;
};

TEST_F(PropertyProviderTest, Int_Create) {
    const size_t COUNT = 4;
    int intData[COUNT] = {0, 0, 0, 0};
    int initialValues[COUNT] = {1, 2, 3, 4};
    gesturePropProvider.create_int_fn(&mProvider, "Some Integers", intData, COUNT, initialValues);

    ASSERT_TRUE(mProvider.hasProperty("Some Integers"));
    GesturesProp& prop = mProvider.getProperty("Some Integers");
    EXPECT_EQ(prop.getName(), "Some Integers");
    EXPECT_EQ(prop.getCount(), COUNT);
    EXPECT_THAT(intData, ElementsAre(1, 2, 3, 4));
}

TEST_F(PropertyProviderTest, Int_Get) {
    const size_t COUNT = 4;
    int intData[COUNT] = {0, 0, 0, 0};
    int initialValues[COUNT] = {9, 9, 9, 9};
    GesturesProp* propPtr = gesturePropProvider.create_int_fn(&mProvider, "Some Integers", intData,
                                                              COUNT, initialValues);

    // Get handlers are supposed to be called before the property's data is accessed, so they can
    // update it if necessary. This getter updates the values, so that the ordering can be checked.
    GesturesPropGetHandler getter{[](void* handlerData) -> GesturesPropBool {
        int* array = static_cast<int*>(handlerData);
        array[0] = 1;
        array[1] = 2;
        array[2] = 3;
        array[3] = 4;
        return true;
    }};
    gesturePropProvider.register_handlers_fn(&mProvider, propPtr, /* handler_data= */ intData,
                                             getter, nullptr);

    ASSERT_TRUE(mProvider.hasProperty("Some Integers"));
    GesturesProp& prop = mProvider.getProperty("Some Integers");
    EXPECT_THAT(prop.getIntValues(), ElementsAre(1, 2, 3, 4));
}

TEST_F(PropertyProviderTest, Int_Set) {
    const size_t COUNT = 4;
    int intData[COUNT] = {0, 0, 0, 0};
    int initialValues[COUNT] = {9, 9, 9, 9};
    GesturesProp* propPtr = gesturePropProvider.create_int_fn(&mProvider, "Some Integers", intData,
                                                              COUNT, initialValues);

    struct SetterData {
        bool setterCalled;
        int* propertyData;
    };
    SetterData setterData = {false, intData};
    GesturesPropSetHandler setter{[](void* handlerData) {
        SetterData* data = static_cast<SetterData*>(handlerData);
        // Set handlers should be called after the property's data has changed, so check the data.
        EXPECT_EQ(data->propertyData[0], 1);
        EXPECT_EQ(data->propertyData[1], 2);
        EXPECT_EQ(data->propertyData[2], 3);
        EXPECT_EQ(data->propertyData[3], 4);
        data->setterCalled = true;
    }};
    gesturePropProvider.register_handlers_fn(&mProvider, propPtr, /* handler_data= */ &setterData,
                                             nullptr, setter);

    ASSERT_TRUE(mProvider.hasProperty("Some Integers"));
    GesturesProp& prop = mProvider.getProperty("Some Integers");
    prop.setIntValues({1, 2, 3, 4});
    EXPECT_THAT(intData, ElementsAre(1, 2, 3, 4));
    EXPECT_TRUE(setterData.setterCalled);
    EXPECT_THAT(prop.getIntValues(), ElementsAre(1, 2, 3, 4));
}

TEST_F(PropertyProviderTest, Bool_Create) {
    const size_t COUNT = 3;
    GesturesPropBool boolData[COUNT] = {false, false, false};
    GesturesPropBool initialValues[COUNT] = {true, false, false};
    gesturePropProvider.create_bool_fn(&mProvider, "Some Booleans", boolData, COUNT, initialValues);

    ASSERT_TRUE(mProvider.hasProperty("Some Booleans"));
    GesturesProp& prop = mProvider.getProperty("Some Booleans");
    EXPECT_EQ(prop.getName(), "Some Booleans");
    EXPECT_EQ(prop.getCount(), COUNT);
    EXPECT_THAT(boolData, ElementsAre(true, false, false));
}

TEST_F(PropertyProviderTest, Bool_Get) {
    const size_t COUNT = 3;
    GesturesPropBool boolData[COUNT] = {false, false, false};
    GesturesPropBool initialValues[COUNT] = {true, false, false};
    GesturesProp* propPtr = gesturePropProvider.create_bool_fn(&mProvider, "Some Booleans",
                                                               boolData, COUNT, initialValues);

    // Get handlers are supposed to be called before the property's data is accessed, so they can
    // update it if necessary. This getter updates the values, so that the ordering can be checked.
    GesturesPropGetHandler getter{[](void* handlerData) -> GesturesPropBool {
        GesturesPropBool* array = static_cast<GesturesPropBool*>(handlerData);
        array[0] = false;
        array[1] = true;
        array[2] = true;
        return true;
    }};
    gesturePropProvider.register_handlers_fn(&mProvider, propPtr, /* handler_data= */ boolData,
                                             getter, nullptr);

    ASSERT_TRUE(mProvider.hasProperty("Some Booleans"));
    GesturesProp& prop = mProvider.getProperty("Some Booleans");
    EXPECT_THAT(prop.getBoolValues(), ElementsAre(false, true, true));
}

TEST_F(PropertyProviderTest, Bool_Set) {
    const size_t COUNT = 3;
    GesturesPropBool boolData[COUNT] = {false, false, false};
    GesturesPropBool initialValues[COUNT] = {true, false, false};
    GesturesProp* propPtr = gesturePropProvider.create_bool_fn(&mProvider, "Some Booleans",
                                                               boolData, COUNT, initialValues);

    struct SetterData {
        bool setterCalled;
        GesturesPropBool* propertyData;
    };
    SetterData setterData = {false, boolData};
    GesturesPropSetHandler setter{[](void* handlerData) {
        SetterData* data = static_cast<SetterData*>(handlerData);
        // Set handlers should be called after the property's data has changed, so check the data.
        EXPECT_EQ(data->propertyData[0], false);
        EXPECT_EQ(data->propertyData[1], true);
        EXPECT_EQ(data->propertyData[2], true);
        data->setterCalled = true;
    }};
    gesturePropProvider.register_handlers_fn(&mProvider, propPtr, /* handler_data= */ &setterData,
                                             nullptr, setter);

    ASSERT_TRUE(mProvider.hasProperty("Some Booleans"));
    GesturesProp& prop = mProvider.getProperty("Some Booleans");
    prop.setBoolValues({false, true, true});
    EXPECT_THAT(boolData, ElementsAre(false, true, true));
    EXPECT_TRUE(setterData.setterCalled);
    EXPECT_THAT(prop.getBoolValues(), ElementsAre(false, true, true));
}

TEST_F(PropertyProviderTest, Real_Create) {
    const size_t COUNT = 3;
    double realData[COUNT] = {0.0, 0.0, 0.0};
    double initialValues[COUNT] = {3.14, 0.7, -5.0};
    gesturePropProvider.create_real_fn(&mProvider, "Some Reals", realData, COUNT, initialValues);

    ASSERT_TRUE(mProvider.hasProperty("Some Reals"));
    GesturesProp& prop = mProvider.getProperty("Some Reals");
    EXPECT_EQ(prop.getName(), "Some Reals");
    EXPECT_EQ(prop.getCount(), COUNT);
    EXPECT_THAT(realData, ElementsAre(3.14, 0.7, -5.0));
}

TEST_F(PropertyProviderTest, Real_Get) {
    const size_t COUNT = 3;
    double realData[COUNT] = {0.0, 0.0, 0.0};
    double initialValues[COUNT] = {-1.0, -1.0, -1.0};
    GesturesProp* propPtr = gesturePropProvider.create_real_fn(&mProvider, "Some Reals", realData,
                                                               COUNT, initialValues);

    // Get handlers are supposed to be called before the property's data is accessed, so they can
    // update it if necessary. This getter updates the values, so that the ordering can be checked.
    GesturesPropGetHandler getter{[](void* handlerData) -> GesturesPropBool {
        double* array = static_cast<double*>(handlerData);
        array[0] = 3.14;
        array[1] = 0.7;
        array[2] = -5.0;
        return true;
    }};
    gesturePropProvider.register_handlers_fn(&mProvider, propPtr, /* handler_data= */ realData,
                                             getter, nullptr);

    ASSERT_TRUE(mProvider.hasProperty("Some Reals"));
    GesturesProp& prop = mProvider.getProperty("Some Reals");
    EXPECT_THAT(prop.getRealValues(), ElementsAre(3.14, 0.7, -5.0));
}

TEST_F(PropertyProviderTest, Real_Set) {
    const size_t COUNT = 3;
    double realData[COUNT] = {0.0, 0.0, 0.0};
    double initialValues[COUNT] = {-1.0, -1.0, -1.0};
    GesturesProp* propPtr = gesturePropProvider.create_real_fn(&mProvider, "Some Reals", realData,
                                                               COUNT, initialValues);

    struct SetterData {
        bool setterCalled;
        double* propertyData;
    };
    SetterData setterData = {false, realData};
    GesturesPropSetHandler setter{[](void* handlerData) {
        SetterData* data = static_cast<SetterData*>(handlerData);
        // Set handlers should be called after the property's data has changed, so check the data.
        EXPECT_EQ(data->propertyData[0], 3.14);
        EXPECT_EQ(data->propertyData[1], 0.7);
        EXPECT_EQ(data->propertyData[2], -5.0);
        data->setterCalled = true;
    }};
    gesturePropProvider.register_handlers_fn(&mProvider, propPtr, /* handler_data= */ &setterData,
                                             nullptr, setter);

    ASSERT_TRUE(mProvider.hasProperty("Some Reals"));
    GesturesProp& prop = mProvider.getProperty("Some Reals");
    prop.setRealValues({3.14, 0.7, -5.0});
    EXPECT_THAT(realData, ElementsAre(3.14, 0.7, -5.0));
    EXPECT_TRUE(setterData.setterCalled);
    EXPECT_THAT(prop.getRealValues(), ElementsAre(3.14, 0.7, -5.0));
}

TEST_F(PropertyProviderTest, String_Create) {
    const char* str = nullptr;
    std::string initialValue = "Foo";
    gesturePropProvider.create_string_fn(&mProvider, "A String", &str, initialValue.c_str());

    ASSERT_TRUE(mProvider.hasProperty("A String"));
    GesturesProp& prop = mProvider.getProperty("A String");
    EXPECT_EQ(prop.getName(), "A String");
    EXPECT_EQ(prop.getCount(), 1u);
    EXPECT_STREQ(str, "Foo");
}

TEST_F(PropertyProviderTest, String_Get) {
    const char* str = nullptr;
    std::string initialValue = "Foo";
    GesturesProp* propPtr = gesturePropProvider.create_string_fn(&mProvider, "A String", &str,
                                                                 initialValue.c_str());

    // Get handlers are supposed to be called before the property's data is accessed, so they can
    // update it if necessary. This getter updates the values, so that the ordering can be checked.
    struct GetterData {
        const char** strPtr;
        std::string newValue; // Have to store the new value outside getter so it stays allocated.
    };
    GetterData getterData = {&str, "Bar"};
    GesturesPropGetHandler getter{[](void* handlerData) -> GesturesPropBool {
        GetterData* data = static_cast<GetterData*>(handlerData);
        *data->strPtr = data->newValue.c_str();
        return true;
    }};
    gesturePropProvider.register_handlers_fn(&mProvider, propPtr, /* handler_data= */ &getterData,
                                             getter, nullptr);

    ASSERT_TRUE(mProvider.hasProperty("A String"));
    GesturesProp& prop = mProvider.getProperty("A String");
    EXPECT_EQ(prop.getStringValue(), "Bar");
}

TEST_F(PropertyProviderTest, Free) {
    int intData = 0;
    int initialValue = 42;
    GesturesProp* propPtr =
            gesturePropProvider.create_int_fn(&mProvider, "Foo", &intData, 1, &initialValue);
    gesturePropProvider.free_fn(&mProvider, propPtr);

    EXPECT_FALSE(mProvider.hasProperty("Foo"));
}

class PropertyProviderIdcLoadingTest : public testing::Test {
protected:
    void SetUp() override {
        int initialInt = 0;
        GesturesPropBool initialBool = false;
        double initialReal = 0.0;
        gesturePropProvider.create_int_fn(&mProvider, "An Integer", &mIntData, 1, &initialInt);
        gesturePropProvider.create_bool_fn(&mProvider, "A Boolean", &mBoolData, 1, &initialBool);
        gesturePropProvider.create_real_fn(&mProvider, "A Real", &mRealData, 1, &initialReal);
    }

    PropertyProvider mProvider;

    int mIntData;
    GesturesPropBool mBoolData;
    double mRealData;
};

TEST_F(PropertyProviderIdcLoadingTest, AllCorrect) {
    PropertyMap idcProps;
    idcProps.addProperty("gestureProp.An_Integer", "42");
    idcProps.addProperty("gestureProp.A_Boolean", "1");
    idcProps.addProperty("gestureProp.A_Real", "3.14159");

    mProvider.loadPropertiesFromIdcFile(idcProps);
    EXPECT_THAT(mProvider.getProperty("An Integer").getIntValues(), ElementsAre(42));
    EXPECT_THAT(mProvider.getProperty("A Boolean").getBoolValues(), ElementsAre(true));
    EXPECT_NEAR(mProvider.getProperty("A Real").getRealValues()[0], 3.14159, EPSILON);
}

TEST_F(PropertyProviderIdcLoadingTest, InvalidPropsIgnored) {
    int intArrayData[2];
    int initialInts[2] = {0, 1};
    gesturePropProvider.create_int_fn(&mProvider, "Two Integers", intArrayData, 2, initialInts);

    PropertyMap idcProps;
    // Wrong type
    idcProps.addProperty("gestureProp.An_Integer", "37.25");
    // Wrong size
    idcProps.addProperty("gestureProp.Two_Integers", "42");
    // Doesn't exist
    idcProps.addProperty("gestureProp.Some_Nonexistent_Property", "1");
    // A valid assignment that should still be applied despite the others being invalid
    idcProps.addProperty("gestureProp.A_Real", "3.14159");

    mProvider.loadPropertiesFromIdcFile(idcProps);
    EXPECT_THAT(mProvider.getProperty("An Integer").getIntValues(), ElementsAre(0));
    EXPECT_THAT(mProvider.getProperty("Two Integers").getIntValues(), ElementsAre(0, 1));
    EXPECT_FALSE(mProvider.hasProperty("Some Nonexistent Property"));
    EXPECT_NEAR(mProvider.getProperty("A Real").getRealValues()[0], 3.14159, EPSILON);
}

TEST_F(PropertyProviderIdcLoadingTest, FunkyName) {
    int data;
    int initialData = 0;
    gesturePropProvider.create_int_fn(&mProvider, "  I lOvE sNAKes ", &data, 1, &initialData);

    PropertyMap idcProps;
    idcProps.addProperty("gestureProp.__I_lOvE_sNAKes_", "42");

    mProvider.loadPropertiesFromIdcFile(idcProps);
    EXPECT_THAT(mProvider.getProperty("  I lOvE sNAKes ").getIntValues(), ElementsAre(42));
}

} // namespace android
