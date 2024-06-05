/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <binder/Parcel.h>
#include <binder/PersistableBundle.h>
#include <gtest/gtest.h>
#include <numeric>

using android::OK;
using android::Parcel;
using android::status_t;
using android::String16;
using android::String8;
using android::os::PersistableBundle;

namespace android {

inline std::string to_string(String16 const& str) {
    return String8{str}.c_str();
}

namespace os {

template <typename T>
inline std::ostream& operator<<(std::ostream& out, std::vector<T> const& vec) {
    using std::to_string;
    auto str =
            std::accumulate(vec.begin(), vec.end(), std::string{},
                            [](std::string const& a, auto const& b) { return a + to_string(b); });
    return out << str;
}

inline std::ostream& operator<<(std::ostream& out, PersistableBundle const& pb) {
#define PRINT(TYPENAME, TYPE)                                \
    for (auto const& key : pb.get##TYPENAME##Keys()) {       \
        TYPE val{};                                          \
        pb.get##TYPENAME(key, &val);                         \
        out << #TYPE " " << key << ": " << val << std::endl; \
    }

    out << "size: " << pb.size() << std::endl;
    PRINT(Boolean, bool);
    PRINT(Int, int);
    PRINT(Long, int64_t);
    PRINT(Double, double);
    PRINT(String, String16);
    PRINT(BooleanVector, std::vector<bool>);
    PRINT(IntVector, std::vector<int32_t>);
    PRINT(LongVector, std::vector<int64_t>);
    PRINT(DoubleVector, std::vector<double>);
    PRINT(StringVector, std::vector<String16>);
    PRINT(PersistableBundle, PersistableBundle);

#undef PRINT

    return out;
}

} // namespace os
} // namespace android

static const String16 kKey{"key"};

static PersistableBundle createSimplePersistableBundle() {
    PersistableBundle pb{};
    pb.putInt(kKey, 64);
    return pb;
}

#define TEST_PUT_AND_GET(TYPENAME, TYPE, ...)              \
    TEST(PersistableBundle, PutAndGet##TYPENAME) {         \
        TYPE const expected{__VA_ARGS__};                  \
        PersistableBundle pb{};                            \
                                                           \
        pb.put##TYPENAME(kKey, expected);                  \
                                                           \
        std::set<String16> expectedKeys{kKey};             \
        EXPECT_EQ(pb.get##TYPENAME##Keys(), expectedKeys); \
                                                           \
        TYPE val{};                                        \
        EXPECT_TRUE(pb.get##TYPENAME(kKey, &val));         \
        EXPECT_EQ(val, expected);                          \
    }

TEST_PUT_AND_GET(Boolean, bool, true);
TEST_PUT_AND_GET(Int, int, 64);
TEST_PUT_AND_GET(Long, int64_t, 42);
TEST_PUT_AND_GET(Double, double, 42.64);
TEST_PUT_AND_GET(String, String16, String16{"foo"});
TEST_PUT_AND_GET(BooleanVector, std::vector<bool>, true, true);
TEST_PUT_AND_GET(IntVector, std::vector<int32_t>, 1, 2);
TEST_PUT_AND_GET(LongVector, std::vector<int64_t>, 1, 2);
TEST_PUT_AND_GET(DoubleVector, std::vector<double>, 4.2, 5.9);
TEST_PUT_AND_GET(StringVector, std::vector<String16>, String16{"foo"}, String16{"bar"});
TEST_PUT_AND_GET(PersistableBundle, PersistableBundle, createSimplePersistableBundle());

TEST(PersistableBundle, ParcelAndUnparcel) {
    PersistableBundle expected = createSimplePersistableBundle();
    PersistableBundle out{};

    Parcel p{};
    EXPECT_EQ(expected.writeToParcel(&p), 0);
    p.setDataPosition(0);
    EXPECT_EQ(out.readFromParcel(&p), 0);

    EXPECT_EQ(expected, out);
}

TEST(PersistableBundle, OverwriteKey) {
    PersistableBundle pb{};

    pb.putInt(kKey, 64);
    pb.putDouble(kKey, 0.5);

    EXPECT_EQ(pb.getIntKeys().size(), 0);
    EXPECT_EQ(pb.getDoubleKeys().size(), 1);

    double out;
    EXPECT_TRUE(pb.getDouble(kKey, &out));
    EXPECT_EQ(out, 0.5);
}
