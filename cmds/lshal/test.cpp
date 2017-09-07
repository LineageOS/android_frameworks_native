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

#define LOG_TAG "Lshal"
#include <android-base/logging.h>

#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <android/hardware/tests/baz/1.0/IQuux.h>
#include <hidl/HidlTransportSupport.h>

#include "ListCommand.h"
#include "Lshal.h"

#define NELEMS(array)   static_cast<int>(sizeof(array) / sizeof(array[0]))

using namespace testing;

using ::android::hidl::base::V1_0::IBase;
using ::android::hidl::manager::V1_0::IServiceManager;
using ::android::hidl::manager::V1_0::IServiceNotification;
using ::android::hardware::hidl_death_recipient;
using ::android::hardware::hidl_handle;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;

namespace android {
namespace hardware {
namespace tests {
namespace baz {
namespace V1_0 {
namespace implementation {
struct Quux : android::hardware::tests::baz::V1_0::IQuux {
    ::android::hardware::Return<void> debug(const hidl_handle& hh, const hidl_vec<hidl_string>& options) override {
        const native_handle_t *handle = hh.getNativeHandle();
        if (handle->numFds < 1) {
            return Void();
        }
        int fd = handle->data[0];
        std::string content{descriptor};
        for (const auto &option : options) {
            content += "\n";
            content += option.c_str();
        }
        ssize_t written = write(fd, content.c_str(), content.size());
        if (written != (ssize_t)content.size()) {
            LOG(WARNING) << "SERVER(Quux) debug writes " << written << " bytes < "
                    << content.size() << " bytes, errno = " << errno;
        }
        return Void();
    }
};

} // namespace implementation
} // namespace V1_0
} // namespace baz
} // namespace tests
} // namespace hardware

namespace lshal {


class MockServiceManager : public IServiceManager {
public:
    template<typename T>
    using R = ::android::hardware::Return<T>;
    using String = const hidl_string&;
    ~MockServiceManager() = default;

#define MOCK_METHOD_CB(name) MOCK_METHOD1(name, R<void>(IServiceManager::name##_cb))

    MOCK_METHOD2(get, R<sp<IBase>>(String, String));
    MOCK_METHOD2(add, R<bool>(String, const sp<IBase>&));
    MOCK_METHOD2(getTransport, R<IServiceManager::Transport>(String, String));
    MOCK_METHOD_CB(list);
    MOCK_METHOD2(listByInterface, R<void>(String, listByInterface_cb));
    MOCK_METHOD3(registerForNotifications, R<bool>(String, String, const sp<IServiceNotification>&));
    MOCK_METHOD_CB(debugDump);
    MOCK_METHOD2(registerPassthroughClient, R<void>(String, String));
    MOCK_METHOD_CB(interfaceChain);
    MOCK_METHOD2(debug, R<void>(const hidl_handle&, const hidl_vec<hidl_string>&));
    MOCK_METHOD_CB(interfaceDescriptor);
    MOCK_METHOD_CB(getHashChain);
    MOCK_METHOD0(setHalInstrumentation, R<void>());
    MOCK_METHOD2(linkToDeath, R<bool>(const sp<hidl_death_recipient>&, uint64_t));
    MOCK_METHOD0(ping, R<void>());
    MOCK_METHOD_CB(getDebugInfo);
    MOCK_METHOD0(notifySyspropsChanged, R<void>());
    MOCK_METHOD1(unlinkToDeath, R<bool>(const sp<hidl_death_recipient>&));

};

class DebugTest : public ::testing::Test {
public:
    void SetUp() override {
        using ::android::hardware::tests::baz::V1_0::IQuux;
        using ::android::hardware::tests::baz::V1_0::implementation::Quux;

        err.str("");
        out.str("");
        serviceManager = new testing::NiceMock<MockServiceManager>();
        ON_CALL(*serviceManager, get(_, _)).WillByDefault(Invoke(
            [](const auto &iface, const auto &inst) -> ::android::hardware::Return<sp<IBase>> {
                if (iface == IQuux::descriptor && inst == "default")
                    return new Quux();
                return nullptr;
            }));

        lshal = std::make_unique<Lshal>(out, err, serviceManager, serviceManager);
    }
    void TearDown() override {}

    std::stringstream err;
    std::stringstream out;
    sp<MockServiceManager> serviceManager;

    std::unique_ptr<Lshal> lshal;
};

static Arg createArg(const std::vector<const char*>& args) {
    return Arg{static_cast<int>(args.size()), const_cast<char**>(args.data())};
}

template<typename T>
static Status callMain(const std::unique_ptr<T>& lshal, const std::vector<const char*>& args) {
    return lshal->main(createArg(args));
}

TEST_F(DebugTest, Debug) {
    EXPECT_EQ(0u, callMain(lshal, {
        "lshal", "debug", "android.hardware.tests.baz@1.0::IQuux/default", "foo", "bar"
    }));
    EXPECT_THAT(out.str(), StrEq("android.hardware.tests.baz@1.0::IQuux\nfoo\nbar"));
    EXPECT_THAT(err.str(), IsEmpty());
}

TEST_F(DebugTest, Debug2) {
    EXPECT_EQ(0u, callMain(lshal, {
        "lshal", "debug", "android.hardware.tests.baz@1.0::IQuux", "baz", "quux"
    }));
    EXPECT_THAT(out.str(), StrEq("android.hardware.tests.baz@1.0::IQuux\nbaz\nquux"));
    EXPECT_THAT(err.str(), IsEmpty());
}

TEST_F(DebugTest, Debug3) {
    EXPECT_NE(0u, callMain(lshal, {
        "lshal", "debug", "android.hardware.tests.doesnotexist@1.0::IDoesNotExist",
    }));
    EXPECT_THAT(err.str(), HasSubstr("does not exist"));
}

class MockLshal : public Lshal {
public:
    MockLshal() {}
    ~MockLshal() = default;
    MOCK_CONST_METHOD0(out, NullableOStream<std::ostream>());
    MOCK_CONST_METHOD0(err, NullableOStream<std::ostream>());
};

// expose protected fields and methods for ListCommand
class MockListCommand : public ListCommand {
public:
    MockListCommand(Lshal* lshal) : ListCommand(*lshal) {}

    Status parseArgs(const Arg& arg) { return ListCommand::parseArgs("", arg); }
    void forEachTable(const std::function<void(const Table &)> &f) const {
        return ListCommand::forEachTable(f);
    }
};

class ListParseArgsTest : public ::testing::Test {
public:
    void SetUp() override {
        mockLshal = std::make_unique<NiceMock<MockLshal>>();
        mockList = std::make_unique<MockListCommand>(mockLshal.get());
        // ListCommand::parseArgs should parse arguments from the second element
        optind = 1;
    }
    std::unique_ptr<MockLshal> mockLshal;
    std::unique_ptr<MockListCommand> mockList;
    std::stringstream output;
};

TEST_F(ListParseArgsTest, Default) {
    // default args
    EXPECT_EQ(0u, mockList->parseArgs(createArg({})));
    mockList->forEachTable([](const Table& table) {
        EXPECT_EQ(SelectedColumns({TableColumnType::INTERFACE_NAME, TableColumnType::THREADS,
                                   TableColumnType::SERVER_PID, TableColumnType::CLIENT_PIDS}),
                  table.getSelectedColumns());
    });
}

TEST_F(ListParseArgsTest, Args) {
    EXPECT_EQ(0u, mockList->parseArgs(createArg({"lshal", "-p", "-i", "-a", "-c"})));
    mockList->forEachTable([](const Table& table) {
        EXPECT_EQ(SelectedColumns({TableColumnType::SERVER_PID, TableColumnType::INTERFACE_NAME,
                                   TableColumnType::SERVER_ADDR, TableColumnType::CLIENT_PIDS}),
                  table.getSelectedColumns());
    });
}

TEST_F(ListParseArgsTest, Cmds) {
    EXPECT_EQ(0u, mockList->parseArgs(createArg({"lshal", "-m"})));
    mockList->forEachTable([](const Table& table) {
        EXPECT_EQ(SelectedColumns({TableColumnType::INTERFACE_NAME, TableColumnType::THREADS,
                                   TableColumnType::SERVER_CMD, TableColumnType::CLIENT_CMDS}),
                  table.getSelectedColumns());
    });
}

TEST_F(ListParseArgsTest, DebugAndNeat) {
    ON_CALL(*mockLshal, err()).WillByDefault(Return(NullableOStream<std::ostream>(output)));
    EXPECT_NE(0u, mockList->parseArgs(createArg({"lshal", "--neat", "-d"})));
    EXPECT_THAT(output.str(), StrNe(""));
}

} // namespace lshal
} // namespace android

int main(int argc, char **argv) {
    ::testing::InitGoogleMock(&argc, argv);
    return RUN_ALL_TESTS();
}
