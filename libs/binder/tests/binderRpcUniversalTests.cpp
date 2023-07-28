/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <chrono>
#include <cstdlib>
#include <type_traits>

#include "binderRpcTestCommon.h"
#include "binderRpcTestFixture.h"

using namespace std::chrono_literals;
using namespace std::placeholders;
using testing::AssertionFailure;
using testing::AssertionResult;
using testing::AssertionSuccess;

namespace android {

static_assert(RPC_WIRE_PROTOCOL_VERSION + 1 == RPC_WIRE_PROTOCOL_VERSION_NEXT ||
              RPC_WIRE_PROTOCOL_VERSION == RPC_WIRE_PROTOCOL_VERSION_EXPERIMENTAL);

TEST(BinderRpcParcel, EntireParcelFormatted) {
    Parcel p;
    p.writeInt32(3);

    EXPECT_DEATH_IF_SUPPORTED(p.markForBinder(sp<BBinder>::make()),
                              "format must be set before data is written");
}

TEST(BinderRpc, CannotUseNextWireVersion) {
    auto session = RpcSession::make();
    EXPECT_FALSE(session->setProtocolVersion(RPC_WIRE_PROTOCOL_VERSION_NEXT));
    EXPECT_FALSE(session->setProtocolVersion(RPC_WIRE_PROTOCOL_VERSION_NEXT + 1));
    EXPECT_FALSE(session->setProtocolVersion(RPC_WIRE_PROTOCOL_VERSION_NEXT + 2));
    EXPECT_FALSE(session->setProtocolVersion(RPC_WIRE_PROTOCOL_VERSION_NEXT + 15));
}

TEST(BinderRpc, CanUseExperimentalWireVersion) {
    auto session = RpcSession::make();
    EXPECT_TRUE(session->setProtocolVersion(RPC_WIRE_PROTOCOL_VERSION_EXPERIMENTAL));
}

TEST_P(BinderRpc, Ping) {
    auto proc = createRpcTestSocketServerProcess({});
    ASSERT_NE(proc.rootBinder, nullptr);
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());
}

TEST_P(BinderRpc, GetInterfaceDescriptor) {
    auto proc = createRpcTestSocketServerProcess({});
    ASSERT_NE(proc.rootBinder, nullptr);
    EXPECT_EQ(IBinderRpcTest::descriptor, proc.rootBinder->getInterfaceDescriptor());
}

TEST_P(BinderRpc, MultipleSessions) {
    if (serverSingleThreaded()) {
        // Tests with multiple sessions require a multi-threaded service,
        // but work fine on a single-threaded client
        GTEST_SKIP() << "This test requires a multi-threaded service";
    }

    auto proc = createRpcTestSocketServerProcess({.numThreads = 1, .numSessions = 5});
    for (auto session : proc.proc->sessions) {
        ASSERT_NE(nullptr, session.root);
        EXPECT_EQ(OK, session.root->pingBinder());
    }
}

TEST_P(BinderRpc, SeparateRootObject) {
    if (serverSingleThreaded()) {
        GTEST_SKIP() << "This test requires a multi-threaded service";
    }

    SocketType type = GetParam().type;
    if (type == SocketType::PRECONNECTED || type == SocketType::UNIX ||
        type == SocketType::UNIX_BOOTSTRAP || type == SocketType::UNIX_RAW) {
        // we can't get port numbers for unix sockets
        return;
    }

    auto proc = createRpcTestSocketServerProcess({.numSessions = 2});

    int port1 = 0;
    EXPECT_OK(proc.rootIface->getClientPort(&port1));

    sp<IBinderRpcTest> rootIface2 = interface_cast<IBinderRpcTest>(proc.proc->sessions.at(1).root);
    int port2;
    EXPECT_OK(rootIface2->getClientPort(&port2));

    // we should have a different IBinderRpcTest object created for each
    // session, because we use setPerSessionRootObject
    EXPECT_NE(port1, port2);
}

TEST_P(BinderRpc, TransactionsMustBeMarkedRpc) {
    auto proc = createRpcTestSocketServerProcess({});
    Parcel data;
    Parcel reply;
    EXPECT_EQ(BAD_TYPE, proc.rootBinder->transact(IBinder::PING_TRANSACTION, data, &reply, 0));
}

TEST_P(BinderRpc, AppendSeparateFormats) {
    if (socketType() == SocketType::TIPC) {
        GTEST_SKIP() << "Trusty does not support multiple server processes";
    }

    auto proc1 = createRpcTestSocketServerProcess({});
    auto proc2 = createRpcTestSocketServerProcess({});

    Parcel pRaw;

    Parcel p1;
    p1.markForBinder(proc1.rootBinder);
    p1.writeInt32(3);

    EXPECT_EQ(BAD_TYPE, p1.appendFrom(&pRaw, 0, pRaw.dataSize()));
    EXPECT_EQ(BAD_TYPE, pRaw.appendFrom(&p1, 0, p1.dataSize()));

    Parcel p2;
    p2.markForBinder(proc2.rootBinder);
    p2.writeInt32(7);

    EXPECT_EQ(BAD_TYPE, p1.appendFrom(&p2, 0, p2.dataSize()));
    EXPECT_EQ(BAD_TYPE, p2.appendFrom(&p1, 0, p1.dataSize()));
}

TEST_P(BinderRpc, UnknownTransaction) {
    auto proc = createRpcTestSocketServerProcess({});
    Parcel data;
    data.markForBinder(proc.rootBinder);
    Parcel reply;
    EXPECT_EQ(UNKNOWN_TRANSACTION, proc.rootBinder->transact(1337, data, &reply, 0));
}

TEST_P(BinderRpc, SendSomethingOneway) {
    auto proc = createRpcTestSocketServerProcess({});
    EXPECT_OK(proc.rootIface->sendString("asdf"));
}

TEST_P(BinderRpc, SendAndGetResultBack) {
    auto proc = createRpcTestSocketServerProcess({});
    std::string doubled;
    EXPECT_OK(proc.rootIface->doubleString("cool ", &doubled));
    EXPECT_EQ("cool cool ", doubled);
}

TEST_P(BinderRpc, SendAndGetResultBackBig) {
    auto proc = createRpcTestSocketServerProcess({});
    // Trusty has a limit of 4096 bytes for the entire RPC Binder message
    size_t singleLen = socketType() == SocketType::TIPC ? 512 : 4096;
    std::string single = std::string(singleLen, 'a');
    std::string doubled;
    EXPECT_OK(proc.rootIface->doubleString(single, &doubled));
    EXPECT_EQ(single + single, doubled);
}

TEST_P(BinderRpc, InvalidNullBinderReturn) {
    auto proc = createRpcTestSocketServerProcess({});

    sp<IBinder> outBinder;
    EXPECT_EQ(proc.rootIface->getNullBinder(&outBinder).transactionError(), UNEXPECTED_NULL);
}

TEST_P(BinderRpc, CallMeBack) {
    auto proc = createRpcTestSocketServerProcess({});

    int32_t pingResult;
    EXPECT_OK(proc.rootIface->pingMe(new MyBinderRpcSession("foo"), &pingResult));
    EXPECT_EQ(OK, pingResult);

    EXPECT_EQ(0, MyBinderRpcSession::gNum);
}

TEST_P(BinderRpc, RepeatBinder) {
    auto proc = createRpcTestSocketServerProcess({});

    sp<IBinder> inBinder = new MyBinderRpcSession("foo");
    sp<IBinder> outBinder;
    EXPECT_OK(proc.rootIface->repeatBinder(inBinder, &outBinder));
    EXPECT_EQ(inBinder, outBinder);

    wp<IBinder> weak = inBinder;
    inBinder = nullptr;
    outBinder = nullptr;

    // Force reading a reply, to process any pending dec refs from the other
    // process (the other process will process dec refs there before processing
    // the ping here).
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());

    EXPECT_EQ(nullptr, weak.promote());

    EXPECT_EQ(0, MyBinderRpcSession::gNum);
}

TEST_P(BinderRpc, RepeatTheirBinder) {
    auto proc = createRpcTestSocketServerProcess({});

    sp<IBinderRpcSession> session;
    EXPECT_OK(proc.rootIface->openSession("aoeu", &session));

    sp<IBinder> inBinder = IInterface::asBinder(session);
    sp<IBinder> outBinder;
    EXPECT_OK(proc.rootIface->repeatBinder(inBinder, &outBinder));
    EXPECT_EQ(inBinder, outBinder);

    wp<IBinder> weak = inBinder;
    session = nullptr;
    inBinder = nullptr;
    outBinder = nullptr;

    // Force reading a reply, to process any pending dec refs from the other
    // process (the other process will process dec refs there before processing
    // the ping here).
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());

    EXPECT_EQ(nullptr, weak.promote());
}

TEST_P(BinderRpc, RepeatBinderNull) {
    auto proc = createRpcTestSocketServerProcess({});

    sp<IBinder> outBinder;
    EXPECT_OK(proc.rootIface->repeatBinder(nullptr, &outBinder));
    EXPECT_EQ(nullptr, outBinder);
}

TEST_P(BinderRpc, HoldBinder) {
    auto proc = createRpcTestSocketServerProcess({});

    IBinder* ptr = nullptr;
    {
        sp<IBinder> binder = new BBinder();
        ptr = binder.get();
        EXPECT_OK(proc.rootIface->holdBinder(binder));
    }

    sp<IBinder> held;
    EXPECT_OK(proc.rootIface->getHeldBinder(&held));

    EXPECT_EQ(held.get(), ptr);

    // stop holding binder, because we test to make sure references are cleaned
    // up
    EXPECT_OK(proc.rootIface->holdBinder(nullptr));
    // and flush ref counts
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());
}

// START TESTS FOR LIMITATIONS OF SOCKET BINDER
// These are behavioral differences form regular binder, where certain usecases
// aren't supported.

TEST_P(BinderRpc, CannotMixBindersBetweenUnrelatedSocketSessions) {
    if (socketType() == SocketType::TIPC) {
        GTEST_SKIP() << "Trusty does not support multiple server processes";
    }

    auto proc1 = createRpcTestSocketServerProcess({});
    auto proc2 = createRpcTestSocketServerProcess({});

    sp<IBinder> outBinder;
    EXPECT_EQ(INVALID_OPERATION,
              proc1.rootIface->repeatBinder(proc2.rootBinder, &outBinder).transactionError());
}

TEST_P(BinderRpc, CannotMixBindersBetweenTwoSessionsToTheSameServer) {
    if (serverSingleThreaded()) {
        GTEST_SKIP() << "This test requires a multi-threaded service";
    }

    auto proc = createRpcTestSocketServerProcess({.numThreads = 1, .numSessions = 2});

    sp<IBinder> outBinder;
    EXPECT_EQ(INVALID_OPERATION,
              proc.rootIface->repeatBinder(proc.proc->sessions.at(1).root, &outBinder)
                      .transactionError());
}

TEST_P(BinderRpc, CannotSendRegularBinderOverSocketBinder) {
    if (!kEnableKernelIpc || noKernel()) {
        GTEST_SKIP() << "Test disabled because Binder kernel driver was disabled "
                        "at build time.";
    }

    auto proc = createRpcTestSocketServerProcess({});

    sp<IBinder> someRealBinder = IInterface::asBinder(defaultServiceManager());
    sp<IBinder> outBinder;
    EXPECT_EQ(INVALID_OPERATION,
              proc.rootIface->repeatBinder(someRealBinder, &outBinder).transactionError());
}

TEST_P(BinderRpc, CannotSendSocketBinderOverRegularBinder) {
    if (!kEnableKernelIpc || noKernel()) {
        GTEST_SKIP() << "Test disabled because Binder kernel driver was disabled "
                        "at build time.";
    }

    auto proc = createRpcTestSocketServerProcess({});

    // for historical reasons, IServiceManager interface only returns the
    // exception code
    EXPECT_EQ(binder::Status::EX_TRANSACTION_FAILED,
              defaultServiceManager()->addService(String16("not_suspicious"), proc.rootBinder));
}

// END TESTS FOR LIMITATIONS OF SOCKET BINDER

TEST_P(BinderRpc, RepeatRootObject) {
    auto proc = createRpcTestSocketServerProcess({});

    sp<IBinder> outBinder;
    EXPECT_OK(proc.rootIface->repeatBinder(proc.rootBinder, &outBinder));
    EXPECT_EQ(proc.rootBinder, outBinder);
}

TEST_P(BinderRpc, NestedTransactions) {
    auto fileDescriptorTransportMode = RpcSession::FileDescriptorTransportMode::UNIX;
    if (socketType() == SocketType::TIPC) {
        // TIPC does not support file descriptors yet
        fileDescriptorTransportMode = RpcSession::FileDescriptorTransportMode::NONE;
    }
    auto proc = createRpcTestSocketServerProcess({
            // Enable FD support because it uses more stack space and so represents
            // something closer to a worst case scenario.
            .clientFileDescriptorTransportMode = fileDescriptorTransportMode,
            .serverSupportedFileDescriptorTransportModes = {fileDescriptorTransportMode},
    });

    auto nastyNester = sp<MyBinderRpcTestDefault>::make();
    EXPECT_OK(proc.rootIface->nestMe(nastyNester, 10));

    wp<IBinder> weak = nastyNester;
    nastyNester = nullptr;
    EXPECT_EQ(nullptr, weak.promote());
}

TEST_P(BinderRpc, SameBinderEquality) {
    auto proc = createRpcTestSocketServerProcess({});

    sp<IBinder> a;
    EXPECT_OK(proc.rootIface->alwaysGiveMeTheSameBinder(&a));

    sp<IBinder> b;
    EXPECT_OK(proc.rootIface->alwaysGiveMeTheSameBinder(&b));

    EXPECT_EQ(a, b);
}

TEST_P(BinderRpc, SameBinderEqualityWeak) {
    auto proc = createRpcTestSocketServerProcess({});

    sp<IBinder> a;
    EXPECT_OK(proc.rootIface->alwaysGiveMeTheSameBinder(&a));
    wp<IBinder> weak = a;
    a = nullptr;

    sp<IBinder> b;
    EXPECT_OK(proc.rootIface->alwaysGiveMeTheSameBinder(&b));

    // this is the wrong behavior, since BpBinder
    // doesn't implement onIncStrongAttempted
    // but make sure there is no crash
    EXPECT_EQ(nullptr, weak.promote());

    GTEST_SKIP() << "Weak binders aren't currently re-promotable for RPC binder.";

    // In order to fix this:
    // - need to have incStrongAttempted reflected across IPC boundary (wait for
    //   response to promote - round trip...)
    // - sendOnLastWeakRef, to delete entries out of RpcState table
    EXPECT_EQ(b, weak.promote());
}

#define EXPECT_SESSIONS(expected, iface)                  \
    do {                                                  \
        int session;                                      \
        EXPECT_OK((iface)->getNumOpenSessions(&session)); \
        EXPECT_EQ(static_cast<int>(expected), session);   \
    } while (false)

TEST_P(BinderRpc, SingleSession) {
    auto proc = createRpcTestSocketServerProcess({});

    sp<IBinderRpcSession> session;
    EXPECT_OK(proc.rootIface->openSession("aoeu", &session));
    std::string out;
    EXPECT_OK(session->getName(&out));
    EXPECT_EQ("aoeu", out);

    EXPECT_SESSIONS(1, proc.rootIface);
    session = nullptr;
    EXPECT_SESSIONS(0, proc.rootIface);
}

TEST_P(BinderRpc, ManySessions) {
    auto proc = createRpcTestSocketServerProcess({});

    std::vector<sp<IBinderRpcSession>> sessions;

    for (size_t i = 0; i < 15; i++) {
        EXPECT_SESSIONS(i, proc.rootIface);
        sp<IBinderRpcSession> session;
        EXPECT_OK(proc.rootIface->openSession(std::to_string(i), &session));
        sessions.push_back(session);
    }
    EXPECT_SESSIONS(sessions.size(), proc.rootIface);
    for (size_t i = 0; i < sessions.size(); i++) {
        std::string out;
        EXPECT_OK(sessions.at(i)->getName(&out));
        EXPECT_EQ(std::to_string(i), out);
    }
    EXPECT_SESSIONS(sessions.size(), proc.rootIface);

    while (!sessions.empty()) {
        sessions.pop_back();
        EXPECT_SESSIONS(sessions.size(), proc.rootIface);
    }
    EXPECT_SESSIONS(0, proc.rootIface);
}

TEST_P(BinderRpc, OnewayCallDoesNotWait) {
    constexpr size_t kReallyLongTimeMs = 100;
    constexpr size_t kSleepMs = kReallyLongTimeMs * 5;

    auto proc = createRpcTestSocketServerProcess({});

    size_t epochMsBefore = epochMillis();

    EXPECT_OK(proc.rootIface->sleepMsAsync(kSleepMs));

    size_t epochMsAfter = epochMillis();
    EXPECT_LT(epochMsAfter, epochMsBefore + kReallyLongTimeMs);
}

TEST_P(BinderRpc, Callbacks) {
    const static std::string kTestString = "good afternoon!";

    for (bool callIsOneway : {true, false}) {
        for (bool callbackIsOneway : {true, false}) {
            for (bool delayed : {true, false}) {
                if (clientOrServerSingleThreaded() &&
                    (callIsOneway || callbackIsOneway || delayed)) {
                    // we have no incoming connections to receive the callback
                    continue;
                }

                size_t numIncomingConnections = clientOrServerSingleThreaded() ? 0 : 1;
                auto proc = createRpcTestSocketServerProcess(
                        {.numThreads = 1,
                         .numSessions = 1,
                         .numIncomingConnectionsBySession = {numIncomingConnections}});
                auto cb = sp<MyBinderRpcCallback>::make();

                if (callIsOneway) {
                    EXPECT_OK(proc.rootIface->doCallbackAsync(cb, callbackIsOneway, delayed,
                                                              kTestString));
                } else {
                    EXPECT_OK(
                            proc.rootIface->doCallback(cb, callbackIsOneway, delayed, kTestString));
                }

                // if both transactions are synchronous and the response is sent back on the
                // same thread, everything should have happened in a nested call. Otherwise,
                // the callback will be processed on another thread.
                if (callIsOneway || callbackIsOneway || delayed) {
                    using std::literals::chrono_literals::operator""s;
                    RpcMutexUniqueLock _l(cb->mMutex);
                    cb->mCv.wait_for(_l, 1s, [&] { return !cb->mValues.empty(); });
                }

                EXPECT_EQ(cb->mValues.size(), 1UL)
                        << "callIsOneway: " << callIsOneway
                        << " callbackIsOneway: " << callbackIsOneway << " delayed: " << delayed;
                if (cb->mValues.empty()) continue;
                EXPECT_EQ(cb->mValues.at(0), kTestString)
                        << "callIsOneway: " << callIsOneway
                        << " callbackIsOneway: " << callbackIsOneway << " delayed: " << delayed;

                proc.forceShutdown();
            }
        }
    }
}

TEST_P(BinderRpc, OnewayCallbackWithNoThread) {
    auto proc = createRpcTestSocketServerProcess({});
    auto cb = sp<MyBinderRpcCallback>::make();

    Status status = proc.rootIface->doCallback(cb, true /*oneway*/, false /*delayed*/, "anything");
    EXPECT_EQ(WOULD_BLOCK, status.transactionError());
}

TEST_P(BinderRpc, AidlDelegatorTest) {
    auto proc = createRpcTestSocketServerProcess({});
    auto myDelegator = sp<IBinderRpcTestDelegator>::make(proc.rootIface);
    ASSERT_NE(nullptr, myDelegator);

    std::string doubled;
    EXPECT_OK(myDelegator->doubleString("cool ", &doubled));
    EXPECT_EQ("cool cool ", doubled);
}

} // namespace android
