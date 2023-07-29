/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <aidl/IBinderRpcTest.h>
#include <android-base/stringprintf.h>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <type_traits>

#include <dlfcn.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>

#ifdef BINDER_RPC_TO_TRUSTY_TEST
#include <binder/RpcTransportTipcAndroid.h>
#include <trusty/tipc.h>
#endif // BINDER_RPC_TO_TRUSTY_TEST

#include "binderRpcTestCommon.h"
#include "binderRpcTestFixture.h"

using namespace std::chrono_literals;
using namespace std::placeholders;
using testing::AssertionFailure;
using testing::AssertionResult;
using testing::AssertionSuccess;

namespace android {

#ifdef BINDER_TEST_NO_SHARED_LIBS
constexpr bool kEnableSharedLibs = false;
#else
constexpr bool kEnableSharedLibs = true;
#endif

#ifdef BINDER_RPC_TO_TRUSTY_TEST
constexpr char kTrustyIpcDevice[] = "/dev/trusty-ipc-dev0";
#endif

static std::string WaitStatusToString(int wstatus) {
    if (WIFEXITED(wstatus)) {
        return base::StringPrintf("exit status %d", WEXITSTATUS(wstatus));
    }
    if (WIFSIGNALED(wstatus)) {
        return base::StringPrintf("term signal %d", WTERMSIG(wstatus));
    }
    return base::StringPrintf("unexpected state %d", wstatus);
}

static void debugBacktrace(pid_t pid) {
    std::cerr << "TAKING BACKTRACE FOR PID " << pid << std::endl;
    system((std::string("debuggerd -b ") + std::to_string(pid)).c_str());
}

class Process {
public:
    Process(Process&& other)
          : mCustomExitStatusCheck(std::move(other.mCustomExitStatusCheck)),
            mReadEnd(std::move(other.mReadEnd)),
            mWriteEnd(std::move(other.mWriteEnd)) {
        // The default move constructor doesn't clear mPid after moving it,
        // which we need to do because the destructor checks for mPid!=0
        mPid = other.mPid;
        other.mPid = 0;
    }
    Process(const std::function<void(android::base::borrowed_fd /* writeEnd */,
                                     android::base::borrowed_fd /* readEnd */)>& f) {
        android::base::unique_fd childWriteEnd;
        android::base::unique_fd childReadEnd;
        CHECK(android::base::Pipe(&mReadEnd, &childWriteEnd, 0)) << strerror(errno);
        CHECK(android::base::Pipe(&childReadEnd, &mWriteEnd, 0)) << strerror(errno);
        if (0 == (mPid = fork())) {
            // racey: assume parent doesn't crash before this is set
            prctl(PR_SET_PDEATHSIG, SIGHUP);

            f(childWriteEnd, childReadEnd);

            exit(0);
        }
    }
    ~Process() {
        if (mPid != 0) {
            int wstatus;
            waitpid(mPid, &wstatus, 0);
            if (mCustomExitStatusCheck) {
                mCustomExitStatusCheck(wstatus);
            } else {
                EXPECT_TRUE(WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0)
                        << "server process failed: " << WaitStatusToString(wstatus);
            }
        }
    }
    android::base::borrowed_fd readEnd() { return mReadEnd; }
    android::base::borrowed_fd writeEnd() { return mWriteEnd; }

    void setCustomExitStatusCheck(std::function<void(int wstatus)> f) {
        mCustomExitStatusCheck = std::move(f);
    }

    // Kill the process. Avoid if possible. Shutdown gracefully via an RPC instead.
    void terminate() { kill(mPid, SIGTERM); }

    pid_t getPid() { return mPid; }

private:
    std::function<void(int wstatus)> mCustomExitStatusCheck;
    pid_t mPid = 0;
    android::base::unique_fd mReadEnd;
    android::base::unique_fd mWriteEnd;
};

static std::string allocateSocketAddress() {
    static size_t id = 0;
    std::string temp = getenv("TMPDIR") ?: "/tmp";
    auto ret = temp + "/binderRpcTest_" + std::to_string(getpid()) + "_" + std::to_string(id++);
    unlink(ret.c_str());
    return ret;
};

static unsigned int allocateVsockPort() {
    static unsigned int vsockPort = 34567;
    return vsockPort++;
}

static base::unique_fd initUnixSocket(std::string addr) {
    auto socket_addr = UnixSocketAddress(addr.c_str());
    base::unique_fd fd(
            TEMP_FAILURE_RETRY(socket(socket_addr.addr()->sa_family, SOCK_STREAM, AF_UNIX)));
    CHECK(fd.ok());
    CHECK_EQ(0, TEMP_FAILURE_RETRY(bind(fd.get(), socket_addr.addr(), socket_addr.addrSize())));
    return fd;
}

// Destructors need to be defined, even if pure virtual
ProcessSession::~ProcessSession() {}

class LinuxProcessSession : public ProcessSession {
public:
    // reference to process hosting a socket server
    Process host;

    LinuxProcessSession(LinuxProcessSession&&) = default;
    LinuxProcessSession(Process&& host) : host(std::move(host)) {}
    ~LinuxProcessSession() override {
        for (auto& session : sessions) {
            session.root = nullptr;
        }

        for (size_t sessionNum = 0; sessionNum < sessions.size(); sessionNum++) {
            auto& info = sessions.at(sessionNum);
            sp<RpcSession>& session = info.session;

            EXPECT_NE(nullptr, session);
            EXPECT_NE(nullptr, session->state());
            EXPECT_EQ(0, session->state()->countBinders()) << (session->state()->dump(), "dump:");

            wp<RpcSession> weakSession = session;
            session = nullptr;

            // b/244325464 - 'getStrongCount' is printing '1' on failure here, which indicates the
            // the object should not actually be promotable. By looping, we distinguish a race here
            // from a bug causing the object to not be promotable.
            for (size_t i = 0; i < 3; i++) {
                sp<RpcSession> strongSession = weakSession.promote();
                EXPECT_EQ(nullptr, strongSession)
                        << "For session " << sessionNum << ". "
                        << (debugBacktrace(host.getPid()), debugBacktrace(getpid()),
                            "Leaked sess: ")
                        << strongSession->getStrongCount() << " checked time " << i;

                if (strongSession != nullptr) {
                    sleep(1);
                }
            }
        }
    }

    void setCustomExitStatusCheck(std::function<void(int wstatus)> f) override {
        host.setCustomExitStatusCheck(std::move(f));
    }

    void terminate() override { host.terminate(); }
};

static base::unique_fd connectTo(const RpcSocketAddress& addr) {
    base::unique_fd serverFd(
            TEMP_FAILURE_RETRY(socket(addr.addr()->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0)));
    int savedErrno = errno;
    CHECK(serverFd.ok()) << "Could not create socket " << addr.toString() << ": "
                         << strerror(savedErrno);

    if (0 != TEMP_FAILURE_RETRY(connect(serverFd.get(), addr.addr(), addr.addrSize()))) {
        int savedErrno = errno;
        LOG(FATAL) << "Could not connect to socket " << addr.toString() << ": "
                   << strerror(savedErrno);
    }
    return serverFd;
}

#ifndef BINDER_RPC_TO_TRUSTY_TEST
static base::unique_fd connectToUnixBootstrap(const RpcTransportFd& transportFd) {
    base::unique_fd sockClient, sockServer;
    if (!base::Socketpair(SOCK_STREAM, &sockClient, &sockServer)) {
        int savedErrno = errno;
        LOG(FATAL) << "Failed socketpair(): " << strerror(savedErrno);
    }

    int zero = 0;
    iovec iov{&zero, sizeof(zero)};
    std::vector<std::variant<base::unique_fd, base::borrowed_fd>> fds;
    fds.emplace_back(std::move(sockServer));

    if (sendMessageOnSocket(transportFd, &iov, 1, &fds) < 0) {
        int savedErrno = errno;
        LOG(FATAL) << "Failed sendMessageOnSocket: " << strerror(savedErrno);
    }
    return std::move(sockClient);
}
#endif // BINDER_RPC_TO_TRUSTY_TEST

std::unique_ptr<RpcTransportCtxFactory> BinderRpc::newFactory(RpcSecurity rpcSecurity) {
    return newTlsFactory(rpcSecurity);
}

// This creates a new process serving an interface on a certain number of
// threads.
std::unique_ptr<ProcessSession> BinderRpc::createRpcTestSocketServerProcessEtc(
        const BinderRpcOptions& options) {
    CHECK_GE(options.numSessions, 1) << "Must have at least one session to a server";

    if (options.numIncomingConnectionsBySession.size() != 0) {
        CHECK_EQ(options.numIncomingConnectionsBySession.size(), options.numSessions);
    }

    SocketType socketType = GetParam().type;
    RpcSecurity rpcSecurity = GetParam().security;
    uint32_t clientVersion = GetParam().clientVersion;
    uint32_t serverVersion = GetParam().serverVersion;
    bool singleThreaded = GetParam().singleThreaded;
    bool noKernel = GetParam().noKernel;

    std::string path = android::base::GetExecutableDirectory();
    auto servicePath = android::base::StringPrintf("%s/binder_rpc_test_service%s%s", path.c_str(),
                                                   singleThreaded ? "_single_threaded" : "",
                                                   noKernel ? "_no_kernel" : "");

    base::unique_fd bootstrapClientFd, socketFd;

    auto addr = allocateSocketAddress();
    // Initializes the socket before the fork/exec.
    if (socketType == SocketType::UNIX_RAW) {
        socketFd = initUnixSocket(addr);
    } else if (socketType == SocketType::UNIX_BOOTSTRAP) {
        // Do not set O_CLOEXEC, bootstrapServerFd needs to survive fork/exec.
        // This is because we cannot pass ParcelFileDescriptor over a pipe.
        if (!base::Socketpair(SOCK_STREAM, &bootstrapClientFd, &socketFd)) {
            int savedErrno = errno;
            LOG(FATAL) << "Failed socketpair(): " << strerror(savedErrno);
        }
    }

    auto ret = std::make_unique<LinuxProcessSession>(
            Process([=](android::base::borrowed_fd writeEnd, android::base::borrowed_fd readEnd) {
                if (socketType == SocketType::TIPC) {
                    // Trusty has a single persistent service
                    return;
                }

                auto writeFd = std::to_string(writeEnd.get());
                auto readFd = std::to_string(readEnd.get());
                execl(servicePath.c_str(), servicePath.c_str(), writeFd.c_str(), readFd.c_str(),
                      NULL);
            }));

    BinderRpcTestServerConfig serverConfig;
    serverConfig.numThreads = options.numThreads;
    serverConfig.socketType = static_cast<int32_t>(socketType);
    serverConfig.rpcSecurity = static_cast<int32_t>(rpcSecurity);
    serverConfig.serverVersion = serverVersion;
    serverConfig.vsockPort = allocateVsockPort();
    serverConfig.addr = addr;
    serverConfig.socketFd = socketFd.get();
    for (auto mode : options.serverSupportedFileDescriptorTransportModes) {
        serverConfig.serverSupportedFileDescriptorTransportModes.push_back(
                static_cast<int32_t>(mode));
    }
    if (socketType != SocketType::TIPC) {
        writeToFd(ret->host.writeEnd(), serverConfig);
    }

    std::vector<sp<RpcSession>> sessions;
    auto certVerifier = std::make_shared<RpcCertificateVerifierSimple>();
    for (size_t i = 0; i < options.numSessions; i++) {
        std::unique_ptr<RpcTransportCtxFactory> factory;
        if (socketType == SocketType::TIPC) {
#ifdef BINDER_RPC_TO_TRUSTY_TEST
            factory = RpcTransportCtxFactoryTipcAndroid::make();
#else
            LOG_ALWAYS_FATAL("TIPC socket type only supported on vendor");
#endif
        } else {
            factory = newTlsFactory(rpcSecurity, certVerifier);
        }
        sessions.emplace_back(RpcSession::make(std::move(factory)));
    }

    BinderRpcTestServerInfo serverInfo;
    if (socketType != SocketType::TIPC) {
        serverInfo = readFromFd<BinderRpcTestServerInfo>(ret->host.readEnd());
        BinderRpcTestClientInfo clientInfo;
        for (const auto& session : sessions) {
            auto& parcelableCert = clientInfo.certs.emplace_back();
            parcelableCert.data = session->getCertificate(RpcCertificateFormat::PEM);
        }
        writeToFd(ret->host.writeEnd(), clientInfo);

        CHECK_LE(serverInfo.port, std::numeric_limits<unsigned int>::max());
        if (socketType == SocketType::INET) {
            CHECK_NE(0, serverInfo.port);
        }

        if (rpcSecurity == RpcSecurity::TLS) {
            const auto& serverCert = serverInfo.cert.data;
            CHECK_EQ(OK,
                     certVerifier->addTrustedPeerCertificate(RpcCertificateFormat::PEM,
                                                             serverCert));
        }
    }

    status_t status;

    for (size_t i = 0; i < sessions.size(); i++) {
        const auto& session = sessions.at(i);

        size_t numIncoming = options.numIncomingConnectionsBySession.size() > 0
                ? options.numIncomingConnectionsBySession.at(i)
                : 0;

        CHECK(session->setProtocolVersion(clientVersion));
        session->setMaxIncomingThreads(numIncoming);
        session->setMaxOutgoingConnections(options.numOutgoingConnections);
        session->setFileDescriptorTransportMode(options.clientFileDescriptorTransportMode);

        switch (socketType) {
            case SocketType::PRECONNECTED:
                status = session->setupPreconnectedClient({}, [=]() {
                    return connectTo(UnixSocketAddress(serverConfig.addr.c_str()));
                });
                break;
            case SocketType::UNIX_RAW:
            case SocketType::UNIX:
                status = session->setupUnixDomainClient(serverConfig.addr.c_str());
                break;
            case SocketType::UNIX_BOOTSTRAP:
                status = session->setupUnixDomainSocketBootstrapClient(
                        base::unique_fd(dup(bootstrapClientFd.get())));
                break;
            case SocketType::VSOCK:
                status = session->setupVsockClient(VMADDR_CID_LOCAL, serverConfig.vsockPort);
                break;
            case SocketType::INET:
                status = session->setupInetClient("127.0.0.1", serverInfo.port);
                break;
            case SocketType::TIPC:
                status = session->setupPreconnectedClient({}, [=]() {
#ifdef BINDER_RPC_TO_TRUSTY_TEST
                    auto port = trustyIpcPort(serverVersion);
                    for (size_t i = 0; i < 5; i++) {
                        // Try to connect several times,
                        // in case the service is slow to start
                        int tipcFd = tipc_connect(kTrustyIpcDevice, port.c_str());
                        if (tipcFd >= 0) {
                            return android::base::unique_fd(tipcFd);
                        }
                        usleep(50000);
                    }
                    return android::base::unique_fd();
#else
                    LOG_ALWAYS_FATAL("Tried to connect to Trusty outside of vendor");
                    return android::base::unique_fd();
#endif
                });
                break;
            default:
                LOG_ALWAYS_FATAL("Unknown socket type");
        }
        if (options.allowConnectFailure && status != OK) {
            ret->sessions.clear();
            break;
        }
        CHECK_EQ(status, OK) << "Could not connect: " << statusToString(status);
        ret->sessions.push_back({session, session->getRootObject()});
    }
    return ret;
}

TEST_P(BinderRpc, ThreadPoolGreaterThanEqualRequested) {
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }

    constexpr size_t kNumThreads = 10;

    auto proc = createRpcTestSocketServerProcess({.numThreads = kNumThreads});

    EXPECT_OK(proc.rootIface->lock());

    // block all but one thread taking locks
    std::vector<std::thread> ts;
    for (size_t i = 0; i < kNumThreads - 1; i++) {
        ts.push_back(std::thread([&] { proc.rootIface->lockUnlock(); }));
    }

    usleep(100000); // give chance for calls on other threads

    // other calls still work
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());

    constexpr size_t blockTimeMs = 100;
    size_t epochMsBefore = epochMillis();
    // after this, we should never see a response within this time
    EXPECT_OK(proc.rootIface->unlockInMsAsync(blockTimeMs));

    // this call should be blocked for blockTimeMs
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());

    size_t epochMsAfter = epochMillis();
    EXPECT_GE(epochMsAfter, epochMsBefore + blockTimeMs) << epochMsBefore;

    for (auto& t : ts) t.join();
}

static void testThreadPoolOverSaturated(sp<IBinderRpcTest> iface, size_t numCalls, size_t sleepMs) {
    size_t epochMsBefore = epochMillis();

    std::vector<std::thread> ts;
    for (size_t i = 0; i < numCalls; i++) {
        ts.push_back(std::thread([&] { iface->sleepMs(sleepMs); }));
    }

    for (auto& t : ts) t.join();

    size_t epochMsAfter = epochMillis();

    EXPECT_GE(epochMsAfter, epochMsBefore + 2 * sleepMs);

    // Potential flake, but make sure calls are handled in parallel. Due
    // to past flakes, this only checks that the amount of time taken has
    // some parallelism. Other tests such as ThreadPoolGreaterThanEqualRequested
    // check this more exactly.
    EXPECT_LE(epochMsAfter, epochMsBefore + (numCalls - 1) * sleepMs);
}

TEST_P(BinderRpc, ThreadPoolOverSaturated) {
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }

    constexpr size_t kNumThreads = 10;
    constexpr size_t kNumCalls = kNumThreads + 3;
    auto proc = createRpcTestSocketServerProcess({.numThreads = kNumThreads});

    // b/272429574 - below 500ms, the test fails
    testThreadPoolOverSaturated(proc.rootIface, kNumCalls, 500 /*ms*/);
}

TEST_P(BinderRpc, ThreadPoolLimitOutgoing) {
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }

    constexpr size_t kNumThreads = 20;
    constexpr size_t kNumOutgoingConnections = 10;
    constexpr size_t kNumCalls = kNumOutgoingConnections + 3;
    auto proc = createRpcTestSocketServerProcess(
            {.numThreads = kNumThreads, .numOutgoingConnections = kNumOutgoingConnections});

    // b/272429574 - below 500ms, the test fails
    testThreadPoolOverSaturated(proc.rootIface, kNumCalls, 500 /*ms*/);
}

TEST_P(BinderRpc, ThreadingStressTest) {
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }

    constexpr size_t kNumClientThreads = 5;
    constexpr size_t kNumServerThreads = 5;
    constexpr size_t kNumCalls = 50;

    auto proc = createRpcTestSocketServerProcess({.numThreads = kNumServerThreads});

    std::vector<std::thread> threads;
    for (size_t i = 0; i < kNumClientThreads; i++) {
        threads.push_back(std::thread([&] {
            for (size_t j = 0; j < kNumCalls; j++) {
                sp<IBinder> out;
                EXPECT_OK(proc.rootIface->repeatBinder(proc.rootBinder, &out));
                EXPECT_EQ(proc.rootBinder, out);
            }
        }));
    }

    for (auto& t : threads) t.join();
}

static void saturateThreadPool(size_t threadCount, const sp<IBinderRpcTest>& iface) {
    std::vector<std::thread> threads;
    for (size_t i = 0; i < threadCount; i++) {
        threads.push_back(std::thread([&] { EXPECT_OK(iface->sleepMs(500)); }));
    }
    for (auto& t : threads) t.join();
}

TEST_P(BinderRpc, OnewayStressTest) {
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }

    constexpr size_t kNumClientThreads = 10;
    constexpr size_t kNumServerThreads = 10;
    constexpr size_t kNumCalls = 1000;

    auto proc = createRpcTestSocketServerProcess({.numThreads = kNumServerThreads});

    std::vector<std::thread> threads;
    for (size_t i = 0; i < kNumClientThreads; i++) {
        threads.push_back(std::thread([&] {
            for (size_t j = 0; j < kNumCalls; j++) {
                EXPECT_OK(proc.rootIface->sendString("a"));
            }
        }));
    }

    for (auto& t : threads) t.join();

    saturateThreadPool(kNumServerThreads, proc.rootIface);
}

TEST_P(BinderRpc, OnewayCallQueueingWithFds) {
    if (!supportsFdTransport()) {
        GTEST_SKIP() << "Would fail trivially (which is tested elsewhere)";
    }
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }

    constexpr size_t kNumServerThreads = 3;

    // This test forces a oneway transaction to be queued by issuing two
    // `blockingSendFdOneway` calls, then drains the queue by issuing two
    // `blockingRecvFd` calls.
    //
    // For more details about the queuing semantics see
    // https://developer.android.com/reference/android/os/IBinder#FLAG_ONEWAY

    auto proc = createRpcTestSocketServerProcess({
            .numThreads = kNumServerThreads,
            .clientFileDescriptorTransportMode = RpcSession::FileDescriptorTransportMode::UNIX,
            .serverSupportedFileDescriptorTransportModes =
                    {RpcSession::FileDescriptorTransportMode::UNIX},
    });

    EXPECT_OK(proc.rootIface->blockingSendFdOneway(
            android::os::ParcelFileDescriptor(mockFileDescriptor("a"))));
    EXPECT_OK(proc.rootIface->blockingSendFdOneway(
            android::os::ParcelFileDescriptor(mockFileDescriptor("b"))));

    android::os::ParcelFileDescriptor fdA;
    EXPECT_OK(proc.rootIface->blockingRecvFd(&fdA));
    std::string result;
    CHECK(android::base::ReadFdToString(fdA.get(), &result));
    EXPECT_EQ(result, "a");

    android::os::ParcelFileDescriptor fdB;
    EXPECT_OK(proc.rootIface->blockingRecvFd(&fdB));
    CHECK(android::base::ReadFdToString(fdB.get(), &result));
    EXPECT_EQ(result, "b");

    saturateThreadPool(kNumServerThreads, proc.rootIface);
}

TEST_P(BinderRpc, OnewayCallQueueing) {
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }

    constexpr size_t kNumQueued = 10;
    constexpr size_t kNumExtraServerThreads = 4;

    // make sure calls to the same object happen on the same thread
    auto proc = createRpcTestSocketServerProcess({.numThreads = 1 + kNumExtraServerThreads});

    // all these *Oneway commands should be queued on the server sequentially,
    // even though there are multiple threads.
    for (size_t i = 0; i + 1 < kNumQueued; i++) {
        proc.rootIface->blockingSendIntOneway(i);
    }
    for (size_t i = 0; i + 1 < kNumQueued; i++) {
        int n;
        proc.rootIface->blockingRecvInt(&n);
        EXPECT_EQ(n, i);
    }

    saturateThreadPool(1 + kNumExtraServerThreads, proc.rootIface);
}

TEST_P(BinderRpc, OnewayCallExhaustion) {
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }

    constexpr size_t kNumClients = 2;
    constexpr size_t kTooLongMs = 1000;

    auto proc = createRpcTestSocketServerProcess({.numThreads = kNumClients, .numSessions = 2});

    // Build up oneway calls on the second session to make sure it terminates
    // and shuts down. The first session should be unaffected (proc destructor
    // checks the first session).
    auto iface = interface_cast<IBinderRpcTest>(proc.proc->sessions.at(1).root);

    std::vector<std::thread> threads;
    for (size_t i = 0; i < kNumClients; i++) {
        // one of these threads will get stuck queueing a transaction once the
        // socket fills up, the other will be able to fill up transactions on
        // this object
        threads.push_back(std::thread([&] {
            while (iface->sleepMsAsync(kTooLongMs).isOk()) {
            }
        }));
    }
    for (auto& t : threads) t.join();

    Status status = iface->sleepMsAsync(kTooLongMs);
    EXPECT_EQ(DEAD_OBJECT, status.transactionError()) << status;

    // now that it has died, wait for the remote session to shutdown
    std::vector<int32_t> remoteCounts;
    do {
        EXPECT_OK(proc.rootIface->countBinders(&remoteCounts));
    } while (remoteCounts.size() == kNumClients);

    // the second session should be shutdown in the other process by the time we
    // are able to join above (it'll only be hung up once it finishes processing
    // any pending commands). We need to erase this session from the record
    // here, so that the destructor for our session won't check that this
    // session is valid, but we still want it to test the other session.
    proc.proc->sessions.erase(proc.proc->sessions.begin() + 1);
}

TEST_P(BinderRpc, SessionWithIncomingThreadpoolDoesntLeak) {
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }

    // session 0 - will check for leaks in destrutor of proc
    // session 1 - we want to make sure it gets deleted when we drop all references to it
    auto proc = createRpcTestSocketServerProcess(
            {.numThreads = 1, .numSessions = 2, .numIncomingConnectionsBySession = {0, 1}});

    wp<RpcSession> session = proc.proc->sessions.at(1).session;

    // remove all references to the second session
    proc.proc->sessions.at(1).root = nullptr;
    proc.proc->sessions.erase(proc.proc->sessions.begin() + 1);

    // TODO(b/271830568) more efficient way to wait for other incoming threadpool
    // to drain commands.
    for (size_t i = 0; i < 100; i++) {
        usleep(10 * 1000);
        if (session.promote() == nullptr) break;
    }

    EXPECT_EQ(nullptr, session.promote());

    // now that it has died, wait for the remote session to shutdown
    std::vector<int32_t> remoteCounts;
    do {
        EXPECT_OK(proc.rootIface->countBinders(&remoteCounts));
    } while (remoteCounts.size() > 1);
}

TEST_P(BinderRpc, SingleDeathRecipient) {
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }
    class MyDeathRec : public IBinder::DeathRecipient {
    public:
        void binderDied(const wp<IBinder>& /* who */) override {
            dead = true;
            mCv.notify_one();
        }
        std::mutex mMtx;
        std::condition_variable mCv;
        bool dead = false;
    };

    // Death recipient needs to have an incoming connection to be called
    auto proc = createRpcTestSocketServerProcess(
            {.numThreads = 1, .numSessions = 1, .numIncomingConnectionsBySession = {1}});

    auto dr = sp<MyDeathRec>::make();
    ASSERT_EQ(OK, proc.rootBinder->linkToDeath(dr, (void*)1, 0));

    if (auto status = proc.rootIface->scheduleShutdown(); !status.isOk()) {
        EXPECT_EQ(DEAD_OBJECT, status.transactionError()) << status;
    }

    std::unique_lock<std::mutex> lock(dr->mMtx);
    ASSERT_TRUE(dr->mCv.wait_for(lock, 100ms, [&]() { return dr->dead; }));

    // need to wait for the session to shutdown so we don't "Leak session"
    // can't do this before checking the death recipient by calling
    // forceShutdown earlier, because shutdownAndWait will also trigger
    // a death recipient, but if we had a way to wait for the service
    // to gracefully shutdown, we could use that here.
    EXPECT_TRUE(proc.proc->sessions.at(0).session->shutdownAndWait(true));
    proc.expectAlreadyShutdown = true;
}

TEST_P(BinderRpc, SingleDeathRecipientOnShutdown) {
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }
    class MyDeathRec : public IBinder::DeathRecipient {
    public:
        void binderDied(const wp<IBinder>& /* who */) override {
            dead = true;
            mCv.notify_one();
        }
        std::mutex mMtx;
        std::condition_variable mCv;
        bool dead = false;
    };

    // Death recipient needs to have an incoming connection to be called
    auto proc = createRpcTestSocketServerProcess(
            {.numThreads = 1, .numSessions = 1, .numIncomingConnectionsBySession = {1}});

    auto dr = sp<MyDeathRec>::make();
    EXPECT_EQ(OK, proc.rootBinder->linkToDeath(dr, (void*)1, 0));

    // Explicitly calling shutDownAndWait will cause the death recipients
    // to be called.
    EXPECT_TRUE(proc.proc->sessions.at(0).session->shutdownAndWait(true));

    std::unique_lock<std::mutex> lock(dr->mMtx);
    if (!dr->dead) {
        EXPECT_EQ(std::cv_status::no_timeout, dr->mCv.wait_for(lock, 100ms));
    }
    EXPECT_TRUE(dr->dead) << "Failed to receive the death notification.";

    proc.proc->terminate();
    proc.proc->setCustomExitStatusCheck([](int wstatus) {
        EXPECT_TRUE(WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGTERM)
                << "server process failed incorrectly: " << WaitStatusToString(wstatus);
    });
    proc.expectAlreadyShutdown = true;
}

TEST_P(BinderRpc, DeathRecipientFailsWithoutIncoming) {
    if (socketType() == SocketType::TIPC) {
        // This should work, but Trusty takes too long to restart the service
        GTEST_SKIP() << "Service death test not supported on Trusty";
    }
    class MyDeathRec : public IBinder::DeathRecipient {
    public:
        void binderDied(const wp<IBinder>& /* who */) override {}
    };

    auto proc = createRpcTestSocketServerProcess({.numThreads = 1, .numSessions = 1});

    auto dr = sp<MyDeathRec>::make();
    EXPECT_EQ(INVALID_OPERATION, proc.rootBinder->linkToDeath(dr, (void*)1, 0));
}

TEST_P(BinderRpc, UnlinkDeathRecipient) {
    if (clientOrServerSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }
    class MyDeathRec : public IBinder::DeathRecipient {
    public:
        void binderDied(const wp<IBinder>& /* who */) override {
            GTEST_FAIL() << "This should not be called after unlinkToDeath";
        }
    };

    // Death recipient needs to have an incoming connection to be called
    auto proc = createRpcTestSocketServerProcess(
            {.numThreads = 1, .numSessions = 1, .numIncomingConnectionsBySession = {1}});

    auto dr = sp<MyDeathRec>::make();
    ASSERT_EQ(OK, proc.rootBinder->linkToDeath(dr, (void*)1, 0));
    ASSERT_EQ(OK, proc.rootBinder->unlinkToDeath(dr, (void*)1, 0, nullptr));

    proc.forceShutdown();
}

TEST_P(BinderRpc, Die) {
    if (socketType() == SocketType::TIPC) {
        // This should work, but Trusty takes too long to restart the service
        GTEST_SKIP() << "Service death test not supported on Trusty";
    }

    for (bool doDeathCleanup : {true, false}) {
        auto proc = createRpcTestSocketServerProcess({});

        // make sure there is some state during crash
        // 1. we hold their binder
        sp<IBinderRpcSession> session;
        EXPECT_OK(proc.rootIface->openSession("happy", &session));
        // 2. they hold our binder
        sp<IBinder> binder = new BBinder();
        EXPECT_OK(proc.rootIface->holdBinder(binder));

        EXPECT_EQ(DEAD_OBJECT, proc.rootIface->die(doDeathCleanup).transactionError())
                << "Do death cleanup: " << doDeathCleanup;

        proc.proc->setCustomExitStatusCheck([](int wstatus) {
            EXPECT_TRUE(WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 1)
                    << "server process failed incorrectly: " << WaitStatusToString(wstatus);
        });
        proc.expectAlreadyShutdown = true;
    }
}

TEST_P(BinderRpc, UseKernelBinderCallingId) {
    // This test only works if the current process shared the internal state of
    // ProcessState with the service across the call to fork(). Both the static
    // libraries and libbinder.so have their own separate copies of all the
    // globals, so the test only works when the test client and service both use
    // libbinder.so (when using static libraries, even a client and service
    // using the same kind of static library should have separate copies of the
    // variables).
    if (!kEnableSharedLibs || serverSingleThreaded() || noKernel()) {
        GTEST_SKIP() << "Test disabled because Binder kernel driver was disabled "
                        "at build time.";
    }

    auto proc = createRpcTestSocketServerProcess({});

    // we can't allocate IPCThreadState so actually the first time should
    // succeed :(
    EXPECT_OK(proc.rootIface->useKernelBinderCallingId());

    // second time! we catch the error :)
    EXPECT_EQ(DEAD_OBJECT, proc.rootIface->useKernelBinderCallingId().transactionError());

    proc.proc->setCustomExitStatusCheck([](int wstatus) {
        EXPECT_TRUE(WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGABRT)
                << "server process failed incorrectly: " << WaitStatusToString(wstatus);
    });
    proc.expectAlreadyShutdown = true;
}

TEST_P(BinderRpc, FileDescriptorTransportRejectNone) {
    if (socketType() == SocketType::TIPC) {
        GTEST_SKIP() << "File descriptor tests not supported on Trusty (yet)";
    }

    auto proc = createRpcTestSocketServerProcess({
            .clientFileDescriptorTransportMode = RpcSession::FileDescriptorTransportMode::NONE,
            .serverSupportedFileDescriptorTransportModes =
                    {RpcSession::FileDescriptorTransportMode::UNIX},
            .allowConnectFailure = true,
    });
    EXPECT_TRUE(proc.proc->sessions.empty()) << "session connections should have failed";
    proc.proc->terminate();
    proc.proc->setCustomExitStatusCheck([](int wstatus) {
        EXPECT_TRUE(WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGTERM)
                << "server process failed incorrectly: " << WaitStatusToString(wstatus);
    });
    proc.expectAlreadyShutdown = true;
}

TEST_P(BinderRpc, FileDescriptorTransportRejectUnix) {
    if (socketType() == SocketType::TIPC) {
        GTEST_SKIP() << "File descriptor tests not supported on Trusty (yet)";
    }

    auto proc = createRpcTestSocketServerProcess({
            .clientFileDescriptorTransportMode = RpcSession::FileDescriptorTransportMode::UNIX,
            .serverSupportedFileDescriptorTransportModes =
                    {RpcSession::FileDescriptorTransportMode::NONE},
            .allowConnectFailure = true,
    });
    EXPECT_TRUE(proc.proc->sessions.empty()) << "session connections should have failed";
    proc.proc->terminate();
    proc.proc->setCustomExitStatusCheck([](int wstatus) {
        EXPECT_TRUE(WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGTERM)
                << "server process failed incorrectly: " << WaitStatusToString(wstatus);
    });
    proc.expectAlreadyShutdown = true;
}

TEST_P(BinderRpc, FileDescriptorTransportOptionalUnix) {
    if (socketType() == SocketType::TIPC) {
        GTEST_SKIP() << "File descriptor tests not supported on Trusty (yet)";
    }

    auto proc = createRpcTestSocketServerProcess({
            .clientFileDescriptorTransportMode = RpcSession::FileDescriptorTransportMode::NONE,
            .serverSupportedFileDescriptorTransportModes =
                    {RpcSession::FileDescriptorTransportMode::NONE,
                     RpcSession::FileDescriptorTransportMode::UNIX},
    });

    android::os::ParcelFileDescriptor out;
    auto status = proc.rootIface->echoAsFile("hello", &out);
    EXPECT_EQ(status.transactionError(), FDS_NOT_ALLOWED) << status;
}

TEST_P(BinderRpc, ReceiveFile) {
    if (socketType() == SocketType::TIPC) {
        GTEST_SKIP() << "File descriptor tests not supported on Trusty (yet)";
    }

    auto proc = createRpcTestSocketServerProcess({
            .clientFileDescriptorTransportMode = RpcSession::FileDescriptorTransportMode::UNIX,
            .serverSupportedFileDescriptorTransportModes =
                    {RpcSession::FileDescriptorTransportMode::UNIX},
    });

    android::os::ParcelFileDescriptor out;
    auto status = proc.rootIface->echoAsFile("hello", &out);
    if (!supportsFdTransport()) {
        EXPECT_EQ(status.transactionError(), BAD_VALUE) << status;
        return;
    }
    ASSERT_TRUE(status.isOk()) << status;

    std::string result;
    CHECK(android::base::ReadFdToString(out.get(), &result));
    EXPECT_EQ(result, "hello");
}

TEST_P(BinderRpc, SendFiles) {
    if (socketType() == SocketType::TIPC) {
        GTEST_SKIP() << "File descriptor tests not supported on Trusty (yet)";
    }

    auto proc = createRpcTestSocketServerProcess({
            .clientFileDescriptorTransportMode = RpcSession::FileDescriptorTransportMode::UNIX,
            .serverSupportedFileDescriptorTransportModes =
                    {RpcSession::FileDescriptorTransportMode::UNIX},
    });

    std::vector<android::os::ParcelFileDescriptor> files;
    files.emplace_back(android::os::ParcelFileDescriptor(mockFileDescriptor("123")));
    files.emplace_back(android::os::ParcelFileDescriptor(mockFileDescriptor("a")));
    files.emplace_back(android::os::ParcelFileDescriptor(mockFileDescriptor("b")));
    files.emplace_back(android::os::ParcelFileDescriptor(mockFileDescriptor("cd")));

    android::os::ParcelFileDescriptor out;
    auto status = proc.rootIface->concatFiles(files, &out);
    if (!supportsFdTransport()) {
        EXPECT_EQ(status.transactionError(), BAD_VALUE) << status;
        return;
    }
    ASSERT_TRUE(status.isOk()) << status;

    std::string result;
    CHECK(android::base::ReadFdToString(out.get(), &result));
    EXPECT_EQ(result, "123abcd");
}

TEST_P(BinderRpc, SendMaxFiles) {
    if (!supportsFdTransport()) {
        GTEST_SKIP() << "Would fail trivially (which is tested by BinderRpc::SendFiles)";
    }

    auto proc = createRpcTestSocketServerProcess({
            .clientFileDescriptorTransportMode = RpcSession::FileDescriptorTransportMode::UNIX,
            .serverSupportedFileDescriptorTransportModes =
                    {RpcSession::FileDescriptorTransportMode::UNIX},
    });

    std::vector<android::os::ParcelFileDescriptor> files;
    for (int i = 0; i < 253; i++) {
        files.emplace_back(android::os::ParcelFileDescriptor(mockFileDescriptor("a")));
    }

    android::os::ParcelFileDescriptor out;
    auto status = proc.rootIface->concatFiles(files, &out);
    ASSERT_TRUE(status.isOk()) << status;

    std::string result;
    CHECK(android::base::ReadFdToString(out.get(), &result));
    EXPECT_EQ(result, std::string(253, 'a'));
}

TEST_P(BinderRpc, SendTooManyFiles) {
    if (!supportsFdTransport()) {
        GTEST_SKIP() << "Would fail trivially (which is tested by BinderRpc::SendFiles)";
    }

    auto proc = createRpcTestSocketServerProcess({
            .clientFileDescriptorTransportMode = RpcSession::FileDescriptorTransportMode::UNIX,
            .serverSupportedFileDescriptorTransportModes =
                    {RpcSession::FileDescriptorTransportMode::UNIX},
    });

    std::vector<android::os::ParcelFileDescriptor> files;
    for (int i = 0; i < 254; i++) {
        files.emplace_back(android::os::ParcelFileDescriptor(mockFileDescriptor("a")));
    }

    android::os::ParcelFileDescriptor out;
    auto status = proc.rootIface->concatFiles(files, &out);
    EXPECT_EQ(status.transactionError(), BAD_VALUE) << status;
}

TEST_P(BinderRpc, AppendInvalidFd) {
    if (socketType() == SocketType::TIPC) {
        GTEST_SKIP() << "File descriptor tests not supported on Trusty (yet)";
    }

    auto proc = createRpcTestSocketServerProcess({
            .clientFileDescriptorTransportMode = RpcSession::FileDescriptorTransportMode::UNIX,
            .serverSupportedFileDescriptorTransportModes =
                    {RpcSession::FileDescriptorTransportMode::UNIX},
    });

    int badFd = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 0);
    ASSERT_NE(badFd, -1);

    // Close the file descriptor so it becomes invalid for dup
    close(badFd);

    Parcel p1;
    p1.markForBinder(proc.rootBinder);
    p1.writeInt32(3);
    EXPECT_EQ(OK, p1.writeFileDescriptor(badFd, false));

    Parcel pRaw;
    pRaw.markForBinder(proc.rootBinder);
    EXPECT_EQ(OK, pRaw.appendFrom(&p1, 0, p1.dataSize()));

    pRaw.setDataPosition(0);
    EXPECT_EQ(3, pRaw.readInt32());
    ASSERT_EQ(-1, pRaw.readFileDescriptor());
}

#ifndef __ANDROID_VENDOR__ // No AIBinder_fromPlatformBinder on vendor
TEST_P(BinderRpc, WorksWithLibbinderNdkPing) {
    if constexpr (!kEnableSharedLibs) {
        GTEST_SKIP() << "Test disabled because Binder was built as a static library";
    }

    auto proc = createRpcTestSocketServerProcess({});

    ndk::SpAIBinder binder = ndk::SpAIBinder(AIBinder_fromPlatformBinder(proc.rootBinder));
    ASSERT_NE(binder, nullptr);

    ASSERT_EQ(STATUS_OK, AIBinder_ping(binder.get()));
}

TEST_P(BinderRpc, WorksWithLibbinderNdkUserTransaction) {
    if constexpr (!kEnableSharedLibs) {
        GTEST_SKIP() << "Test disabled because Binder was built as a static library";
    }

    auto proc = createRpcTestSocketServerProcess({});

    ndk::SpAIBinder binder = ndk::SpAIBinder(AIBinder_fromPlatformBinder(proc.rootBinder));
    ASSERT_NE(binder, nullptr);

    auto ndkBinder = aidl::IBinderRpcTest::fromBinder(binder);
    ASSERT_NE(ndkBinder, nullptr);

    std::string out;
    ndk::ScopedAStatus status = ndkBinder->doubleString("aoeu", &out);
    ASSERT_TRUE(status.isOk()) << status.getDescription();
    ASSERT_EQ("aoeuaoeu", out);
}
#endif // __ANDROID_VENDOR__

ssize_t countFds() {
    DIR* dir = opendir("/proc/self/fd/");
    if (dir == nullptr) return -1;
    ssize_t ret = 0;
    dirent* ent;
    while ((ent = readdir(dir)) != nullptr) ret++;
    closedir(dir);
    return ret;
}

TEST_P(BinderRpc, Fds) {
    if (serverSingleThreaded()) {
        GTEST_SKIP() << "This test requires multiple threads";
    }
    if (socketType() == SocketType::TIPC) {
        GTEST_SKIP() << "File descriptor tests not supported on Trusty (yet)";
    }

    ssize_t beforeFds = countFds();
    ASSERT_GE(beforeFds, 0);
    {
        auto proc = createRpcTestSocketServerProcess({.numThreads = 10});
        ASSERT_EQ(OK, proc.rootBinder->pingBinder());
    }
    ASSERT_EQ(beforeFds, countFds()) << (system("ls -l /proc/self/fd/"), "fd leak?");
}

#ifdef BINDER_RPC_TO_TRUSTY_TEST

static std::vector<BinderRpc::ParamType> getTrustyBinderRpcParams() {
    std::vector<BinderRpc::ParamType> ret;

    for (const auto& clientVersion : testVersions()) {
        for (const auto& serverVersion : testVersions()) {
            ret.push_back(BinderRpc::ParamType{
                    .type = SocketType::TIPC,
                    .security = RpcSecurity::RAW,
                    .clientVersion = clientVersion,
                    .serverVersion = serverVersion,
                    .singleThreaded = true,
                    .noKernel = true,
            });
        }
    }

    return ret;
}

INSTANTIATE_TEST_CASE_P(Trusty, BinderRpc, ::testing::ValuesIn(getTrustyBinderRpcParams()),
                        BinderRpc::PrintParamInfo);
#else // BINDER_RPC_TO_TRUSTY_TEST
bool testSupportVsockLoopback() {
    // We don't need to enable TLS to know if vsock is supported.
    unsigned int vsockPort = allocateVsockPort();

    android::base::unique_fd serverFd(
            TEMP_FAILURE_RETRY(socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)));

    if (errno == EAFNOSUPPORT) {
        return false;
    }

    LOG_ALWAYS_FATAL_IF(serverFd == -1, "Could not create socket: %s", strerror(errno));

    sockaddr_vm serverAddr{
            .svm_family = AF_VSOCK,
            .svm_port = vsockPort,
            .svm_cid = VMADDR_CID_ANY,
    };
    int ret = TEMP_FAILURE_RETRY(
            bind(serverFd.get(), reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)));
    LOG_ALWAYS_FATAL_IF(0 != ret, "Could not bind socket to port %u: %s", vsockPort,
                        strerror(errno));

    ret = TEMP_FAILURE_RETRY(listen(serverFd.get(), 1 /*backlog*/));
    LOG_ALWAYS_FATAL_IF(0 != ret, "Could not listen socket on port %u: %s", vsockPort,
                        strerror(errno));

    // Try to connect to the server using the VMADDR_CID_LOCAL cid
    // to see if the kernel supports it. It's safe to use a blocking
    // connect because vsock sockets have a 2 second connection timeout,
    // and they return ETIMEDOUT after that.
    android::base::unique_fd connectFd(
            TEMP_FAILURE_RETRY(socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)));
    LOG_ALWAYS_FATAL_IF(connectFd == -1, "Could not create socket for port %u: %s", vsockPort,
                        strerror(errno));

    bool success = false;
    sockaddr_vm connectAddr{
            .svm_family = AF_VSOCK,
            .svm_port = vsockPort,
            .svm_cid = VMADDR_CID_LOCAL,
    };
    ret = TEMP_FAILURE_RETRY(connect(connectFd.get(), reinterpret_cast<sockaddr*>(&connectAddr),
                                     sizeof(connectAddr)));
    if (ret != 0 && (errno == EAGAIN || errno == EINPROGRESS)) {
        android::base::unique_fd acceptFd;
        while (true) {
            pollfd pfd[]{
                    {.fd = serverFd.get(), .events = POLLIN, .revents = 0},
                    {.fd = connectFd.get(), .events = POLLOUT, .revents = 0},
            };
            ret = TEMP_FAILURE_RETRY(poll(pfd, arraysize(pfd), -1));
            LOG_ALWAYS_FATAL_IF(ret < 0, "Error polling: %s", strerror(errno));

            if (pfd[0].revents & POLLIN) {
                sockaddr_vm acceptAddr;
                socklen_t acceptAddrLen = sizeof(acceptAddr);
                ret = TEMP_FAILURE_RETRY(accept4(serverFd.get(),
                                                 reinterpret_cast<sockaddr*>(&acceptAddr),
                                                 &acceptAddrLen, SOCK_CLOEXEC));
                LOG_ALWAYS_FATAL_IF(ret < 0, "Could not accept4 socket: %s", strerror(errno));
                LOG_ALWAYS_FATAL_IF(acceptAddrLen != static_cast<socklen_t>(sizeof(acceptAddr)),
                                    "Truncated address");

                // Store the fd in acceptFd so we keep the connection alive
                // while polling connectFd
                acceptFd.reset(ret);
            }

            if (pfd[1].revents & POLLOUT) {
                // Connect either succeeded or timed out
                int connectErrno;
                socklen_t connectErrnoLen = sizeof(connectErrno);
                int ret = getsockopt(connectFd.get(), SOL_SOCKET, SO_ERROR, &connectErrno,
                                     &connectErrnoLen);
                LOG_ALWAYS_FATAL_IF(ret == -1,
                                    "Could not getsockopt() after connect() "
                                    "on non-blocking socket: %s.",
                                    strerror(errno));

                // We're done, this is all we wanted
                success = connectErrno == 0;
                break;
            }
        }
    } else {
        success = ret == 0;
    }

    ALOGE("Detected vsock loopback supported: %s", success ? "yes" : "no");

    return success;
}

static std::vector<SocketType> testSocketTypes(bool hasPreconnected = true) {
    std::vector<SocketType> ret = {SocketType::UNIX, SocketType::UNIX_BOOTSTRAP, SocketType::INET,
                                   SocketType::UNIX_RAW};

    if (hasPreconnected) ret.push_back(SocketType::PRECONNECTED);

#ifdef __BIONIC__
    // Devices may not have vsock support. AVF tests will verify whether they do, but
    // we can't require it due to old kernels for the time being.
    static bool hasVsockLoopback = testSupportVsockLoopback();
#else
    // On host machines, we always assume we have vsock loopback. If we don't, the
    // subsequent failures will be more clear than showing one now.
    static bool hasVsockLoopback = true;
#endif

    if (hasVsockLoopback) {
        ret.push_back(SocketType::VSOCK);
    }

    return ret;
}

static std::vector<BinderRpc::ParamType> getBinderRpcParams() {
    std::vector<BinderRpc::ParamType> ret;

    constexpr bool full = false;

    for (const auto& type : testSocketTypes()) {
        if (full || type == SocketType::UNIX) {
            for (const auto& security : RpcSecurityValues()) {
                for (const auto& clientVersion : testVersions()) {
                    for (const auto& serverVersion : testVersions()) {
                        for (bool singleThreaded : {false, true}) {
                            for (bool noKernel : {false, true}) {
                                ret.push_back(BinderRpc::ParamType{
                                        .type = type,
                                        .security = security,
                                        .clientVersion = clientVersion,
                                        .serverVersion = serverVersion,
                                        .singleThreaded = singleThreaded,
                                        .noKernel = noKernel,
                                });
                            }
                        }
                    }
                }
            }
        } else {
            ret.push_back(BinderRpc::ParamType{
                    .type = type,
                    .security = RpcSecurity::RAW,
                    .clientVersion = RPC_WIRE_PROTOCOL_VERSION,
                    .serverVersion = RPC_WIRE_PROTOCOL_VERSION,
                    .singleThreaded = false,
                    .noKernel = false,
            });
        }
    }

    return ret;
}

INSTANTIATE_TEST_CASE_P(PerSocket, BinderRpc, ::testing::ValuesIn(getBinderRpcParams()),
                        BinderRpc::PrintParamInfo);

class BinderRpcServerRootObject
      : public ::testing::TestWithParam<std::tuple<bool, bool, RpcSecurity>> {};

TEST_P(BinderRpcServerRootObject, WeakRootObject) {
    using SetFn = std::function<void(RpcServer*, sp<IBinder>)>;
    auto setRootObject = [](bool isStrong) -> SetFn {
        return isStrong ? SetFn(&RpcServer::setRootObject) : SetFn(&RpcServer::setRootObjectWeak);
    };

    auto [isStrong1, isStrong2, rpcSecurity] = GetParam();
    auto server = RpcServer::make(newTlsFactory(rpcSecurity));
    auto binder1 = sp<BBinder>::make();
    IBinder* binderRaw1 = binder1.get();
    setRootObject(isStrong1)(server.get(), binder1);
    EXPECT_EQ(binderRaw1, server->getRootObject());
    binder1.clear();
    EXPECT_EQ((isStrong1 ? binderRaw1 : nullptr), server->getRootObject());

    auto binder2 = sp<BBinder>::make();
    IBinder* binderRaw2 = binder2.get();
    setRootObject(isStrong2)(server.get(), binder2);
    EXPECT_EQ(binderRaw2, server->getRootObject());
    binder2.clear();
    EXPECT_EQ((isStrong2 ? binderRaw2 : nullptr), server->getRootObject());
}

INSTANTIATE_TEST_CASE_P(BinderRpc, BinderRpcServerRootObject,
                        ::testing::Combine(::testing::Bool(), ::testing::Bool(),
                                           ::testing::ValuesIn(RpcSecurityValues())));

class OneOffSignal {
public:
    // If notify() was previously called, or is called within |duration|, return true; else false.
    template <typename R, typename P>
    bool wait(std::chrono::duration<R, P> duration) {
        std::unique_lock<std::mutex> lock(mMutex);
        return mCv.wait_for(lock, duration, [this] { return mValue; });
    }
    void notify() {
        std::unique_lock<std::mutex> lock(mMutex);
        mValue = true;
        lock.unlock();
        mCv.notify_all();
    }

private:
    std::mutex mMutex;
    std::condition_variable mCv;
    bool mValue = false;
};

TEST(BinderRpc, Java) {
#if !defined(__ANDROID__)
    GTEST_SKIP() << "This test is only run on Android. Though it can technically run on host on"
                    "createRpcDelegateServiceManager() with a device attached, such test belongs "
                    "to binderHostDeviceTest. Hence, just disable this test on host.";
#endif // !__ANDROID__
    if constexpr (!kEnableKernelIpc) {
        GTEST_SKIP() << "Test disabled because Binder kernel driver was disabled "
                        "at build time.";
    }

    sp<IServiceManager> sm = defaultServiceManager();
    ASSERT_NE(nullptr, sm);
    // Any Java service with non-empty getInterfaceDescriptor() would do.
    // Let's pick batteryproperties.
    auto binder = sm->checkService(String16("batteryproperties"));
    ASSERT_NE(nullptr, binder);
    auto descriptor = binder->getInterfaceDescriptor();
    ASSERT_GE(descriptor.size(), 0);
    ASSERT_EQ(OK, binder->pingBinder());

    auto rpcServer = RpcServer::make();
    unsigned int port;
    ASSERT_EQ(OK, rpcServer->setupInetServer(kLocalInetAddress, 0, &port));
    auto socket = rpcServer->releaseServer();

    auto keepAlive = sp<BBinder>::make();
    auto setRpcClientDebugStatus = binder->setRpcClientDebug(std::move(socket), keepAlive);

    if (!android::base::GetBoolProperty("ro.debuggable", false) ||
        android::base::GetProperty("ro.build.type", "") == "user") {
        ASSERT_EQ(INVALID_OPERATION, setRpcClientDebugStatus)
                << "setRpcClientDebug should return INVALID_OPERATION on non-debuggable or user "
                   "builds, but get "
                << statusToString(setRpcClientDebugStatus);
        GTEST_SKIP();
    }

    ASSERT_EQ(OK, setRpcClientDebugStatus);

    auto rpcSession = RpcSession::make();
    ASSERT_EQ(OK, rpcSession->setupInetClient("127.0.0.1", port));
    auto rpcBinder = rpcSession->getRootObject();
    ASSERT_NE(nullptr, rpcBinder);

    ASSERT_EQ(OK, rpcBinder->pingBinder());

    ASSERT_EQ(descriptor, rpcBinder->getInterfaceDescriptor())
            << "getInterfaceDescriptor should not crash system_server";
    ASSERT_EQ(OK, rpcBinder->pingBinder());
}

class BinderRpcServerOnly : public ::testing::TestWithParam<std::tuple<RpcSecurity, uint32_t>> {
public:
    static std::string PrintTestParam(const ::testing::TestParamInfo<ParamType>& info) {
        return std::string(newTlsFactory(std::get<0>(info.param))->toCString()) + "_serverV" +
                std::to_string(std::get<1>(info.param));
    }
};

TEST_P(BinderRpcServerOnly, SetExternalServerTest) {
    base::unique_fd sink(TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR)));
    int sinkFd = sink.get();
    auto server = RpcServer::make(newTlsFactory(std::get<0>(GetParam())));
    ASSERT_TRUE(server->setProtocolVersion(std::get<1>(GetParam())));
    ASSERT_FALSE(server->hasServer());
    ASSERT_EQ(OK, server->setupExternalServer(std::move(sink)));
    ASSERT_TRUE(server->hasServer());
    base::unique_fd retrieved = server->releaseServer();
    ASSERT_FALSE(server->hasServer());
    ASSERT_EQ(sinkFd, retrieved.get());
}

TEST_P(BinderRpcServerOnly, Shutdown) {
    if constexpr (!kEnableRpcThreads) {
        GTEST_SKIP() << "Test skipped because threads were disabled at build time";
    }

    auto addr = allocateSocketAddress();
    auto server = RpcServer::make(newTlsFactory(std::get<0>(GetParam())));
    ASSERT_TRUE(server->setProtocolVersion(std::get<1>(GetParam())));
    ASSERT_EQ(OK, server->setupUnixDomainServer(addr.c_str()));
    auto joinEnds = std::make_shared<OneOffSignal>();

    // If things are broken and the thread never stops, don't block other tests. Because the thread
    // may run after the test finishes, it must not access the stack memory of the test. Hence,
    // shared pointers are passed.
    std::thread([server, joinEnds] {
        server->join();
        joinEnds->notify();
    }).detach();

    bool shutdown = false;
    for (int i = 0; i < 10 && !shutdown; i++) {
        usleep(30 * 1000); // 30ms; total 300ms
        if (server->shutdown()) shutdown = true;
    }
    ASSERT_TRUE(shutdown) << "server->shutdown() never returns true";

    ASSERT_TRUE(joinEnds->wait(2s))
            << "After server->shutdown() returns true, join() did not stop after 2s";
}

INSTANTIATE_TEST_CASE_P(BinderRpc, BinderRpcServerOnly,
                        ::testing::Combine(::testing::ValuesIn(RpcSecurityValues()),
                                           ::testing::ValuesIn(testVersions())),
                        BinderRpcServerOnly::PrintTestParam);

class RpcTransportTestUtils {
public:
    // Only parameterized only server version because `RpcSession` is bypassed
    // in the client half of the tests.
    using Param =
            std::tuple<SocketType, RpcSecurity, std::optional<RpcCertificateFormat>, uint32_t>;
    using ConnectToServer = std::function<base::unique_fd()>;

    // A server that handles client socket connections.
    class Server {
    public:
        using AcceptConnection = std::function<base::unique_fd(Server*)>;

        explicit Server() {}
        Server(Server&&) = default;
        ~Server() { shutdownAndWait(); }
        [[nodiscard]] AssertionResult setUp(
                const Param& param,
                std::unique_ptr<RpcAuth> auth = std::make_unique<RpcAuthSelfSigned>()) {
            auto [socketType, rpcSecurity, certificateFormat, serverVersion] = param;
            auto rpcServer = RpcServer::make(newTlsFactory(rpcSecurity));
            if (!rpcServer->setProtocolVersion(serverVersion)) {
                return AssertionFailure() << "Invalid protocol version: " << serverVersion;
            }
            switch (socketType) {
                case SocketType::PRECONNECTED: {
                    return AssertionFailure() << "Not supported by this test";
                } break;
                case SocketType::UNIX: {
                    auto addr = allocateSocketAddress();
                    auto status = rpcServer->setupUnixDomainServer(addr.c_str());
                    if (status != OK) {
                        return AssertionFailure()
                                << "setupUnixDomainServer: " << statusToString(status);
                    }
                    mConnectToServer = [addr] {
                        return connectTo(UnixSocketAddress(addr.c_str()));
                    };
                } break;
                case SocketType::UNIX_BOOTSTRAP: {
                    base::unique_fd bootstrapFdClient, bootstrapFdServer;
                    if (!base::Socketpair(SOCK_STREAM, &bootstrapFdClient, &bootstrapFdServer)) {
                        return AssertionFailure() << "Socketpair() failed";
                    }
                    auto status = rpcServer->setupUnixDomainSocketBootstrapServer(
                            std::move(bootstrapFdServer));
                    if (status != OK) {
                        return AssertionFailure() << "setupUnixDomainSocketBootstrapServer: "
                                                  << statusToString(status);
                    }
                    mBootstrapSocket = RpcTransportFd(std::move(bootstrapFdClient));
                    mAcceptConnection = &Server::recvmsgServerConnection;
                    mConnectToServer = [this] { return connectToUnixBootstrap(mBootstrapSocket); };
                } break;
                case SocketType::UNIX_RAW: {
                    auto addr = allocateSocketAddress();
                    auto status = rpcServer->setupRawSocketServer(initUnixSocket(addr));
                    if (status != OK) {
                        return AssertionFailure()
                                << "setupRawSocketServer: " << statusToString(status);
                    }
                    mConnectToServer = [addr] {
                        return connectTo(UnixSocketAddress(addr.c_str()));
                    };
                } break;
                case SocketType::VSOCK: {
                    auto port = allocateVsockPort();
                    auto status = rpcServer->setupVsockServer(VMADDR_CID_LOCAL, port);
                    if (status != OK) {
                        return AssertionFailure() << "setupVsockServer: " << statusToString(status);
                    }
                    mConnectToServer = [port] {
                        return connectTo(VsockSocketAddress(VMADDR_CID_LOCAL, port));
                    };
                } break;
                case SocketType::INET: {
                    unsigned int port;
                    auto status = rpcServer->setupInetServer(kLocalInetAddress, 0, &port);
                    if (status != OK) {
                        return AssertionFailure() << "setupInetServer: " << statusToString(status);
                    }
                    mConnectToServer = [port] {
                        const char* addr = kLocalInetAddress;
                        auto aiStart = InetSocketAddress::getAddrInfo(addr, port);
                        if (aiStart == nullptr) return base::unique_fd{};
                        for (auto ai = aiStart.get(); ai != nullptr; ai = ai->ai_next) {
                            auto fd = connectTo(
                                    InetSocketAddress(ai->ai_addr, ai->ai_addrlen, addr, port));
                            if (fd.ok()) return fd;
                        }
                        ALOGE("None of the socket address resolved for %s:%u can be connected",
                              addr, port);
                        return base::unique_fd{};
                    };
                } break;
                case SocketType::TIPC: {
                    LOG_ALWAYS_FATAL("RpcTransportTest should not be enabled for TIPC");
                } break;
            }
            mFd = rpcServer->releaseServer();
            if (!mFd.fd.ok()) return AssertionFailure() << "releaseServer returns invalid fd";
            mCtx = newTlsFactory(rpcSecurity, mCertVerifier, std::move(auth))->newServerCtx();
            if (mCtx == nullptr) return AssertionFailure() << "newServerCtx";
            mSetup = true;
            return AssertionSuccess();
        }
        RpcTransportCtx* getCtx() const { return mCtx.get(); }
        std::shared_ptr<RpcCertificateVerifierSimple> getCertVerifier() const {
            return mCertVerifier;
        }
        ConnectToServer getConnectToServerFn() { return mConnectToServer; }
        void start() {
            LOG_ALWAYS_FATAL_IF(!mSetup, "Call Server::setup first!");
            mThread = std::make_unique<std::thread>(&Server::run, this);
        }

        base::unique_fd acceptServerConnection() {
            return base::unique_fd(TEMP_FAILURE_RETRY(
                    accept4(mFd.fd.get(), nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK)));
        }

        base::unique_fd recvmsgServerConnection() {
            std::vector<std::variant<base::unique_fd, base::borrowed_fd>> fds;
            int buf;
            iovec iov{&buf, sizeof(buf)};

            if (receiveMessageFromSocket(mFd, &iov, 1, &fds) < 0) {
                int savedErrno = errno;
                LOG(FATAL) << "Failed receiveMessage: " << strerror(savedErrno);
            }
            if (fds.size() != 1) {
                LOG(FATAL) << "Expected one FD from receiveMessage(), got " << fds.size();
            }
            return std::move(std::get<base::unique_fd>(fds[0]));
        }

        void run() {
            LOG_ALWAYS_FATAL_IF(!mSetup, "Call Server::setup first!");

            std::vector<std::thread> threads;
            while (OK == mFdTrigger->triggerablePoll(mFd, POLLIN)) {
                base::unique_fd acceptedFd = mAcceptConnection(this);
                threads.emplace_back(&Server::handleOne, this, std::move(acceptedFd));
            }

            for (auto& thread : threads) thread.join();
        }
        void handleOne(android::base::unique_fd acceptedFd) {
            ASSERT_TRUE(acceptedFd.ok());
            RpcTransportFd transportFd(std::move(acceptedFd));
            auto serverTransport = mCtx->newTransport(std::move(transportFd), mFdTrigger.get());
            if (serverTransport == nullptr) return; // handshake failed
            ASSERT_TRUE(mPostConnect(serverTransport.get(), mFdTrigger.get()));
        }
        void shutdownAndWait() {
            shutdown();
            join();
        }
        void shutdown() { mFdTrigger->trigger(); }

        void setPostConnect(
                std::function<AssertionResult(RpcTransport*, FdTrigger* fdTrigger)> fn) {
            mPostConnect = std::move(fn);
        }

    private:
        std::unique_ptr<std::thread> mThread;
        ConnectToServer mConnectToServer;
        AcceptConnection mAcceptConnection = &Server::acceptServerConnection;
        std::unique_ptr<FdTrigger> mFdTrigger = FdTrigger::make();
        RpcTransportFd mFd, mBootstrapSocket;
        std::unique_ptr<RpcTransportCtx> mCtx;
        std::shared_ptr<RpcCertificateVerifierSimple> mCertVerifier =
                std::make_shared<RpcCertificateVerifierSimple>();
        bool mSetup = false;
        // The function invoked after connection and handshake. By default, it is
        // |defaultPostConnect| that sends |kMessage| to the client.
        std::function<AssertionResult(RpcTransport*, FdTrigger* fdTrigger)> mPostConnect =
                Server::defaultPostConnect;

        void join() {
            if (mThread != nullptr) {
                mThread->join();
                mThread = nullptr;
            }
        }

        static AssertionResult defaultPostConnect(RpcTransport* serverTransport,
                                                  FdTrigger* fdTrigger) {
            std::string message(kMessage);
            iovec messageIov{message.data(), message.size()};
            auto status = serverTransport->interruptableWriteFully(fdTrigger, &messageIov, 1,
                                                                   std::nullopt, nullptr);
            if (status != OK) return AssertionFailure() << statusToString(status);
            return AssertionSuccess();
        }
    };

    class Client {
    public:
        explicit Client(ConnectToServer connectToServer) : mConnectToServer(connectToServer) {}
        Client(Client&&) = default;
        [[nodiscard]] AssertionResult setUp(const Param& param) {
            auto [socketType, rpcSecurity, certificateFormat, serverVersion] = param;
            (void)serverVersion;
            mFdTrigger = FdTrigger::make();
            mCtx = newTlsFactory(rpcSecurity, mCertVerifier)->newClientCtx();
            if (mCtx == nullptr) return AssertionFailure() << "newClientCtx";
            return AssertionSuccess();
        }
        RpcTransportCtx* getCtx() const { return mCtx.get(); }
        std::shared_ptr<RpcCertificateVerifierSimple> getCertVerifier() const {
            return mCertVerifier;
        }
        // connect() and do handshake
        bool setUpTransport() {
            mFd = mConnectToServer();
            if (!mFd.fd.ok()) return AssertionFailure() << "Cannot connect to server";
            mClientTransport = mCtx->newTransport(std::move(mFd), mFdTrigger.get());
            return mClientTransport != nullptr;
        }
        AssertionResult readMessage(const std::string& expectedMessage = kMessage) {
            LOG_ALWAYS_FATAL_IF(mClientTransport == nullptr, "setUpTransport not called or failed");
            std::string readMessage(expectedMessage.size(), '\0');
            iovec readMessageIov{readMessage.data(), readMessage.size()};
            status_t readStatus =
                    mClientTransport->interruptableReadFully(mFdTrigger.get(), &readMessageIov, 1,
                                                             std::nullopt, nullptr);
            if (readStatus != OK) {
                return AssertionFailure() << statusToString(readStatus);
            }
            if (readMessage != expectedMessage) {
                return AssertionFailure()
                        << "Expected " << expectedMessage << ", actual " << readMessage;
            }
            return AssertionSuccess();
        }
        void run(bool handshakeOk = true, bool readOk = true) {
            if (!setUpTransport()) {
                ASSERT_FALSE(handshakeOk) << "newTransport returns nullptr, but it shouldn't";
                return;
            }
            ASSERT_TRUE(handshakeOk) << "newTransport does not return nullptr, but it should";
            ASSERT_EQ(readOk, readMessage());
        }

        bool isTransportWaiting() { return mClientTransport->isWaiting(); }

    private:
        ConnectToServer mConnectToServer;
        RpcTransportFd mFd;
        std::unique_ptr<FdTrigger> mFdTrigger = FdTrigger::make();
        std::unique_ptr<RpcTransportCtx> mCtx;
        std::shared_ptr<RpcCertificateVerifierSimple> mCertVerifier =
                std::make_shared<RpcCertificateVerifierSimple>();
        std::unique_ptr<RpcTransport> mClientTransport;
    };

    // Make A trust B.
    template <typename A, typename B>
    static status_t trust(RpcSecurity rpcSecurity,
                          std::optional<RpcCertificateFormat> certificateFormat, const A& a,
                          const B& b) {
        if (rpcSecurity != RpcSecurity::TLS) return OK;
        LOG_ALWAYS_FATAL_IF(!certificateFormat.has_value());
        auto bCert = b->getCtx()->getCertificate(*certificateFormat);
        return a->getCertVerifier()->addTrustedPeerCertificate(*certificateFormat, bCert);
    }

    static constexpr const char* kMessage = "hello";
};

class RpcTransportTest : public testing::TestWithParam<RpcTransportTestUtils::Param> {
public:
    using Server = RpcTransportTestUtils::Server;
    using Client = RpcTransportTestUtils::Client;
    static inline std::string PrintParamInfo(const testing::TestParamInfo<ParamType>& info) {
        auto [socketType, rpcSecurity, certificateFormat, serverVersion] = info.param;
        auto ret = PrintToString(socketType) + "_" + newTlsFactory(rpcSecurity)->toCString();
        if (certificateFormat.has_value()) ret += "_" + PrintToString(*certificateFormat);
        ret += "_serverV" + std::to_string(serverVersion);
        return ret;
    }
    static std::vector<ParamType> getRpcTranportTestParams() {
        std::vector<ParamType> ret;
        for (auto serverVersion : testVersions()) {
            for (auto socketType : testSocketTypes(false /* hasPreconnected */)) {
                for (auto rpcSecurity : RpcSecurityValues()) {
                    switch (rpcSecurity) {
                        case RpcSecurity::RAW: {
                            ret.emplace_back(socketType, rpcSecurity, std::nullopt, serverVersion);
                        } break;
                        case RpcSecurity::TLS: {
                            ret.emplace_back(socketType, rpcSecurity, RpcCertificateFormat::PEM,
                                             serverVersion);
                            ret.emplace_back(socketType, rpcSecurity, RpcCertificateFormat::DER,
                                             serverVersion);
                        } break;
                    }
                }
            }
        }
        return ret;
    }
    template <typename A, typename B>
    status_t trust(const A& a, const B& b) {
        auto [socketType, rpcSecurity, certificateFormat, serverVersion] = GetParam();
        (void)serverVersion;
        return RpcTransportTestUtils::trust(rpcSecurity, certificateFormat, a, b);
    }
    void SetUp() override {
        if constexpr (!kEnableRpcThreads) {
            GTEST_SKIP() << "Test skipped because threads were disabled at build time";
        }
    }
};

TEST_P(RpcTransportTest, GoodCertificate) {
    auto server = std::make_unique<Server>();
    ASSERT_TRUE(server->setUp(GetParam()));

    Client client(server->getConnectToServerFn());
    ASSERT_TRUE(client.setUp(GetParam()));

    ASSERT_EQ(OK, trust(&client, server));
    ASSERT_EQ(OK, trust(server, &client));

    server->start();
    client.run();
}

TEST_P(RpcTransportTest, MultipleClients) {
    auto server = std::make_unique<Server>();
    ASSERT_TRUE(server->setUp(GetParam()));

    std::vector<Client> clients;
    for (int i = 0; i < 2; i++) {
        auto& client = clients.emplace_back(server->getConnectToServerFn());
        ASSERT_TRUE(client.setUp(GetParam()));
        ASSERT_EQ(OK, trust(&client, server));
        ASSERT_EQ(OK, trust(server, &client));
    }

    server->start();
    for (auto& client : clients) client.run();
}

TEST_P(RpcTransportTest, UntrustedServer) {
    auto [socketType, rpcSecurity, certificateFormat, serverVersion] = GetParam();
    (void)serverVersion;

    auto untrustedServer = std::make_unique<Server>();
    ASSERT_TRUE(untrustedServer->setUp(GetParam()));

    Client client(untrustedServer->getConnectToServerFn());
    ASSERT_TRUE(client.setUp(GetParam()));

    ASSERT_EQ(OK, trust(untrustedServer, &client));

    untrustedServer->start();

    // For TLS, this should reject the certificate. For RAW sockets, it should pass because
    // the client can't verify the server's identity.
    bool handshakeOk = rpcSecurity != RpcSecurity::TLS;
    client.run(handshakeOk);
}
TEST_P(RpcTransportTest, MaliciousServer) {
    auto [socketType, rpcSecurity, certificateFormat, serverVersion] = GetParam();
    (void)serverVersion;

    auto validServer = std::make_unique<Server>();
    ASSERT_TRUE(validServer->setUp(GetParam()));

    auto maliciousServer = std::make_unique<Server>();
    ASSERT_TRUE(maliciousServer->setUp(GetParam()));

    Client client(maliciousServer->getConnectToServerFn());
    ASSERT_TRUE(client.setUp(GetParam()));

    ASSERT_EQ(OK, trust(&client, validServer));
    ASSERT_EQ(OK, trust(validServer, &client));
    ASSERT_EQ(OK, trust(maliciousServer, &client));

    maliciousServer->start();

    // For TLS, this should reject the certificate. For RAW sockets, it should pass because
    // the client can't verify the server's identity.
    bool handshakeOk = rpcSecurity != RpcSecurity::TLS;
    client.run(handshakeOk);
}

TEST_P(RpcTransportTest, UntrustedClient) {
    auto [socketType, rpcSecurity, certificateFormat, serverVersion] = GetParam();
    (void)serverVersion;

    auto server = std::make_unique<Server>();
    ASSERT_TRUE(server->setUp(GetParam()));

    Client client(server->getConnectToServerFn());
    ASSERT_TRUE(client.setUp(GetParam()));

    ASSERT_EQ(OK, trust(&client, server));

    server->start();

    // For TLS, Client should be able to verify server's identity, so client should see
    // do_handshake() successfully executed. However, server shouldn't be able to verify client's
    // identity and should drop the connection, so client shouldn't be able to read anything.
    bool readOk = rpcSecurity != RpcSecurity::TLS;
    client.run(true, readOk);
}

TEST_P(RpcTransportTest, MaliciousClient) {
    auto [socketType, rpcSecurity, certificateFormat, serverVersion] = GetParam();
    (void)serverVersion;

    auto server = std::make_unique<Server>();
    ASSERT_TRUE(server->setUp(GetParam()));

    Client validClient(server->getConnectToServerFn());
    ASSERT_TRUE(validClient.setUp(GetParam()));
    Client maliciousClient(server->getConnectToServerFn());
    ASSERT_TRUE(maliciousClient.setUp(GetParam()));

    ASSERT_EQ(OK, trust(&validClient, server));
    ASSERT_EQ(OK, trust(&maliciousClient, server));

    server->start();

    // See UntrustedClient.
    bool readOk = rpcSecurity != RpcSecurity::TLS;
    maliciousClient.run(true, readOk);
}

TEST_P(RpcTransportTest, Trigger) {
    std::string msg2 = ", world!";
    std::mutex writeMutex;
    std::condition_variable writeCv;
    bool shouldContinueWriting = false;
    auto serverPostConnect = [&](RpcTransport* serverTransport, FdTrigger* fdTrigger) {
        std::string message(RpcTransportTestUtils::kMessage);
        iovec messageIov{message.data(), message.size()};
        auto status = serverTransport->interruptableWriteFully(fdTrigger, &messageIov, 1,
                                                               std::nullopt, nullptr);
        if (status != OK) return AssertionFailure() << statusToString(status);

        {
            std::unique_lock<std::mutex> lock(writeMutex);
            if (!writeCv.wait_for(lock, 3s, [&] { return shouldContinueWriting; })) {
                return AssertionFailure() << "write barrier not cleared in time!";
            }
        }

        iovec msg2Iov{msg2.data(), msg2.size()};
        status = serverTransport->interruptableWriteFully(fdTrigger, &msg2Iov, 1, std::nullopt,
                                                          nullptr);
        if (status != DEAD_OBJECT)
            return AssertionFailure() << "When FdTrigger is shut down, interruptableWriteFully "
                                         "should return DEAD_OBJECT, but it is "
                                      << statusToString(status);
        return AssertionSuccess();
    };

    auto server = std::make_unique<Server>();
    ASSERT_TRUE(server->setUp(GetParam()));

    // Set up client
    Client client(server->getConnectToServerFn());
    ASSERT_TRUE(client.setUp(GetParam()));

    // Exchange keys
    ASSERT_EQ(OK, trust(&client, server));
    ASSERT_EQ(OK, trust(server, &client));

    server->setPostConnect(serverPostConnect);

    server->start();
    // connect() to server and do handshake
    ASSERT_TRUE(client.setUpTransport());
    // read the first message. This ensures that server has finished handshake and start handling
    // client fd. Server thread should pause at writeCv.wait_for().
    ASSERT_TRUE(client.readMessage(RpcTransportTestUtils::kMessage));
    // Trigger server shutdown after server starts handling client FD. This ensures that the second
    // write is on an FdTrigger that has been shut down.
    server->shutdown();
    // Continues server thread to write the second message.
    {
        std::lock_guard<std::mutex> lock(writeMutex);
        shouldContinueWriting = true;
    }
    writeCv.notify_all();
    // After this line, server thread unblocks and attempts to write the second message, but
    // shutdown is triggered, so write should failed with DEAD_OBJECT. See |serverPostConnect|.
    // On the client side, second read fails with DEAD_OBJECT
    ASSERT_FALSE(client.readMessage(msg2));
}

TEST_P(RpcTransportTest, CheckWaitingForRead) {
    std::mutex readMutex;
    std::condition_variable readCv;
    bool shouldContinueReading = false;
    // Server will write data on transport once its started
    auto serverPostConnect = [&](RpcTransport* serverTransport, FdTrigger* fdTrigger) {
        std::string message(RpcTransportTestUtils::kMessage);
        iovec messageIov{message.data(), message.size()};
        auto status = serverTransport->interruptableWriteFully(fdTrigger, &messageIov, 1,
                                                               std::nullopt, nullptr);
        if (status != OK) return AssertionFailure() << statusToString(status);

        {
            std::unique_lock<std::mutex> lock(readMutex);
            shouldContinueReading = true;
            lock.unlock();
            readCv.notify_all();
        }
        return AssertionSuccess();
    };

    // Setup Server and client
    auto server = std::make_unique<Server>();
    ASSERT_TRUE(server->setUp(GetParam()));

    Client client(server->getConnectToServerFn());
    ASSERT_TRUE(client.setUp(GetParam()));

    ASSERT_EQ(OK, trust(&client, server));
    ASSERT_EQ(OK, trust(server, &client));
    server->setPostConnect(serverPostConnect);

    server->start();
    ASSERT_TRUE(client.setUpTransport());
    {
        // Wait till server writes data
        std::unique_lock<std::mutex> lock(readMutex);
        ASSERT_TRUE(readCv.wait_for(lock, 3s, [&] { return shouldContinueReading; }));
    }

    // Since there is no read polling here, we will get polling count 0
    ASSERT_FALSE(client.isTransportWaiting());
    ASSERT_TRUE(client.readMessage(RpcTransportTestUtils::kMessage));
    // Thread should increment polling count, read and decrement polling count
    // Again, polling count should be zero here
    ASSERT_FALSE(client.isTransportWaiting());

    server->shutdown();
}

INSTANTIATE_TEST_CASE_P(BinderRpc, RpcTransportTest,
                        ::testing::ValuesIn(RpcTransportTest::getRpcTranportTestParams()),
                        RpcTransportTest::PrintParamInfo);

class RpcTransportTlsKeyTest
      : public testing::TestWithParam<
                std::tuple<SocketType, RpcCertificateFormat, RpcKeyFormat, uint32_t>> {
public:
    template <typename A, typename B>
    status_t trust(const A& a, const B& b) {
        auto [socketType, certificateFormat, keyFormat, serverVersion] = GetParam();
        (void)serverVersion;
        return RpcTransportTestUtils::trust(RpcSecurity::TLS, certificateFormat, a, b);
    }
    static std::string PrintParamInfo(const testing::TestParamInfo<ParamType>& info) {
        auto [socketType, certificateFormat, keyFormat, serverVersion] = info.param;
        return PrintToString(socketType) + "_certificate_" + PrintToString(certificateFormat) +
                "_key_" + PrintToString(keyFormat) + "_serverV" + std::to_string(serverVersion);
    };
};

TEST_P(RpcTransportTlsKeyTest, PreSignedCertificate) {
    if constexpr (!kEnableRpcThreads) {
        GTEST_SKIP() << "Test skipped because threads were disabled at build time";
    }

    auto [socketType, certificateFormat, keyFormat, serverVersion] = GetParam();

    std::vector<uint8_t> pkeyData, certData;
    {
        auto pkey = makeKeyPairForSelfSignedCert();
        ASSERT_NE(nullptr, pkey);
        auto cert = makeSelfSignedCert(pkey.get(), kCertValidSeconds);
        ASSERT_NE(nullptr, cert);
        pkeyData = serializeUnencryptedPrivatekey(pkey.get(), keyFormat);
        certData = serializeCertificate(cert.get(), certificateFormat);
    }

    auto desPkey = deserializeUnencryptedPrivatekey(pkeyData, keyFormat);
    auto desCert = deserializeCertificate(certData, certificateFormat);
    auto auth = std::make_unique<RpcAuthPreSigned>(std::move(desPkey), std::move(desCert));
    auto utilsParam = std::make_tuple(socketType, RpcSecurity::TLS,
                                      std::make_optional(certificateFormat), serverVersion);

    auto server = std::make_unique<RpcTransportTestUtils::Server>();
    ASSERT_TRUE(server->setUp(utilsParam, std::move(auth)));

    RpcTransportTestUtils::Client client(server->getConnectToServerFn());
    ASSERT_TRUE(client.setUp(utilsParam));

    ASSERT_EQ(OK, trust(&client, server));
    ASSERT_EQ(OK, trust(server, &client));

    server->start();
    client.run();
}

INSTANTIATE_TEST_CASE_P(
        BinderRpc, RpcTransportTlsKeyTest,
        testing::Combine(testing::ValuesIn(testSocketTypes(false /* hasPreconnected*/)),
                         testing::Values(RpcCertificateFormat::PEM, RpcCertificateFormat::DER),
                         testing::Values(RpcKeyFormat::PEM, RpcKeyFormat::DER),
                         testing::ValuesIn(testVersions())),
        RpcTransportTlsKeyTest::PrintParamInfo);
#endif // BINDER_RPC_TO_TRUSTY_TEST

} // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    android::base::InitLogging(argv, android::base::StderrLogger, android::base::DefaultAborter);

    return RUN_ALL_TESTS();
}
