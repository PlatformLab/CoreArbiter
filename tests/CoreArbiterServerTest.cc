/* Copyright (c) 2015-2017 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define private public

#include "gtest/gtest.h"
#include "MockSyscall.h"
#include "CoreArbiterServer.h"

namespace CoreArbiter {

class CoreArbiterServerTest : public ::testing::Test {
  public:

    MockSyscall* sys;
    std::string socketPath;
    std::string memPath;

    CoreArbiterServerTest()
        : socketPath("testsocket")
        , memPath("testmem")
    {
        sys = new MockSyscall();
        CoreArbiterServer::sys = sys;
    }

    ~CoreArbiterServerTest()
    {
        delete sys;
    }
};

TEST_F(CoreArbiterServerTest, constructor_notRoot) {
    sys->callGeteuid = false;
    sys->geteuidResult = 1;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<core_t>()),
        "The core arbiter server must be run as root");
    sys->callGeteuid = true;    
}

TEST_F(CoreArbiterServerTest, constructor_socketError) {
    sys->socketErrno = EAFNOSUPPORT;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<core_t>()),
        "Error creating listen socket:.*");
    sys->socketErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_bindError) {
    sys->bindErrno = EINVAL;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<core_t>()),
        "Error binding listen socket:.*");
    sys->bindErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_listenError) {
    sys->listenErrno = EBADF;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<core_t>()),
        "Error listening:.*");
    sys->listenErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_chmodError) {
    sys->chmodErrno = EACCES;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<core_t>()),
        "Error on chmod for.*");
    sys->chmodErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_epollCreateError) {
    sys->epollCreateErrno = EINVAL;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<core_t>()),
        "Error on epoll_create:.*");
    sys->epollCreateErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_epollCtlError) {
    sys->epollCtlErrno = EBADF;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<core_t>()),
        "Error adding listenFd .* to epoll:.*");
    sys->epollCtlErrno = 0;
}

TEST_F(CoreArbiterServerTest, threadBlocking) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer server(socketPath, memPath, std::vector<core_t>());

    int processId = 1;
    int threadId = 2;
    int fd = 3;

    CoreArbiterServer::ThreadInfo thread(threadId, processId, fd);

    // Nothing should happen because the server doesn't know about this thread yet
    server.threadBlocking(fd);
    ASSERT_EQ(thread.state, CoreArbiterServer::RUNNING_SHARED);

    // Add thread information to server
    core_t coreReleaseRequestCount = 0;
    CoreArbiterServer::ProcessInfo process(2, 0, &coreReleaseRequestCount);
    server.threadFdToInfo[fd] = &thread;
    server.processIdToInfo[processId] = &process;

    // Block call should now succeed
    server.threadBlocking(fd);
    ASSERT_EQ(thread.state, CoreArbiterServer::BLOCKED);

    thread.state = CoreArbiterServer::RUNNING_EXCLUSIVE;

    // If the thread is running exclusively a block call should fail if the
    // server hasn't requested cores back
    server.threadBlocking(fd);
    ASSERT_EQ(thread.state, CoreArbiterServer::RUNNING_EXCLUSIVE);

    // If the server has requestd cores back, this call succeeds
    coreReleaseRequestCount = 1;
    server.threadBlocking(fd);
    ASSERT_EQ(thread.state, CoreArbiterServer::BLOCKED);
}

TEST_F(CoreArbiterServerTest, coresRequested) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer server(socketPath, memPath, std::vector<core_t>());

    int processId = 1;
    int threadId = 2;
    int fd[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
    int serverFd = fd[0];
    int clientFd = fd[1];
    core_t coreReleaseRequestCount = 0;

    CoreArbiterServer::ThreadInfo thread(threadId, processId, serverFd);
    CoreArbiterServer::ProcessInfo process(processId, 0, &coreReleaseRequestCount);
    server.threadFdToInfo[serverFd] = &thread;
    server.processIdToInfo[processId] = &process;

    // Request more cores
    core_t numCores = 3;
    send(clientFd, &numCores, sizeof(core_t), 0);
    server.coresRequested(serverFd);
    ASSERT_EQ(process.numCoresDesired, numCores);
    ASSERT_EQ(server.processesOwedCores.size(), 1u);

    // Request fewer cores. Since we weren't granted any before, we shouldn't
    // have any requested back.
    numCores = 2;
    send(clientFd, &numCores, sizeof(core_t), 0);
    server.coresRequested(serverFd);
    ASSERT_EQ(process.numCoresDesired, numCores);
    ASSERT_EQ(coreReleaseRequestCount, 0);
    ASSERT_EQ(server.processesOwedCores.size(), 1u);

    // Request fewer cores again. This time we did own cores that we have to
    // give up.
    process.numCoresOwned = 2;
    numCores = 0;
    send(clientFd, &numCores, sizeof(core_t), 0);
    server.coresRequested(serverFd);
    ASSERT_EQ(process.numCoresDesired, numCores);
    ASSERT_EQ(coreReleaseRequestCount, 2);
    ASSERT_EQ(server.processesOwedCores.size(), 0u);
    
    close(serverFd);
    close(clientFd);
}

}