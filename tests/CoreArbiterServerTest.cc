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
#include "Logger.h"

namespace CoreArbiter {

class CoreArbiterServerTest : public ::testing::Test {
  public:

    MockSyscall* sys;
    std::string socketPath;
    std::string memPath;
    int clientSocket;
    int serverSocket;

    typedef CoreArbiterServer::ThreadInfo ThreadInfo;
    typedef CoreArbiterServer::ProcessInfo ProcessInfo;
    typedef CoreArbiterServer::CoreInfo CoreInfo;
    typedef CoreArbiterServer::ThreadState ThreadState;

    CoreArbiterServerTest()
        : socketPath("/tmp/CoreArbiter/testsocket")
        , memPath("/tmp/CoreArbiter/testmem")
    {
        Logger::setLogLevel(ERROR);

        sys = new MockSyscall();
        CoreArbiterServer::sys = sys;

        int fd[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
        clientSocket = fd[0];
        serverSocket = fd[1];
    }

    ~CoreArbiterServerTest()
    {
        close(clientSocket);
        close(serverSocket);
        delete sys;
    }

    /**
     * Populates processes and threads with RUNNING_SHARED threads
     */
    void setupProcessesAndThreads(CoreArbiterServer& server,
                                  std::vector<ProcessInfo>& processes,
                                  std::vector<ThreadInfo>& threads,
                                  ThreadState defaultState) {

        size_t threadIdx = 0;
        for (size_t i = 0; i < processes.size(); i++) {
            ProcessInfo* process = &processes[i];
            process->id = (pid_t)i;
            server.processIdToInfo[process->id] = process;

            for (size_t j = 0; j < threads.size() / processes.size(); j++) {
                ThreadInfo* thread = &threads[threadIdx];
                thread->process = process;
                thread->threadId = (pid_t)threadIdx;
                thread->state = defaultState;
                process->threadStateToSet[defaultState].insert(thread);

                threadIdx++;
            }
        }
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
        "Error adding listenSocket .* to epoll:.*");
    sys->epollCtlErrno = 0;
}

TEST_F(CoreArbiterServerTest, threadBlocking) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;

    CoreArbiterServer server(socketPath, memPath, std::vector<core_t>());

    int processId = 1;
    int threadId = 2;
    int socket = 3;
    core_t coreReleaseRequestCount = 0;
    ProcessInfo process(processId, 0, &coreReleaseRequestCount);
    ThreadInfo thread(threadId, &process, socket);

    // Nothing should happen because the server doesn't know about this thread
    // yet
    server.threadBlocking(socket);
    ASSERT_EQ(thread.state, CoreArbiterServer::RUNNING_SHARED);

    // Add thread information to server
    server.threadSocketToInfo[socket] = &thread;
    server.processIdToInfo[processId] = &process;

    // If the thread is supposed to be blocked already nothing should happen
    thread.state = CoreArbiterServer::BLOCKED;
    server.threadBlocking(socket);
    ASSERT_EQ(thread.state, CoreArbiterServer::BLOCKED);

    // A thread running on the unmanaged core should always be able to block
    thread.state = CoreArbiterServer::RUNNING_SHARED;
    server.threadBlocking(socket);
    ASSERT_EQ(thread.state, CoreArbiterServer::BLOCKED);

    // If the thread is running exclusively a block call should fail if the
    // server hasn't requested cores back
    CoreInfo core;
    thread.core = &core;
    thread.state = CoreArbiterServer::RUNNING_EXCLUSIVE;
    server.threadBlocking(socket);
    ASSERT_EQ(thread.state, CoreArbiterServer::RUNNING_EXCLUSIVE);

    // If the server has requestd cores back, this call succeeds
    coreReleaseRequestCount = 1;
    server.threadBlocking(socket);
    ASSERT_EQ(thread.state, CoreArbiterServer::BLOCKED);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipCoreDistribution = false;
}

TEST_F(CoreArbiterServerTest, coresRequested) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;

    CoreArbiterServer server(socketPath, memPath, std::vector<core_t>());

    int processId = 1;
    int threadId = 2;
    core_t coreReleaseRequestCount = 0;

    ProcessInfo process(processId, 0, &coreReleaseRequestCount);
    ThreadInfo thread(threadId, &process, serverSocket);
    server.threadSocketToInfo[serverSocket] = &thread;
    server.processIdToInfo[processId] = &process;

    // Request 1 core at each priority and make sure this process is on the wait
    // list for every priority
    std::vector<core_t> coreRequest = {1, 1, 1, 1, 1, 1, 1, 1};
    send(clientSocket, &coreRequest[0], sizeof(core_t) * 8, 0);
    server.coresRequested(serverSocket);
    ASSERT_EQ(process.totalCoresDesired, (core_t)coreRequest.size());
    ASSERT_EQ(coreReleaseRequestCount, 0);
    for (size_t i = 0; i < coreRequest.size(); i++) {
        ASSERT_EQ(server.corePriorityQueues[i].size(), 1u);
        ASSERT_EQ(process.desiredCorePriorities[i], coreRequest[i]);
    }

    // Adding an additional request shouldn't change anything but the process's
    // number of desired cores
    coreRequest = {2, 2, 2, 2, 2, 2, 2, 2};
    send(clientSocket, &coreRequest[0], sizeof(core_t) * 8, 0);
    server.coresRequested(serverSocket);
    ASSERT_EQ(process.totalCoresDesired, 16);
    ASSERT_EQ(coreReleaseRequestCount, 0);
    for (size_t i = 0; i < coreRequest.size(); i++) {
        ASSERT_EQ(server.corePriorityQueues[i].size(), 1u);
        ASSERT_EQ(process.desiredCorePriorities[i], coreRequest[i]);
    }

    // Request fewer cores. Since we weren't granted any before, we shouldn't
    // have any requested back.
    coreRequest = {2, 2, 2, 2, 1, 1, 1, 1};
    send(clientSocket, &coreRequest[0], sizeof(core_t) * 8, 0);
    server.coresRequested(serverSocket);
    ASSERT_EQ(process.totalCoresDesired, 12);
    ASSERT_EQ(coreReleaseRequestCount, 0);
    for (size_t i = 0; i < coreRequest.size(); i++) {
        ASSERT_EQ(server.corePriorityQueues[i].size(), 1u);
        ASSERT_EQ(process.desiredCorePriorities[i], coreRequest[i]);
    }

    // Request fewer cores again, this time under the situation where we did
    // own cores that we have to give up.
    process.totalCoresOwned = 4;
    coreRequest = {0, 0, 0, 0, 0, 0, 0, 0};
    send(clientSocket, &coreRequest[0], sizeof(core_t) * 8, 0);
    server.coresRequested(serverSocket);
    ASSERT_EQ(process.totalCoresDesired, 0);
    ASSERT_EQ(coreReleaseRequestCount, 4);
    for (size_t i = 0; i < coreRequest.size(); i++) {
        ASSERT_EQ(server.corePriorityQueues[i].size(), 0u);
        ASSERT_EQ(process.desiredCorePriorities[i], coreRequest[i]);
    }

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipCoreDistribution = false;
}

TEST_F(CoreArbiterServerTest, distributeCores_noBlockedThreads) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;

    CoreArbiterServer server(socketPath, memPath, {1, 2, 3});
    std::vector<ProcessInfo> processes(2);
    std::vector<ThreadInfo> threads(4);
    setupProcessesAndThreads(server, processes, threads,
                             CoreArbiterServer::RUNNING_SHARED);

    server.corePriorityQueues[7].push_back(&processes[0]);
    server.corePriorityQueues[7].push_back(&processes[1]);

    server.distributeCores();
    ASSERT_TRUE(server.exclusiveThreads.empty());
    for (CoreInfo& core : server.exclusiveCores) {
        ASSERT_EQ(core.exclusiveThread, (ThreadInfo*)NULL);
    }

    CoreArbiterServer::testingSkipCpusetAllocation = false;
}

TEST_F(CoreArbiterServerTest, distributeCores_niceToHaveSinglePriority) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;

    CoreArbiterServer server(socketPath, memPath, {1, 2});

    // Set up two processes who each want two cores at the lowest priority
    std::vector<ProcessInfo> processes(2);
    std::vector<ThreadInfo> threads(4);
    setupProcessesAndThreads(server, processes, threads,
                             CoreArbiterServer::BLOCKED);
    processes[0].desiredCorePriorities[7] = 2;
    processes[1].desiredCorePriorities[7] = 2;
    server.corePriorityQueues[7].push_back(&processes[0]);
    server.corePriorityQueues[7].push_back(&processes[1]);

    // Cores are shared evenly among nice to have threads of the same priority.
    server.distributeCores();
    ASSERT_EQ(server.exclusiveThreads.size(), 2u);
    ASSERT_EQ(processes[0].totalCoresOwned, 1);
    ASSERT_EQ(processes[1].totalCoresOwned, 1);
    std::unordered_map<CoreInfo*, ThreadInfo*> savedCoreToThread;
    for (CoreInfo& core : server.exclusiveCores) {
        ASSERT_TRUE(core.exclusiveThread != NULL);
        savedCoreToThread[&core] = core.exclusiveThread;
    }

    // Threads already running exclusively are given priority over blocked ones
    // in core distribution.
    server.distributeCores();
    ASSERT_EQ(server.exclusiveThreads.size(), 2u);
    ASSERT_EQ(processes[0].totalCoresOwned, 1);
    ASSERT_EQ(processes[1].totalCoresOwned, 1);
    for (CoreInfo& core : server.exclusiveCores) {
        ASSERT_EQ(core.exclusiveThread, savedCoreToThread[&core]);
    }

    // Don't give processes more cores at this priority than they've asked for
    ThreadInfo* removedThread = server.exclusiveCores[0].exclusiveThread;
    removedThread->process->desiredCorePriorities[7] = 0;
    server.exclusiveThreads.erase(removedThread);
    server.exclusiveCores[0].exclusiveThread = NULL;
    server.distributeCores();
    ProcessInfo* otherProcess = removedThread->process == &processes[0] ?
        &processes[1] : &processes[0];
    ASSERT_EQ(server.exclusiveThreads.size(), 2u);
    ASSERT_EQ(otherProcess->totalCoresOwned, 2);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
}

}