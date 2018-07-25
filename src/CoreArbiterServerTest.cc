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

#include <thread>
#define private public

#include "CoreArbiterServer.h"
#include "FakeCoreSegregator.h"
#include "Logger.h"
#include "MockSyscall.h"
#include "Topology.h"

#undef private
#include "PerfUtils/Util.h"
#include "gtest/gtest.h"

namespace CoreArbiter {

class CoreArbiterServerTest : public ::testing::Test {
  public:
    MockSyscall* sys;
    std::string socketPath;
    std::string memPath;
    int clientSocket;
    int serverSocket;
    Topology topology;
    FakeCoreSegregator* fakeCoreSegregator;

    typedef CoreArbiterServer::ThreadInfo ThreadInfo;
    typedef CoreArbiterServer::ProcessInfo ProcessInfo;
    typedef CoreArbiterServer::CoreInfo CoreInfo;
    typedef CoreArbiterServer::ThreadState ThreadState;

    CoreArbiterServerTest()
        : socketPath("/tmp/CoreArbiter/testsocket"),
          memPath("/tmp/CoreArbiter/testmem"),
          topology(),
          fakeCoreSegregator(NULL) {
        Logger::setLogLevel(ERROR);

        sys = new MockSyscall();
        CoreArbiterServer::sys = sys;

        // Default topology should work for most tests using a
        // FakeCoreSegregator.
        Topology::NUMANode nn0{0, {0, 1, 2, 3}};
        std::unordered_map<int, int> coreToHypertwin{
            {0, 1}, {1, 0}, {2, 3}, {3, 2}};
        topology = Topology({nn0}, coreToHypertwin);
        fakeCoreSegregator = new FakeCoreSegregator(topology);

        int fd[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
        clientSocket = fd[0];
        serverSocket = fd[1];
    }

    ~CoreArbiterServerTest() {
        close(clientSocket);
        close(serverSocket);
        delete sys;
        delete fakeCoreSegregator;
    }

    /**
     * The process that this method creates needs to be freed by the caller.
     */
    ProcessInfo* createProcess(CoreArbiterServer& server, pid_t processId,
                               ProcessStats* stats) {
        ProcessInfo* process = new ProcessInfo(processId, 0, stats);
        server.processIdToInfo[processId] = process;
        return process;
    }

    /**
     * The thread that this method creates needs to be freed by the caller.
     */
    ThreadInfo* createThread(CoreArbiterServer& server, pid_t threadId,
                             ProcessInfo* process, int socket,
                             ThreadState state, CoreInfo* core = NULL) {
        ThreadInfo* thread = new ThreadInfo(threadId, process, socket);
        thread->state = state;
        process->threadStateToSet[state].insert(thread);
        server.threadSocketToInfo[socket] = thread;
        if (state == CoreArbiterServer::RUNNING_MANAGED) {
            process->stats->numOwnedCores++;
            thread->core = core;
            core->managedThread = thread;
        } else if (state == CoreArbiterServer::RUNNING_PREEMPTED) {
            process->stats->preemptedCount++;
        }
        return thread;
    }
};

TEST_F(CoreArbiterServerTest, constructor_notRoot) {
    sys->callGeteuid = false;
    sys->geteuidResult = 1;
    ASSERT_DEATH(CoreArbiterServer(socketPath, memPath, {}),
                 "The core arbiter server must be run as root");
    sys->callGeteuid = true;
}

TEST_F(CoreArbiterServerTest, constructor_socketError) {
    sys->socketErrno = EAFNOSUPPORT;
    ASSERT_DEATH(CoreArbiterServer(socketPath, memPath, {}),
                 "Error creating listen socket:.*");
    sys->socketErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_bindError) {
    sys->bindErrno = EINVAL;
    std::string expectedError =
        "Error binding listen socket " + socketPath + ":.*";
    ASSERT_DEATH(CoreArbiterServer(socketPath, memPath, {}),
                 expectedError.c_str());
    sys->bindErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_listenError) {
    sys->listenErrno = EBADF;
    ASSERT_DEATH(CoreArbiterServer(socketPath, memPath, {}),
                 "Error listening:.*");
    sys->listenErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_chmodError) {
    sys->chmodErrno = EACCES;
    ASSERT_DEATH(CoreArbiterServer(socketPath, memPath, {}),
                 "Error on chmod for.*");
    sys->chmodErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_epollCreateError) {
    sys->epollCreateErrno = EINVAL;
    ASSERT_DEATH(CoreArbiterServer(socketPath, memPath, {}),
                 "Error on epoll_create:.*");
    sys->epollCreateErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_epollCtlError) {
    sys->epollCtlErrno = EBADF;
    ASSERT_DEATH(CoreArbiterServer(socketPath, memPath, {}),
                 "Error adding listenSocket .* to epoll:.*");
    sys->epollCtlErrno = 0;
}

TEST_F(CoreArbiterServerTest, endArbitration) {
    CoreArbiterServer server(socketPath, memPath, {1, 2}, false);
    std::thread arbitrationThread([&] { server.startArbitration(); });
    server.endArbitration();
    arbitrationThread.join();
}

TEST_F(CoreArbiterServerTest, defaultCores) {
    CoreArbiterServer server(socketPath, memPath, {}, topology,
                             fakeCoreSegregator, false);
    ASSERT_EQ(server.coreIdToCore.size(), server.topology.getNumCores() - 1);
}

TEST_F(CoreArbiterServerTest, threadBlocking_basic) {
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;

    CoreArbiterServer server(socketPath, memPath, {1}, topology,
                             fakeCoreSegregator, false);
    int processId = 1;
    int threadId = 2;
    int socket = 3;
    ProcessStats processStats;
    ProcessInfo* process = createProcess(server, processId, &processStats);
    ThreadInfo* thread = createThread(server, threadId, process, socket,
                                      CoreArbiterServer::RUNNING_UNMANAGED);

    // Nothing should happen it the server doesn't know about this thread yet
    server.threadSocketToInfo.erase(socket);
    server.threadBlocking(socket);
    ASSERT_EQ(thread->state, CoreArbiterServer::RUNNING_UNMANAGED);
    ASSERT_EQ(processStats.numBlockedThreads, 0u);

    // If the thread is supposed to be blocked already nothing should happen
    server.threadSocketToInfo[socket] = thread;
    thread->state = CoreArbiterServer::BLOCKED;
    server.threadBlocking(socket);
    ASSERT_EQ(thread->state, CoreArbiterServer::BLOCKED);
    ASSERT_EQ(processStats.numBlockedThreads, 0u);

    // A thread running on the unmanaged core should always be able to block
    thread->state = CoreArbiterServer::RUNNING_UNMANAGED;
    server.threadBlocking(socket);
    ASSERT_EQ(thread->state, CoreArbiterServer::BLOCKED);
    ASSERT_EQ(processStats.numBlockedThreads, 1u);

    // If the thread is running on a managed core a block call should fail if
    // the server hasn't requested cores back
    processStats.numBlockedThreads = 0;
    thread->core = server.coreIdToCore[1];
    thread->state = CoreArbiterServer::RUNNING_MANAGED;
    server.threadBlocking(socket);
    ASSERT_EQ(thread->state, CoreArbiterServer::RUNNING_MANAGED);
    ASSERT_EQ(processStats.numBlockedThreads, 0u);

    // If the server has requested cores back, this call succeeds
    processStats.threadCommunicationBlocks[1].coreReleaseRequested = true;
    server.threadBlocking(socket);
    ASSERT_EQ(thread->state, CoreArbiterServer::BLOCKED);
    ASSERT_EQ(processStats.numBlockedThreads, 1u);

    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingSkipCoreDistribution = false;
}

TEST_F(CoreArbiterServerTest, threadBlocking_preemptedThread) {
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1}, topology,
                             fakeCoreSegregator, false);

    pid_t processId = 0;
    pid_t threadId = 1;
    int socket = 2;
    ProcessStats processStats;
    processStats.threadCommunicationBlocks[1].coreReleaseRequested = true;
    ProcessInfo* process = createProcess(server, processId, &processStats);
    ThreadInfo* thread = createThread(server, threadId, process, socket,
                                      CoreArbiterServer::RUNNING_PREEMPTED);
    thread->corePreemptedFrom = server.coreIdToCore[1];
    process->coresPreemptedFrom[server.coreIdToCore[1]] = thread;

    // A preempted thread blocking counts as releasing a core
    server.threadBlocking(socket);
    ASSERT_EQ(thread->state, CoreArbiterServer::BLOCKED);
    ASSERT_EQ(processStats.preemptedCount, 1u);
    ASSERT_EQ(processStats.unpreemptedCount, 1u);
    ASSERT_EQ(processStats.numBlockedThreads, 1u);

    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingSkipCoreDistribution = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, threadBlocking_movePreemptedThread) {
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1}, topology,
                             fakeCoreSegregator, false);

    pid_t processId = 0;
    pid_t threadId1 = 1;
    pid_t threadId2 = 2;
    int socket1 = 3;
    int socket2 = 4;
    ProcessStats processStats;
    ProcessInfo* process = createProcess(server, processId, &processStats);
    ThreadInfo* thread1 = createThread(server, threadId1, process, socket1,
                                       CoreArbiterServer::RUNNING_MANAGED,
                                       server.coreIdToCore[1]);
    ThreadInfo* thread2 = createThread(server, threadId2, process, socket2,
                                       CoreArbiterServer::RUNNING_PREEMPTED);
    thread2->corePreemptedFrom = server.coreIdToCore[1];

    // When a thread blocks without being asked to, it is a no-op.
    server.threadBlocking(socket1);
    ASSERT_EQ(thread1->state, CoreArbiterServer::RUNNING_MANAGED);
    ASSERT_EQ(thread2->state, CoreArbiterServer::RUNNING_PREEMPTED);
    ASSERT_EQ(process->stats->numOwnedCores, 1u);

    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingSkipCoreDistribution = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, coresRequested_flags) {
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1}, topology,
                             fakeCoreSegregator, false);

    // Create a process taht we will update the requests for.
    ProcessStats processStats;
    ProcessInfo* process = createProcess(server, 1, &processStats);
    createThread(server, 1, process, serverSocket,
                 CoreArbiterServer::RUNNING_UNMANAGED);

    std::vector<uint32_t> coreRequest = {1, 1, 1, 1, 1, 1, 1, 1};

    send(clientSocket, &coreRequest[0], sizeof(uint32_t) * 8, 0);
    int flags = 0;
    send(clientSocket, &flags, sizeof(int), 0);
    server.coresRequested(serverSocket);

    ASSERT_FALSE(process->singleNUMAOnly);
    ASSERT_FALSE(process->willShareCores);

    send(clientSocket, &coreRequest[0], sizeof(uint32_t) * 8, 0);
    flags = 1;
    send(clientSocket, &flags, sizeof(int), 0);
    server.coresRequested(serverSocket);

    ASSERT_TRUE(process->singleNUMAOnly);
    ASSERT_FALSE(process->willShareCores);

    send(clientSocket, &coreRequest[0], sizeof(uint32_t) * 8, 0);
    flags = 2;
    send(clientSocket, &flags, sizeof(int), 0);
    server.coresRequested(serverSocket);

    ASSERT_FALSE(process->singleNUMAOnly);
    ASSERT_TRUE(process->willShareCores);

    send(clientSocket, &coreRequest[0], sizeof(uint32_t) * 8, 0);
    flags = 3;
    send(clientSocket, &flags, sizeof(int), 0);
    server.coresRequested(serverSocket);

    ASSERT_TRUE(process->singleNUMAOnly);
    ASSERT_TRUE(process->willShareCores);
}

TEST_F(CoreArbiterServerTest, coresRequested) {
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1}, topology,
                             fakeCoreSegregator, false);

    ProcessStats processStats;
    ProcessInfo* process = createProcess(server, 1, &processStats);
    createThread(server, 1, process, serverSocket,
                 CoreArbiterServer::RUNNING_UNMANAGED);

    // Request 1 core at each priority and make sure this process is on the wait
    // list for every priority
    std::vector<uint32_t> coreRequest = {1, 1, 1, 1, 1, 1, 1, 1};
    send(clientSocket, &coreRequest[0], sizeof(uint32_t) * 8, 0);
    int flags = 0;
    send(clientSocket, &flags, sizeof(int), 0);

    server.coresRequested(serverSocket);
    for (size_t i = 0; i < coreRequest.size(); i++) {
        ASSERT_EQ(server.corePriorityQueues[i].size(), 1u);
        ASSERT_EQ(process->desiredCorePriorities[i], coreRequest[i]);
    }

    // Adding an additional request shouldn't change anything but the process's
    // number of desired cores
    coreRequest = {2, 2, 2, 2, 2, 2, 2, 2};
    send(clientSocket, &coreRequest[0], sizeof(uint32_t) * 8, 0);
    send(clientSocket, &flags, sizeof(int), 0);
    server.coresRequested(serverSocket);
    for (size_t i = 0; i < coreRequest.size(); i++) {
        ASSERT_EQ(server.corePriorityQueues[i].size(), 1u);
        ASSERT_EQ(process->desiredCorePriorities[i], coreRequest[i]);
    }

    // Request fewer cores. This shouldn't change the fact that we're in the
    // core priority queue
    coreRequest = {2, 2, 2, 2, 1, 1, 1, 1};
    send(clientSocket, &coreRequest[0], sizeof(uint32_t) * 8, 0);
    send(clientSocket, &flags, sizeof(int), 0);
    server.coresRequested(serverSocket);
    for (size_t i = 0; i < coreRequest.size(); i++) {
        ASSERT_EQ(server.corePriorityQueues[i].size(), 1u);
        ASSERT_EQ(process->desiredCorePriorities[i], coreRequest[i]);
    }

    // Request 0 cores at all priorities. Now we should be removed from all
    // priority queues
    processStats.numOwnedCores = 4;
    coreRequest = {0, 0, 0, 0, 0, 0, 0, 0};
    send(clientSocket, &coreRequest[0], sizeof(uint32_t) * 8, 0);
    send(clientSocket, &flags, sizeof(int), 0);
    server.coresRequested(serverSocket);
    for (size_t i = 0; i < coreRequest.size(); i++) {
        ASSERT_EQ(server.corePriorityQueues[i].size(), 0u);
        ASSERT_EQ(process->desiredCorePriorities[i], coreRequest[i]);
    }

    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingSkipCoreDistribution = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, distributeCores_basics) {
    // Test Plan: Create two core arbiter clients. Verify that the appropriate
    // number of non-overlapping cores was granted to each process in each
    // case below by examining the logicallyOwnedCores in each process.
    // 1) Request a total number of cores fewer than the number of available
    //    cores.
    // 2) Request a total number of cores larger than the number of available
    //    cores, at equal priority.
    // 3) Request a total number of cores larger than the number of available
    //    cores, at different priorities.

    // Form a topology and set the topology
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;
    CoreArbiterServer server(socketPath, memPath, {1, 2, 3}, topology,
                             fakeCoreSegregator, false);

    // Set up two processes
    std::vector<ProcessInfo*> processes;
    for (int i = 0; i < 2; i++) {
        ProcessInfo* process = createProcess(server, i, new ProcessStats());
        processes.push_back(process);
        // Create enough threads to support different cases relative to the
        // total number of cores available.
        for (int j = 0; j < 5; j++) {
            createThread(server, j, process, j, CoreArbiterServer::BLOCKED);
        }
    }

    server.corePriorityQueues[1].push_back(processes[0]);
    server.corePriorityQueues[1].push_back(processes[1]);
    // Collection of satisfiable requests.
    processes[0]->desiredCorePriorities[1] = 2;
    processes[1]->desiredCorePriorities[1] = 1;

    server.distributeCores();
    EXPECT_EQ(2U, processes[0]->logicallyOwnedCores.size());
    EXPECT_EQ(1U, processes[1]->logicallyOwnedCores.size());
    auto it = processes[0]->logicallyOwnedCores.begin();
    int core1 = (*it)->id;
    it++;
    int core2 = (*it)->id;
    printf("Core1 = %d, Core2 = %d\n", core1, core2);
    EXPECT_EQ(core1, topology.coreToHypertwin[core2]);

    // Make sure we don't get more cores than we asked for, just because more
    // are available.
    processes[0]->desiredCorePriorities[1] = 1;
    processes[1]->desiredCorePriorities[1] = 1;

    server.distributeCores();
    EXPECT_EQ(1U, processes[0]->logicallyOwnedCores.size());
    EXPECT_EQ(1U, processes[1]->logicallyOwnedCores.size());

    // Requesting more than the cores we have
    processes[0]->desiredCorePriorities[1] = 4;
    processes[1]->desiredCorePriorities[1] = 2;

    server.distributeCores();
    EXPECT_EQ(2U, processes[0]->logicallyOwnedCores.size());
    EXPECT_EQ(1U, processes[1]->logicallyOwnedCores.size());

    // Requesting more than the cores we have at different priorities
    processes[0]->desiredCorePriorities[1] = 4;
    processes[1]->desiredCorePriorities[1] = 0;
    processes[1]->desiredCorePriorities[2] = 2;
    server.corePriorityQueues[1].pop_back();
    server.corePriorityQueues[2].push_back(processes[1]);

    server.distributeCores();
    EXPECT_EQ(3U, processes[0]->logicallyOwnedCores.size());
    EXPECT_EQ(0U, processes[1]->logicallyOwnedCores.size());

    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
    // TODO: Add debug logging (RC Style) to examine the internals of the
    // client queues.
}

TEST_F(CoreArbiterServerTest, distributeCores_coreSharingInsufficientCores) {
    // Test Plan: Create three core arbiter clients, two of which are willing
    // to share and one of which is not.
    // TODO: Examine a case where we should be able to fit and verify that we do
    // fit.
    CoreArbiterServer server(socketPath, memPath, {1, 2, 3}, topology,
                             fakeCoreSegregator, false);

    // Set up three processes
    std::vector<ProcessInfo*> processes;
    for (int i = 0; i < 3; i++) {
        ProcessInfo* process = createProcess(server, i, new ProcessStats());
        processes.push_back(process);
        // Create enough threads to support different cases relative to the
        // total number of cores available.
        for (int j = 0; j < 4; j++) {
            createThread(server, j, process, j, CoreArbiterServer::BLOCKED);
        }
    }

    server.corePriorityQueues[1].push_back(processes[0]);
    server.corePriorityQueues[1].push_back(processes[1]);
    server.corePriorityQueues[1].push_back(processes[2]);

    processes[0]->desiredCorePriorities[1] = 1;
    processes[0]->willShareCores = false;
    processes[1]->desiredCorePriorities[1] = 1;
    processes[2]->desiredCorePriorities[1] = 1;

    server.distributeCores();

    EXPECT_EQ(1U, processes[0]->logicallyOwnedCores.size());
    EXPECT_EQ(1U, processes[1]->logicallyOwnedCores.size());
    EXPECT_EQ(0U, processes[2]->logicallyOwnedCores.size());

    int noShareId = (*processes[0]->logicallyOwnedCores.begin())->id;
    EXPECT_TRUE(noShareId == 2 || noShareId == 3);
    EXPECT_EQ(1, (*processes[1]->logicallyOwnedCores.begin())->id);
}

TEST_F(CoreArbiterServerTest, distributeCores_coreSharingSufficientCores) {
    CoreArbiterServer::testingDoNotChangeManagedCores = true;
    // Test Plan: Create three core arbiter clients, two of which are willing
    // to share and one of which is not. Have enough cores for all of them.
    CoreArbiterServer server(socketPath, memPath, {0, 1, 2, 3}, topology,
                             fakeCoreSegregator, false);

    // Set up three processes
    std::vector<ProcessInfo*> processes;
    for (int i = 0; i < 3; i++) {
        ProcessInfo* process = createProcess(server, i, new ProcessStats());
        processes.push_back(process);
        // Create enough threads to support different cases relative to the
        // total number of cores available.
        for (int j = 0; j < 4; j++) {
            createThread(server, j, process, j, CoreArbiterServer::BLOCKED);
        }
    }

    server.corePriorityQueues[1].push_back(processes[0]);
    server.corePriorityQueues[1].push_back(processes[1]);
    server.corePriorityQueues[1].push_back(processes[2]);

    processes[0]->desiredCorePriorities[1] = 1;
    processes[0]->willShareCores = false;
    processes[1]->desiredCorePriorities[1] = 1;
    processes[2]->desiredCorePriorities[1] = 1;

    server.distributeCores();

    EXPECT_EQ(1U, processes[0]->logicallyOwnedCores.size());
    EXPECT_EQ(1U, processes[1]->logicallyOwnedCores.size());
    EXPECT_EQ(1U, processes[2]->logicallyOwnedCores.size());

    int noShareId = (*processes[0]->logicallyOwnedCores.begin())->id;
    int shareId1 = (*processes[1]->logicallyOwnedCores.begin())->id;
    int shareId2 = (*processes[2]->logicallyOwnedCores.begin())->id;
    if (noShareId == 2 || noShareId == 3) {
        EXPECT_TRUE((shareId1 == 0 && shareId2 == 1) ||
                    (shareId1 == 1 && shareId2 == 0));
    } else {
        EXPECT_TRUE((shareId1 == 2 && shareId2 == 3) ||
                    (shareId1 == 3 && shareId2 == 2));
    }

    CoreArbiterServer::testingDoNotChangeManagedCores = true;
}

TEST_F(CoreArbiterServerTest, distributeCores_multisocket) {
    // Test Plan: Create three core arbiter clients, and a topology with two
    // NUMANode. Verify that the appropriate core allocation was granted to
    // each process in each case below by examining the logicallyOwnedCores in
    // each process.
    Topology::NUMANode nn0{0, {0, 1, 2, 3}};
    Topology::NUMANode nn1{1, {4, 5, 6, 7}};
    std::unordered_map<int, int> coreToHypertwin{
        {0, 1}, {2, 3}, {4, 5}, {6, 7}};

    // Make the map symmetric by adding in the reverse entries.
    topology = Topology({nn0, nn1}, coreToHypertwin);
    fakeCoreSegregator = new FakeCoreSegregator(topology);

    CoreArbiterServer server(socketPath, memPath, {1, 2, 3, 4, 5, 6, 7},
                             topology, fakeCoreSegregator, false);

    std::vector<ProcessInfo*> processes;
    for (int i = 0; i < 3; i++) {
        ProcessInfo* process = createProcess(server, i, new ProcessStats());
        processes.push_back(process);
        // Create enough threads to support different cases relative to the
        // total number of cores available.
        for (int j = 0; j < 4; j++) {
            createThread(server, j, process, j, CoreArbiterServer::BLOCKED);
        }
    }

    server.corePriorityQueues[1].push_back(processes[0]);
    server.corePriorityQueues[1].push_back(processes[1]);
    server.corePriorityQueues[1].push_back(processes[2]);

    processes[0]->desiredCorePriorities[1] = 3;
    processes[0]->willShareCores = false;
    processes[1]->desiredCorePriorities[1] = 2;
    processes[2]->desiredCorePriorities[1] = 1;

    server.distributeCores();

    EXPECT_EQ(3U, processes[0]->logicallyOwnedCores.size());
    EXPECT_EQ(2U, processes[1]->logicallyOwnedCores.size());
    EXPECT_EQ(1U, processes[2]->logicallyOwnedCores.size());

    // Verify that the cores for process 0 are on the second NUMAnode
    int notFoundCount = 0;
    auto& cores = processes[0]->logicallyOwnedCores;
    for (int i = 4; i < 8; i++) {
        if (cores.find(server.coreIdToCore[i]) == cores.end()) {
            notFoundCount++;
        }
    }
    EXPECT_EQ(1, notFoundCount);

    // Verify that the cores for process 1 and 2 are on the correct cores.
    cores = processes[1]->logicallyOwnedCores;
    EXPECT_NE(cores.end(), cores.find(server.coreIdToCore[2]));
    EXPECT_NE(cores.end(), cores.find(server.coreIdToCore[3]));

    cores = processes[2]->logicallyOwnedCores;
    EXPECT_NE(cores.end(), cores.find(server.coreIdToCore[1]));
}

TEST_F(CoreArbiterServerTest, distributeCores_noBlockedThreads) {
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer server(socketPath, memPath, {1, 2, 3}, topology,
                             fakeCoreSegregator, false);
    std::vector<ProcessInfo*> processes;
    for (int i = 0; i < 2; i++) {
        ProcessInfo* process = createProcess(server, i, new ProcessStats());
        processes.push_back(process);
        for (int j = 0; j < 2; j++) {
            createThread(server, j, process, j,
                         CoreArbiterServer::RUNNING_UNMANAGED);
        }
    }
    server.corePriorityQueues[7].push_back(processes[0]);
    server.corePriorityQueues[7].push_back(processes[1]);
    processes[0]->desiredCorePriorities[7] = 2;
    processes[1]->desiredCorePriorities[7] = 2;

    server.distributeCores();
    for (auto coreIdAndCore : server.coreIdToCore) {
        CoreInfo* core = coreIdAndCore.second;
        ASSERT_EQ(core->managedThread, (ThreadInfo*)NULL);
    }

    CoreArbiterServer::testingSkipSocketCommunication = false;

    for (ProcessInfo* process : processes) {
        delete process->stats;
    }
}

TEST_F(CoreArbiterServerTest, distributeCores_niceToHaveSinglePriority) {
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;
    CoreArbiterServer server(socketPath, memPath, {0, 1}, topology,
                             fakeCoreSegregator, false);

    // Set up two processes who each want two cores at the lowest priority
    std::vector<ProcessInfo*> processes;
    for (int i = 0; i < 2; i++) {
        ProcessInfo* process = createProcess(server, i, new ProcessStats());
        processes.push_back(process);
        for (int j = 0; j < 2; j++) {
            createThread(server, j, process, j, CoreArbiterServer::BLOCKED);
        }
    }
    processes[0]->desiredCorePriorities[7] = 2;
    processes[1]->desiredCorePriorities[7] = 2;
    server.corePriorityQueues[7].push_back(processes[0]);
    server.corePriorityQueues[7].push_back(processes[1]);

    // Cores are shared evenly among nice to have threads of the same priority.
    server.distributeCores();
    ASSERT_EQ(processes[0]->stats->numOwnedCores, 1u);
    ASSERT_EQ(processes[1]->stats->numOwnedCores, 1u);
    std::unordered_map<CoreInfo*, ThreadInfo*> savedCoreToThread;
    for (auto coreIdAndCore : server.coreIdToCore) {
        CoreInfo* core = coreIdAndCore.second;
        ASSERT_TRUE(core->managedThread != NULL);
        savedCoreToThread[core] = core->managedThread;
    }

    // Threads already running on a managed core are given priority over blocked
    // ones in core distribution.
    server.distributeCores();
    ASSERT_EQ(processes[0]->stats->numOwnedCores, 1u);
    ASSERT_EQ(processes[1]->stats->numOwnedCores, 1u);
    for (auto coreIdAndCore : server.coreIdToCore) {
        CoreInfo* core = coreIdAndCore.second;
        ASSERT_EQ(core->managedThread, savedCoreToThread[core]);
    }

    // Don't give processes more cores at this priority than they've asked for
    ThreadInfo* removedThread = server.coreIdToCore[1]->managedThread;
    removedThread->process->desiredCorePriorities[7] = 0;
    server.coreIdToCore[1]->managedThread = NULL;
    server.distributeCores();
    ProcessInfo* otherProcess =
        removedThread->process == processes[0] ? processes[1] : processes[0];
    ASSERT_EQ(otherProcess->stats->numOwnedCores, 2u);

    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;

    for (ProcessInfo* process : processes) {
        delete process->stats;
    }
}

TEST_F(CoreArbiterServerTest, distributeCores_niceToHaveMultiplePriorities) {
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;
    CoreArbiterServer server(socketPath, memPath, {0, 1, 2, 3}, topology,
                             fakeCoreSegregator, false);

    // Set up two processes with four threads each, one requesting at a higher
    // nice-to-have priority than the other
    std::vector<ProcessInfo*> processes;
    for (int i = 0; i < 2; i++) {
        ProcessInfo* process = createProcess(server, i, new ProcessStats());
        processes.push_back(process);
        for (int j = 0; j < 4; j++) {
            createThread(server, j, process, j, CoreArbiterServer::BLOCKED);
        }
    }
    ProcessInfo* highPriorityProcess = processes[0];
    ProcessInfo* lowPriorityProcess = processes[1];
    highPriorityProcess->desiredCorePriorities[6] = 3;
    lowPriorityProcess->desiredCorePriorities[7] = 3;
    server.corePriorityQueues[6].push_back(highPriorityProcess);
    server.corePriorityQueues[7].push_back(lowPriorityProcess);

    // Higher priorities are assigned before lower priorities
    server.distributeCores();
    ASSERT_EQ(highPriorityProcess->stats->numOwnedCores, 3u);
    ASSERT_EQ(lowPriorityProcess->stats->numOwnedCores, 1u);

    // Higher priority threads preempt lower priority threads
    highPriorityProcess->desiredCorePriorities[6] = 4;
    server.distributeCores();
    ASSERT_TRUE(lowPriorityProcess->stats->threadCommunicationBlocks[0]
                    .coreReleaseRequested ||
                lowPriorityProcess->stats->threadCommunicationBlocks[1]
                    .coreReleaseRequested ||
                lowPriorityProcess->stats->threadCommunicationBlocks[2]
                    .coreReleaseRequested ||
                lowPriorityProcess->stats->threadCommunicationBlocks[3]
                    .coreReleaseRequested);
    ASSERT_EQ(server.timerFdToInfo.size(), 1u);
    ASSERT_EQ(highPriorityProcess->stats->numOwnedCores, 3u);

    // Higher priority threads aren't placed on a core before the preempted
    // thread has timed out
    server.distributeCores();
    ASSERT_EQ(highPriorityProcess->stats->numOwnedCores, 3u);

    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;

    for (ProcessInfo* process : processes) {
        delete process->stats;
    }
}

TEST_F(CoreArbiterServerTest, timeoutThreadPreemption_basic) {
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1}, topology,
                             fakeCoreSegregator, false);
    server.preemptionTimeout = 1;  // For faster testing

    ProcessStats processStats;
    CoreInfo* core = server.coreIdToCore[1];

    ProcessInfo* process = createProcess(server, 1, &processStats);
    ThreadInfo* thread = createThread(server, 1, process, 1,
                                      CoreArbiterServer::RUNNING_MANAGED, core);

    // If the client is cooperative, nothing should happen
    server.requestCoreRelease(core);
    core->managedThread = NULL;

    // Make sure the timer event for preemption is actually processed to avoid
    // double-firing on the later handleEvents call.
    while (server.timerFdToInfo.size())
        server.handleEvents();
    ASSERT_EQ(thread->state, CoreArbiterServer::RUNNING_MANAGED);

    // If client is uncooperative, the thread should be removed from its core
    thread->core = core;
    core->managedThread = thread;
    core->coreReleaseRequested = false;
    server.requestCoreRelease(core);
    server.handleEvents();
    ASSERT_EQ(thread->state, CoreArbiterServer::RUNNING_PREEMPTED);
    ASSERT_EQ(core->managedThread, (ThreadInfo*)NULL);
    ASSERT_EQ(process->stats->numOwnedCores, 0u);

    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, timeoutThreadPreemption_invalidateOldTimeout) {
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1, 2}, topology,
                             fakeCoreSegregator, false);

    ProcessStats processStats;
    CoreInfo* core = server.coreIdToCore[1];

    ProcessInfo* process = createProcess(server, 1, &processStats);
    ThreadInfo* thread = createThread(server, 1, process, 1,
                                      CoreArbiterServer::RUNNING_MANAGED, core);

    // Simulate a timer going off for a process who previously released a core
    server.timerFdToInfo[1] = {1, core};
    core->managedThread = NULL;
    server.timeoutThreadPreemption(1);

    ASSERT_EQ(thread->state, CoreArbiterServer::RUNNING_MANAGED);

    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, cleanupConnection) {
    CoreArbiterServer::testingSkipCoreDistribution = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;
    // Prevent close calls since we're not using real sockets
    sys->closeErrno = 1;

    CoreArbiterServer server(socketPath, memPath, {1}, topology,
                             fakeCoreSegregator, false);

    // Set up a process with three threads: one managed, one preempted, and
    // one blocked
    ProcessStats processStats;
    processStats.preemptedCount = 1;
    CoreInfo* core = server.coreIdToCore[1];
    ProcessInfo* process = createProcess(server, 1, &processStats);
    ThreadInfo* managedThread = createThread(
        server, 1, process, 1, CoreArbiterServer::RUNNING_MANAGED, core);
    ThreadInfo* preemptedThread = createThread(
        server, 2, process, 2, CoreArbiterServer::RUNNING_PREEMPTED);
    ThreadInfo* blockedThread =
        createThread(server, 3, process, 3, CoreArbiterServer::BLOCKED);

    server.cleanupConnection(managedThread->socket);
    ASSERT_TRUE(
        process->threadStateToSet[CoreArbiterServer::RUNNING_MANAGED].empty());
    ASSERT_EQ(server.threadSocketToInfo.find(1),
              server.threadSocketToInfo.end());
    ASSERT_EQ(core->managedThread, (ThreadInfo*)NULL);
    ASSERT_EQ(process->stats->numOwnedCores, 0u);
    ASSERT_EQ(process->stats->unpreemptedCount, 0u);
    ASSERT_EQ(server.processIdToInfo.size(), 1u);

    preemptedThread->corePreemptedFrom = core;
    process->coresPreemptedFrom[core] = preemptedThread;
    server.cleanupConnection(preemptedThread->socket);
    ASSERT_TRUE(process->threadStateToSet[CoreArbiterServer::RUNNING_PREEMPTED]
                    .empty());
    ASSERT_EQ(server.threadSocketToInfo.find(2),
              server.threadSocketToInfo.end());
    ASSERT_EQ(process->stats->numOwnedCores, 0u);
    ASSERT_EQ(process->stats->unpreemptedCount, 1u);
    ASSERT_EQ(server.processIdToInfo.size(), 1u);

    server.cleanupConnection(blockedThread->socket);
    ASSERT_EQ(server.threadSocketToInfo.find(3),
              server.threadSocketToInfo.end());
    ASSERT_EQ(server.processIdToInfo.size(), 0u);

    CoreArbiterServer::testingSkipCoreDistribution = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
    sys->closeErrno = 0;
}

TEST_F(CoreArbiterServerTest, advisoryLock_multiServer) {
    CoreArbiterServer server(socketPath, memPath, {1, 2}, topology,
                             fakeCoreSegregator, false);
    ASSERT_DEATH(CoreArbiterServer(socketPath, memPath, {1, 2}, topology,
                                   fakeCoreSegregator, false),
                 "Error acquiring advisory lock:.*");
}
}  // namespace CoreArbiter
