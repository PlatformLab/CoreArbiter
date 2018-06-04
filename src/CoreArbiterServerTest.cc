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
#include "Logger.h"
#include "MockSyscall.h"

#undef private
#include "gtest/gtest.h"

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
        : socketPath("/tmp/CoreArbiter/testsocket"),
          memPath("/tmp/CoreArbiter/testmem") {
        Logger::setLogLevel(ERROR);

        sys = new MockSyscall();
        CoreArbiterServer::sys = sys;

        int fd[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
        clientSocket = fd[0];
        serverSocket = fd[1];
    }

    ~CoreArbiterServerTest() {
        close(clientSocket);
        close(serverSocket);
        delete sys;
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
            server.managedThreads.push_back(thread);
            process->stats->numOwnedCores++;
            thread->core = core;
            core->managedThread = thread;
        } else if (state == CoreArbiterServer::RUNNING_PREEMPTED) {
            process->stats->preemptedCount++;
        }
        return thread;
    }

    void makeUnmanagedCoresManaged(CoreArbiterServer& server) {
        server.managedCores.insert(server.managedCores.end(),
                                   server.unmanagedCores.begin(),
                                   server.unmanagedCores.end());
        server.unmanagedCores.erase(server.unmanagedCores.begin());
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
    CoreArbiterServer::testingSkipCpusetAllocation = true;

    CoreArbiterServer server(socketPath, memPath, {}, false);
    ASSERT_EQ(server.unmanagedCores.size(),
              std::thread::hardware_concurrency() - 1);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
}

TEST_F(CoreArbiterServerTest, threadBlocking_basic) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;

    CoreArbiterServer server(socketPath, memPath, {1}, false);
    makeUnmanagedCoresManaged(server);
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
    thread->core = server.managedCores[0];
    thread->state = CoreArbiterServer::RUNNING_MANAGED;
    server.threadBlocking(socket);
    ASSERT_EQ(thread->state, CoreArbiterServer::RUNNING_MANAGED);
    ASSERT_EQ(processStats.numBlockedThreads, 0u);

    // If the server has requested cores back, this call succeeds
    processStats.threadCommunicationBlocks[server.managedCores[0]->id]
        .coreReleaseRequested = true;
    server.threadBlocking(socket);
    ASSERT_EQ(thread->state, CoreArbiterServer::BLOCKED);
    ASSERT_EQ(processStats.numBlockedThreads, 1u);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingSkipCoreDistribution = false;
}

TEST_F(CoreArbiterServerTest, threadBlocking_preemptedThread) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1}, false);
    makeUnmanagedCoresManaged(server);

    pid_t processId = 0;
    pid_t threadId = 1;
    int socket = 2;
    ProcessStats processStats;
    processStats.threadCommunicationBlocks[server.managedCores[0]->id]
        .coreReleaseRequested = true;
    ProcessInfo* process = createProcess(server, processId, &processStats);
    ThreadInfo* thread = createThread(server, threadId, process, socket,
                                      CoreArbiterServer::RUNNING_PREEMPTED);
    thread->corePreemptedFrom = server.managedCores[0];
    process->coresPreemptedFrom.insert(server.managedCores[0]);

    // A preempted thread blocking counts as releasing a core
    server.threadBlocking(socket);
    ASSERT_EQ(thread->state, CoreArbiterServer::BLOCKED);
    ASSERT_EQ(processStats.preemptedCount, 1u);
    ASSERT_EQ(processStats.unpreemptedCount, 1u);
    ASSERT_EQ(processStats.numBlockedThreads, 1u);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingSkipCoreDistribution = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, threadBlocking_movePreemptedThread) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1}, false);
    makeUnmanagedCoresManaged(server);

    pid_t processId = 0;
    pid_t threadId1 = 1;
    pid_t threadId2 = 2;
    int socket1 = 3;
    int socket2 = 4;
    ProcessStats processStats;
    ProcessInfo* process = createProcess(server, processId, &processStats);
    ThreadInfo* thread1 = createThread(server, threadId1, process, socket1,
                                       CoreArbiterServer::RUNNING_MANAGED,
                                       server.managedCores[0]);
    ThreadInfo* thread2 = createThread(server, threadId2, process, socket2,
                                       CoreArbiterServer::RUNNING_PREEMPTED);
    thread2->corePreemptedFrom = server.managedCores[0];

    // When a thread blocks without being asked to, it is a no-op.
    server.threadBlocking(socket1);
    ASSERT_EQ(thread1->state, CoreArbiterServer::RUNNING_MANAGED);
    ASSERT_EQ(thread2->state, CoreArbiterServer::RUNNING_PREEMPTED);
    ASSERT_EQ(process->stats->numOwnedCores, 1u);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingSkipCoreDistribution = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, coresRequested) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1}, false);
    makeUnmanagedCoresManaged(server);

    ProcessStats processStats;
    ProcessInfo* process = createProcess(server, 1, &processStats);
    createThread(server, 1, process, serverSocket,
                 CoreArbiterServer::RUNNING_UNMANAGED);

    // Request 1 core at each priority and make sure this process is on the wait
    // list for every priority
    std::vector<uint32_t> coreRequest = {1, 1, 1, 1, 1, 1, 1, 1};
    send(clientSocket, &coreRequest[0], sizeof(uint32_t) * 8, 0);
    server.coresRequested(serverSocket);
    for (size_t i = 0; i < coreRequest.size(); i++) {
        ASSERT_EQ(server.corePriorityQueues[i].size(), 1u);
        ASSERT_EQ(process->desiredCorePriorities[i], coreRequest[i]);
    }

    // Adding an additional request shouldn't change anything but the process's
    // number of desired cores
    coreRequest = {2, 2, 2, 2, 2, 2, 2, 2};
    send(clientSocket, &coreRequest[0], sizeof(uint32_t) * 8, 0);
    server.coresRequested(serverSocket);
    for (size_t i = 0; i < coreRequest.size(); i++) {
        ASSERT_EQ(server.corePriorityQueues[i].size(), 1u);
        ASSERT_EQ(process->desiredCorePriorities[i], coreRequest[i]);
    }

    // Request fewer cores. This shouldn't change the fact that we're in the
    // core priority queue
    coreRequest = {2, 2, 2, 2, 1, 1, 1, 1};
    send(clientSocket, &coreRequest[0], sizeof(uint32_t) * 8, 0);
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
    server.coresRequested(serverSocket);
    for (size_t i = 0; i < coreRequest.size(); i++) {
        ASSERT_EQ(server.corePriorityQueues[i].size(), 0u);
        ASSERT_EQ(process->desiredCorePriorities[i], coreRequest[i]);
    }

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingSkipCoreDistribution = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, distributeCores_noBlockedThreads) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1, 2, 3}, false);
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
    ASSERT_TRUE(server.managedThreads.empty());
    for (CoreInfo* core : server.managedCores) {
        ASSERT_EQ(core->managedThread, (ThreadInfo*)NULL);
    }

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;

    for (ProcessInfo* process : processes) {
        delete process->stats;
    }
}

TEST_F(CoreArbiterServerTest, distributeCores_niceToHaveSinglePriority) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1, 2}, false);

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
    ASSERT_EQ(server.managedThreads.size(), 2u);
    ASSERT_EQ(processes[0]->stats->numOwnedCores, 1u);
    ASSERT_EQ(processes[1]->stats->numOwnedCores, 1u);
    std::unordered_map<CoreInfo*, ThreadInfo*> savedCoreToThread;
    for (CoreInfo* core : server.managedCores) {
        ASSERT_TRUE(core->managedThread != NULL);
        savedCoreToThread[core] = core->managedThread;
    }

    // Threads already running on a managed core are given priority over blocked
    // ones in core distribution.
    server.distributeCores();
    ASSERT_EQ(server.managedThreads.size(), 2u);
    ASSERT_EQ(processes[0]->stats->numOwnedCores, 1u);
    ASSERT_EQ(processes[1]->stats->numOwnedCores, 1u);
    for (CoreInfo* core : server.managedCores) {
        ASSERT_EQ(core->managedThread, savedCoreToThread[core]);
    }

    // Don't give processes more cores at this priority than they've asked for
    ThreadInfo* removedThread = server.managedCores[0]->managedThread;
    removedThread->process->desiredCorePriorities[7] = 0;
    server.managedThreads.erase(std::remove(server.managedThreads.begin(),
                                            server.managedThreads.end(),
                                            removedThread));
    server.managedCores[0]->managedThread = NULL;
    server.distributeCores();
    ProcessInfo* otherProcess =
        removedThread->process == processes[0] ? processes[1] : processes[0];
    ASSERT_EQ(server.managedThreads.size(), 2u);
    ASSERT_EQ(otherProcess->stats->numOwnedCores, 2u);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;

    for (ProcessInfo* process : processes) {
        delete process->stats;
    }
}

TEST_F(CoreArbiterServerTest, distributeCores_niceToHaveMultiplePriorities) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1, 2, 3, 4}, false);

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
    ASSERT_EQ(server.managedThreads.size(), 4u);
    ASSERT_EQ(highPriorityProcess->stats->numOwnedCores, 3u);
    ASSERT_EQ(lowPriorityProcess->stats->numOwnedCores, 1u);

    // Higher priority threads preempt lower priority threads
    highPriorityProcess->desiredCorePriorities[6] = 4;
    server.distributeCores();
    ASSERT_TRUE(lowPriorityProcess->stats
                    ->threadCommunicationBlocks[server.managedCores[0]->id]
                    .coreReleaseRequested ||
                lowPriorityProcess->stats
                    ->threadCommunicationBlocks[server.managedCores[1]->id]
                    .coreReleaseRequested ||
                lowPriorityProcess->stats
                    ->threadCommunicationBlocks[server.managedCores[2]->id]
                    .coreReleaseRequested ||
                lowPriorityProcess->stats
                    ->threadCommunicationBlocks[server.managedCores[3]->id]
                    .coreReleaseRequested);
    ASSERT_EQ(server.timerFdToInfo.size(), 1u);
    ASSERT_EQ(highPriorityProcess->stats->numOwnedCores, 3u);

    // Higher priority threads aren't placed on a core before the preempted
    // thread has timed out
    server.distributeCores();
    ASSERT_EQ(highPriorityProcess->stats->numOwnedCores, 3u);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;

    for (ProcessInfo* process : processes) {
        delete process->stats;
    }
}

TEST_F(CoreArbiterServerTest, distributeCores_scaleUnmanagedCore) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1}, false);

    ProcessStats processStats;
    ProcessInfo* process = createProcess(server, 1, &processStats);
    createThread(server, 1, process, 1, CoreArbiterServer::BLOCKED);
    process->desiredCorePriorities[0] = 1;
    server.corePriorityQueues[0].push_back(process);

    ASSERT_EQ(server.managedCores.size(), 0u);
    ASSERT_EQ(server.unmanagedCores.size(), 1u);

    // Scale up
    server.distributeCores();
    ASSERT_EQ(server.managedCores.size(), 1u);
    ASSERT_EQ(server.unmanagedCores.size(), 0u);

    // distributeCores() shouldn't cause unmanaged cpuset to scale down
    process->desiredCorePriorities[0] = 0;
    server.corePriorityQueues[0].pop_front();
    server.managedCores[0]->managedThread = NULL;
    server.distributeCores();
    ASSERT_EQ(server.managedCores.size(), 1u);
    ASSERT_EQ(server.unmanagedCores.size(), 0u);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, handleEvents_scaleUnmanagedCore) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1}, false);
    makeUnmanagedCoresManaged(server);

    // The server should wake up to move its unused managed cores to the
    // unmanaged cpuset
    uint64_t now = Cycles::rdtsc();
    server.unmanagedCpusetLastUpdate = now;
    server.managedCores[0]->threadRemovalTime = now;
    server.handleEvents();
    ASSERT_EQ(server.managedCores.size(), 0u);
    ASSERT_EQ(server.unmanagedCores.size(), 1u);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, timeoutThreadPreemption_basic) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1}, false);
    makeUnmanagedCoresManaged(server);
    server.preemptionTimeout = 1;  // For faster testing

    ProcessStats processStats;
    CoreInfo* core = server.managedCores[0];

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
    server.requestCoreRelease(core);
    server.handleEvents();
    ASSERT_EQ(thread->state, CoreArbiterServer::RUNNING_PREEMPTED);
    ASSERT_EQ(core->managedThread, (ThreadInfo*)NULL);
    ASSERT_EQ(process->stats->numOwnedCores, 0u);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, timeoutThreadPreemption_invalidateOldTimeout) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipSocketCommunication = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;

    CoreArbiterServer server(socketPath, memPath, {1, 2}, false);
    makeUnmanagedCoresManaged(server);

    ProcessStats processStats;
    CoreInfo* core = server.managedCores[0];

    ProcessInfo* process = createProcess(server, 1, &processStats);
    ThreadInfo* thread = createThread(server, 1, process, 1,
                                      CoreArbiterServer::RUNNING_MANAGED, core);

    // Simulate a timer going off for a process who previously released a core
    server.timerFdToInfo[1] = {1, core};
    core->managedThread = NULL;
    server.timeoutThreadPreemption(1);

    ASSERT_EQ(thread->state, CoreArbiterServer::RUNNING_MANAGED);

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipSocketCommunication = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
}

TEST_F(CoreArbiterServerTest, cleanupConnection) {
    CoreArbiterServer::testingSkipCpusetAllocation = true;
    CoreArbiterServer::testingSkipCoreDistribution = true;
    CoreArbiterServer::testingDoNotChangeManagedCores = true;
    // Prevent close calls since we're not using real sockets
    sys->closeErrno = 1;

    CoreArbiterServer server(socketPath, memPath, {1}, false);
    makeUnmanagedCoresManaged(server);

    // Set up a process with three threads: one managed, one preempted, and
    // one blocked
    ProcessStats processStats;
    processStats.preemptedCount = 1;
    CoreInfo* core = server.managedCores[0];
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
    ASSERT_EQ(std::find(server.managedThreads.begin(),
                        server.managedThreads.end(), managedThread),
              server.managedThreads.end());
    ASSERT_EQ(core->managedThread, (ThreadInfo*)NULL);
    ASSERT_EQ(process->stats->numOwnedCores, 0u);
    ASSERT_EQ(process->stats->unpreemptedCount, 0u);
    ASSERT_EQ(server.processIdToInfo.size(), 1u);

    preemptedThread->corePreemptedFrom = server.managedCores[0];
    process->coresPreemptedFrom.insert(server.managedCores[0]);
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

    CoreArbiterServer::testingSkipCpusetAllocation = false;
    CoreArbiterServer::testingSkipCoreDistribution = false;
    CoreArbiterServer::testingDoNotChangeManagedCores = false;
    sys->closeErrno = 0;
}

TEST_F(CoreArbiterServerTest, advisoryLock_multiServer) {
    CoreArbiterServer server(socketPath, memPath, {1, 2}, false);
    ASSERT_DEATH(CoreArbiterServer(socketPath, memPath, {1, 2}, false),
                 "Error acquiring advisory lock:.*");
}
}  // namespace CoreArbiter
