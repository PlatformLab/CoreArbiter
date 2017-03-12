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

#include <algorithm>
#include <assert.h>
#include <iostream>
#include <sys/un.h>
#include <thread>

#include "CoreArbiterServer.h"
#include "Logger.h"

namespace CoreArbiter {

std::string CoreArbiterServer::cpusetPath = "/sys/fs/cgroup/cpuset";

static Syscall defaultSyscall;
Syscall* CoreArbiterServer::sys = &defaultSyscall;
bool CoreArbiterServer::testingSkipCpusetAllocation = false;
bool CoreArbiterServer::testingSkipCoreDistribution = false;

CoreArbiterServer::CoreArbiterServer(std::string socketPath,
                                     std::string sharedMemPathPrefix,
                                     std::vector<core_t> exclusiveCoreIds)
    : socketPath(socketPath)
    , listenSocket(-1)
    , sharedMemPathPrefix(sharedMemPathPrefix)
    , epollFd(-1)
    , preemptionTimeout(RELEASE_TIMEOUT_MS)
    , exclusiveCores(exclusiveCoreIds.size())
    , corePriorityQueues(NUM_PRIORITIES)
{
    if (sys->geteuid()) {
        LOG(ERROR, "The core arbiter server must be run as root\n");
        exit(-1);
    }

    std::string arbiterCpusetPath = cpusetPath + "/CoreArbiter";
    if (!testingSkipCpusetAllocation) {
        // Remove any old cpusets from a previous server
        removeOldCpusets(arbiterCpusetPath);

        // Create a new cpuset directory for core arbitration. Since this is
        // going to be a parent of all the arbiter's individual core cpusets, it
        // needs to include every core.
        unsigned numCores = std::thread::hardware_concurrency();
        std::string allCores = "0-" + std::to_string(numCores - 1);
        createCpuset(arbiterCpusetPath, allCores, "0");
        // Set up exclusive cores
        for (core_t core : exclusiveCoreIds) {
            std::string exclusiveCpusetPath =
                arbiterCpusetPath + "/Exclusive" + std::to_string(core);
            createCpuset(exclusiveCpusetPath, std::to_string(core), "0");
        }

        // Set up cpuset for all other processes. For now, core 0 is always
        // unmanaged.
        std::string unmanagedCpusetPath = arbiterCpusetPath + "/Unmanaged";
        createCpuset(unmanagedCpusetPath, "0", "0");

        // Move all of the currently running processes to the unmanaged cpuset
        std::string allProcsPath = cpusetPath + "/cgroup.procs";
        std::string unmanagedProcsPath = unmanagedCpusetPath + "/cgroup.procs";
        moveProcsToCpuset(allProcsPath, unmanagedProcsPath);

        // Cpusets should be set up properly now, so we'll save the files needed
        // for moving processes between cpusets
        std::string unmanagedTasksPath = unmanagedCpusetPath + "/tasks";
        unmanagedCore.id = 0;
        unmanagedCore.cpusetFile.open(unmanagedTasksPath);
        if (!unmanagedCore.cpusetFile.is_open()) {
            LOG(ERROR, "Unable to open %s\n", unmanagedTasksPath.c_str());
            exit(-1);
        }
    }

    for (size_t i = 0; i < exclusiveCoreIds.size(); i++) {
        core_t coreId = exclusiveCoreIds[i];
        std::string exclusiveTasksPath = arbiterCpusetPath + "/Exclusive" +
                                         std::to_string(coreId) + "/tasks";

        struct CoreInfo* coreInfo = &exclusiveCores[i];
        coreInfo->id = coreId;

        if (!testingSkipCpusetAllocation) {
            coreInfo->cpusetFile.open(exclusiveTasksPath);
            if (!coreInfo->cpusetFile.is_open()) {
                LOG(ERROR, "Unable to open %s\n", exclusiveTasksPath.c_str());
                exit(-1);
            }
        }
    }

    ensureParents(socketPath.c_str(), 0777);
    ensureParents(sharedMemPathPrefix.c_str(), 0777);

    // Set up unix domain socket
    listenSocket = sys->socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenSocket < 0) {
        LOG(ERROR, "Error creating listen socket: %s\n", strerror(errno));
        exit(-1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

    // This will fail if the socket doesn't already exist. Ignore the error.
    sys->unlink(addr.sun_path);

    if (sys->bind(listenSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listenSocket);
        LOG(ERROR, "Error binding listen socket: %s\n", strerror(errno));
        exit(-1);
    }

    if (sys->listen(listenSocket, 10) < 0) { // TODO: backlog size?
        close(listenSocket);
        LOG(ERROR, "Error listening: %s\n", strerror(errno));
        exit(-1);
    }

    // Our clients are not necessarily root
    if (sys->chmod(addr.sun_path, 0777) < 0) {
        close(listenSocket);
        LOG(ERROR, "Error on chmod for %s: %s\n",
            addr.sun_path, strerror(errno));
        exit(-1);
    }

    // Set up epoll
    epollFd = sys->epoll_create(MAX_EPOLL_EVENTS);
    if (epollFd < 0) {
        close(listenSocket);
        LOG(ERROR, "Error on epoll_create: %s\n", strerror(errno));
        exit(-1);
    }

    struct epoll_event listenEvent;
    listenEvent.events = EPOLLIN | EPOLLRDHUP;
    listenEvent.data.fd = listenSocket;
    if (sys->epoll_ctl(epollFd, EPOLL_CTL_ADD, listenSocket,
                       &listenEvent) < 0) {
        sys->close(listenSocket);
        LOG(ERROR, "Error adding listenSocket %d to epoll: %s\n",
                listenSocket, strerror(errno));
        exit(-1);
    }
}

CoreArbiterServer::~CoreArbiterServer()
{
    sys->close(listenSocket);
    if (remove(socketPath.c_str()) != 0) {
        LOG(ERROR, "Error deleting socket file: %s\n", strerror(errno));
    }
}

/**
 * A wrapper around handleEvents() which does the meat of request
 * handling. It's useful to separate out the loop for testing.
 */
void
CoreArbiterServer::startArbitration()
{
    while (true) {
        handleEvents();
    }
}

void CoreArbiterServer::handleEvents()
{
    struct epoll_event events[MAX_EPOLL_EVENTS];
    int numFds = sys->epoll_wait(epollFd, events, MAX_EPOLL_EVENTS, -1);
    if (numFds < 0) {
        LOG(ERROR, "Error on epoll_wait: %s\n", strerror(errno));
        return;
    }

    for (int i = 0; i < numFds; i++) {
        int socket = events[i].data.fd;

        if (events[i].events & EPOLLRDHUP) {
            // A thread exited or otherwise closed its connection
            LOG(NOTICE, "detected closed connection for fd %d\n", socket);
            sys->epoll_ctl(epollFd, EPOLL_CTL_DEL,
                           socket, &events[i]);
            cleanupConnection(socket);
        } else if (socket == listenSocket) {
            // A new thread is connecting
            acceptConnection(listenSocket);
        } else if (timerFdToProcess.find(socket)
                    != timerFdToProcess.end()) {
            // Core retrieval timer timeout
            timeoutThreadPreemption(socket);
            sys->epoll_ctl(epollFd, EPOLL_CTL_DEL,
                           socket, &events[i]);
        } else {
            // Thread is making some sort of request
            if (!(events[i].events & EPOLLIN)) {
                LOG(WARNING, "Did not receive a message type.\n");
                continue;
            }

            uint8_t msgType;
            if (!readData(socket, &msgType, sizeof(uint8_t),
                         "Error reading message type")) {
                continue;
            }

            switch(msgType) {
                case THREAD_BLOCK:
                    threadBlocking(socket);
                    break;
                case CORE_REQUEST:
                    coresRequested(socket);
                    break;
                case COUNT_BLOCKED_THREADS:
                    countBlockedThreads(socket);
                    break;
                case TOTAL_AVAILABLE_CORES:
                    totalAvailableCores(socket);
                    break;
                default:
                    LOG(ERROR, "Unknown message type: %u\n", msgType);
                    break;
            }
        }
    }
    LOG(NOTICE, "\n");
}

void
CoreArbiterServer::acceptConnection(int listenSocket)
{
    struct sockaddr_un remoteAddr;
    socklen_t len = sizeof(struct sockaddr_un);
    int socket =
        sys->accept(listenSocket, (struct sockaddr *)&remoteAddr, &len);
    if (socket < 0) {
        LOG(ERROR, "Error accepting connection on listenSocket: %s\n",
                strerror(errno));
        return;
    }

    // Add new connection to epoll events list
    struct epoll_event processEvent;
    processEvent.events = EPOLLIN | EPOLLRDHUP;
    processEvent.data.fd = socket;
    if (sys->epoll_ctl(epollFd, EPOLL_CTL_ADD, socket, &processEvent) < 0) {
        LOG(ERROR, "Error adding socket to epoll: %s\n", strerror(errno));
        return;
    }

    // Read connecting process ID from socket.
    pid_t processId;
    if (!readData(socket, &processId, sizeof(pid_t),
                   "Error receiving process ID")) {
        return;
    }

    pid_t threadId;
    if (!readData(socket, &threadId, sizeof(pid_t),
                  "Error receiving thread ID")) {
        return;
    }

    if (processIdToInfo.find(processId) == processIdToInfo.end()) {
        // This is a new process, so we need to do some setup.
        // Construct shared memory page
        std::string sharedMemPath = sharedMemPathPrefix +
                                    std::to_string(processId);
        int sharedMemFd = sys->open(sharedMemPath.c_str(),
                                   O_CREAT | O_RDWR | O_TRUNC, S_IRWXU);
        if (sharedMemFd < 0) {
            LOG(ERROR, "Error opening shared memory page: %s\n",
                strerror(errno));
            return;
        }

        // Our clients are not necessarily root
        sys->chmod(sharedMemPath.c_str(), 0777);

        size_t sharedMemSize = sizeof(core_t) + sizeof(bool);
        sys->ftruncate(sharedMemFd, sharedMemSize);        
        core_t* coreReleaseRequestCount =
            (core_t *)sys->mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
                                 MAP_SHARED, sharedMemFd, 0);
        if (coreReleaseRequestCount == MAP_FAILED) {
            LOG(ERROR, "Error on mmap: %s\n", strerror(errno));
            // TODO: send error to client
            return;
        }
        bool* threadPreempted = (bool*)(coreReleaseRequestCount + 1);
        printf("%p %p\n", coreReleaseRequestCount, threadPreempted);
        *coreReleaseRequestCount = 0;
        *threadPreempted = false;

        // Send location of shared memory to the application.
        // First in the packet is the size of the path, followed by the path
        // itself. The path is null termianted, and the size includes the \0.
        size_t pathLen = sharedMemPath.size() + 1;
        char pathPacket[sizeof(size_t) + pathLen];
        memcpy(pathPacket, &pathLen, sizeof(size_t));
        memcpy(pathPacket + sizeof(size_t), sharedMemPath.c_str(), pathLen);
        if (!sendData(socket, pathPacket, sizeof(pathPacket),
                      "Sending shared memory path failed")) {
            return;
        }

        // Update process information since everything succeeded
        processIdToInfo[processId] = new ProcessInfo(
            processId, sharedMemFd, coreReleaseRequestCount, threadPreempted);

        LOG(NOTICE, "Registered process with id %d on socket %d\n",
               processId, socket);
    }

    struct ThreadInfo* thread = new ThreadInfo(threadId,
                                               processIdToInfo[processId],
                                               socket);
    threadSocketToInfo[socket] = thread;
    processIdToInfo[processId]->threadStateToSet[RUNNING_UNMANAGED]
                                .insert(thread);

    LOG(NOTICE, "Registered thread with id %d on process %d\n",
           threadId, processId);
}


void
CoreArbiterServer::threadBlocking(int socket)
{
    if (threadSocketToInfo.find(socket) == threadSocketToInfo.end()) {
        LOG(WARNING, "Unknown thread is blocking\n");
        return;
    }

    struct ThreadInfo* thread = threadSocketToInfo[socket];
    LOG(NOTICE, "Thread %d is blocking\n", thread->id);

    if (thread->state == BLOCKED) {
        LOG(WARNING, "Thread %d was already blocked\n", thread->id);
        return;
    }

    struct ProcessInfo* process = thread->process;
    bool processOwesCore =
        *(process->coreReleaseRequestCount) > process->coreReleaseCount;
    bool shouldDistributeCores = true;

    if (thread->state == RUNNING_EXCLUSIVE && processOwesCore) {
        LOG(NOTICE, "Removing thread %d from core %lu\n",
            thread->id, thread->core->id);
        process->coreReleaseCount++;
        struct CoreInfo* core = thread->core;
        removeThreadFromExclusiveCore(thread);

        auto& runningPreemptedSet =
            thread->process->threadStateToSet[RUNNING_PREEMPTED];
        if (!runningPreemptedSet.empty()) {
            // This process previously had a thread preempted and moved to the
            // unmanaged core, but now that it has complied we can move its
            // thread back onto an exclusive core.
            struct ThreadInfo* unmanagedThread = *(runningPreemptedSet.begin());
            LOG(NOTICE, "Moving previously preempted thread %d back to "
                        "exclusive core\n", unmanagedThread->id);
            moveThreadToExclusiveCore(unmanagedThread, core);
            shouldDistributeCores = false;
        }
    } else if (thread->state == RUNNING_EXCLUSIVE && !processOwesCore) {
        // This process has not been asked to release a core, so don't
        // allow it to block.
        LOG(WARNING, "Thread %d should not be blocking\n", thread->id);
        return;
    } else if (thread->state == RUNNING_PREEMPTED && processOwesCore) {
        LOG(NOTICE, "Preempted thread %d is blocking\n", thread->id);
        process->coreReleaseCount++;
    } else if (thread->state == RUNNING_PREEMPTED && !processOwesCore) {
        LOG(WARNING, "Inconsistent state! Thread %d was preempted, but its "
                     "process does not owe a core.\n", thread->id);
    }

    changeThreadState(thread, BLOCKED);
    if (thread->process->threadStateToSet[RUNNING_PREEMPTED].empty()) {
        *(process->threadPreempted) = false;
    }
    if (shouldDistributeCores) {
        distributeCores();
    }
}

void
CoreArbiterServer::coresRequested(int socket)
{
    core_t numCoresArr[NUM_PRIORITIES];
    if (!readData(socket, &numCoresArr, sizeof(core_t) * NUM_PRIORITIES,
                 "Error receiving number of cores requested")) {
        return;
    }

    struct ThreadInfo* thread = threadSocketToInfo[socket];
    struct ProcessInfo* process = thread->process;

    LOG(DEBUG, "Received core request from process %d:", process->id);
    for (size_t i = 0; i < NUM_PRIORITIES; i++) {
        LOG(DEBUG, " %lu", numCoresArr[i]);
    }
    LOG(DEBUG, "\n");

    bool desiredCoresChanged = false;
    core_t remainingCoresOwned = process->totalCoresOwned;

    for (size_t priority = 0; priority < NUM_PRIORITIES; priority++) {
        // Update information for a single priority
        core_t prevNumCoresDesired = process->desiredCorePriorities[priority];
        core_t numCoresDesired = numCoresArr[priority];
        core_t numCoresOwned = std::min(remainingCoresOwned, numCoresDesired);
        remainingCoresOwned -= numCoresOwned;

        process->desiredCorePriorities[priority] = numCoresDesired;

        if (numCoresDesired != prevNumCoresDesired) {
            desiredCoresChanged = true;
        }

        if (numCoresDesired > 0 && prevNumCoresDesired == 0) {
            // This process wants a core at a priority that it previously did
            // not, so we need to add it to the priority queue
            corePriorityQueues[priority].push_back(process);
        } else if (numCoresDesired == 0 && prevNumCoresDesired > 0) {
            // This process previously wanted a core at this priority and no
            // longer does, so we need to remove it from the priority queue
            auto& queue = corePriorityQueues[priority];
            queue.erase(std::find(queue.begin(), queue.end(), process));
        }
    }

    if (remainingCoresOwned > 0) {
        // The application is voluntarily giving up cores, so we need to give
        // it permission to block threads.
        *(process->coreReleaseRequestCount) += remainingCoresOwned;
    }

    if (desiredCoresChanged) {
        // Even if the total number of cores this process wants is the same, we
        // may need to shuffle cores around because of priority changes.
        distributeCores();
    }
}

void
CoreArbiterServer::countBlockedThreads(int socket)
{
    if (threadSocketToInfo.find(socket) == threadSocketToInfo.end()) {
        LOG(WARNING, "Unknown connection is asking for blocked thread count\n");
        return;
    }

    struct ProcessInfo* process = threadSocketToInfo[socket]->process;
    size_t numBlockedThreads = process->threadStateToSet[BLOCKED].size();
    LOG(NOTICE,
        "Process %d has requested its number of blocked threads (%lu)\n",
        process->id, numBlockedThreads);

    sendData(socket, &numBlockedThreads, sizeof(size_t),
             "Error sending number of blocked threads");
}

void
CoreArbiterServer::timeoutThreadPreemption(int timerFd)
{
    uint64_t time;
    read(timerFd, &time, sizeof(uint64_t));

    struct ProcessInfo* process = timerFdToProcess[timerFd];

    if (*(process->coreReleaseRequestCount) == process->coreReleaseCount) {
        // This process gave up the core it was supposed to
        LOG(NOTICE, "Core retrieval timer went off for process %d, but process "
            "already released the core it was supposed to.\n", process->id);
        return;
    }

    LOG(NOTICE, "Core retrieval timer went off for process %d. Moving one of "
                "its threads to the unmanaged core.\n", process->id);

    // Remove one of this process's threads from its exclusive core
    auto& exclusiveThreadSet = process->threadStateToSet[RUNNING_EXCLUSIVE];
    if (exclusiveThreadSet.empty()) {
        LOG(WARNING, "Unable to preempt from process %d because it has no "
                     "exclusive threads.\n", process->id);
        return;
    }

    struct ThreadInfo* thread = *(exclusiveThreadSet.begin());
    removeThreadFromExclusiveCore(thread);
    changeThreadState(thread, RUNNING_PREEMPTED);
    *(process->threadPreempted) = true;

    distributeCores();
}

void
CoreArbiterServer::cleanupConnection(int socket)
{
    sys->close(socket);
    ThreadInfo* thread = threadSocketToInfo[socket];
    ProcessInfo* process = thread->process;
    process->threadStateToSet[thread->state].erase(thread);

    // Remove thread from map of threads
    threadSocketToInfo.erase(thread->socket);

    if (thread->state == RUNNING_EXCLUSIVE) {
        exclusiveThreads.erase(thread);
        thread->core->exclusiveThread = NULL;
    }

    bool noRemainingThreads = true;
    for (auto& kv : process->threadStateToSet) {
        if (!kv.second.empty()) {
            noRemainingThreads = false;
            break;
        }
    }
    if (noRemainingThreads) {
        LOG(NOTICE, "All of process %d's threads have exited. Removing all "
            "process records\n", process->id);
        sys->close(process->sharedMemFd);
        processIdToInfo.erase(process->id);

        // Remove this process from the core priority queue
        for (size_t i = 0; i < NUM_PRIORITIES; i++) {
            std::deque<struct ProcessInfo*>& queue = corePriorityQueues[i];
            for (auto processIter = queue.begin(); processIter != queue.end();
                 processIter++) {
                if (*processIter == process) {
                    queue.erase(processIter);
                    break;
                }
            }
        }

        delete process;
    }

    delete thread;
}

void
CoreArbiterServer::distributeCores()
{
    if (testingSkipCoreDistribution) {
        LOG(DEBUG, "Skipping core distribution\n");
        return;
    }

    LOG(NOTICE, "Distributing cores among threads...\n");

    // First, find the threads that should receive cores.
    // This is a queue (front has higher priority) of threads not currently
    // exclusive that should be placed on cores
    std::deque<struct ThreadInfo*> threadsToReceiveCores;

    // Keep track of the threads that are already exclusive and should remain so
    std::unordered_set<struct ThreadInfo*> threadsAlreadyExclusive;

    // Iterate from highest to lowest priority
    bool coresFilled = false;
    for (size_t priority = 0;
         priority < corePriorityQueues.size() && !coresFilled; priority++) {

        auto& processes = corePriorityQueues[priority];
        bool threadAdded = true;

        // A running count of how many cores we have assigned to a process at
        // this priority. This makes it easy to ensure that we don't assign
        // more cores to a process than it has requested.
        std::unordered_map<struct ProcessInfo*, core_t> processToCoreCount;

        // Any threads that are already exclusive should remain so at this
        // priority.
        for (struct ThreadInfo* thread : exclusiveThreads) {
            if (threadsAlreadyExclusive.find(thread) !=
                    threadsAlreadyExclusive.end()) {
                continue;
            }

            struct ProcessInfo* process = thread->process;
            if (processToCoreCount[process] <
                    process->desiredCorePriorities[priority]) {
                // We want to keep this thread on its core
                threadsAlreadyExclusive.insert(thread);
                processToCoreCount[process]++;

                if (threadsToReceiveCores.size() +
                      threadsAlreadyExclusive.size() == exclusiveCores.size()) {
                    coresFilled = true;
                    break;
                }
            }
        }

        // Add as many blocked threads at this priority level as we can
        while (threadAdded && !coresFilled) {
            threadAdded = false;

            // Iterate over every process at this priority level
            for (size_t i = 0; i < processes.size(); i++) {
                // Pop off the first processes and put it at the back of the
                // deque (so that we share cores evenly accross threads at this
                // priority level)
                struct ProcessInfo* process = processes.front();
                processes.pop_front();
                processes.push_back(process);

                if (processToCoreCount[process] ==
                        process->desiredCorePriorities[priority]) {
                    continue;
                }

                // Prefer moving preempted threads back to their cores over
                // blocked threads.
                auto& threadSet = process->threadStateToSet[RUNNING_PREEMPTED];
                if (threadSet.empty()) {
                    threadSet = process->threadStateToSet[BLOCKED];
                }
                if (!threadSet.empty()) {
                    // Choose some blocked thread to put on a core
                    struct ThreadInfo* thread = *(threadSet.begin());
                    threadsToReceiveCores.push_back(thread);
                    processToCoreCount[process]++;
                    threadAdded = true;

                    // Temporarily remove the thread from the process's set of
                    // threads so that we don't double count it
                    threadSet.erase(thread);

                    if (threadsToReceiveCores.size() +
                            threadsAlreadyExclusive.size() ==
                                exclusiveCores.size()) {
                        coresFilled = true;
                        break;
                    }
                }
            }
        }
    }

    // Add threads back to the correct sets in their process
    for (struct ThreadInfo* thread : threadsToReceiveCores) {
        thread->process->threadStateToSet[thread->state].insert(thread);
    }

    if (threadsToReceiveCores.empty()) {
        return;
    }

    // Assign cores to threads
    for (size_t i = 0; i < exclusiveCores.size() &&
         !threadsToReceiveCores.empty(); i++) {
        struct CoreInfo* core = &exclusiveCores[i];

        if (!core->exclusiveThread) {
            // This core is available. Give it to a thread not already on
            // a core.
            struct ThreadInfo* thread = threadsToReceiveCores.front();
            threadsToReceiveCores.pop_front();
            
            LOG(NOTICE, "Granting core %lu to thread %d from process %d\n",
                   core->id, thread->id, thread->process->id);
            moveThreadToExclusiveCore(thread, core);

            if (!testingSkipCpusetAllocation) {
                // Wake up the thread
                if (!sendData(thread->socket, &core->id, sizeof(core_t),
                              "Error sending core ID to thread " +
                                    std::to_string(thread->id))) {
                    return;
                }
            }
        } else if (threadsAlreadyExclusive.find(core->exclusiveThread) !=
                   threadsAlreadyExclusive.end()) {
            // This thread is supposed to have a core, so do nothing.
            LOG(NOTICE, "Keeping thread %d on core %lu\n",
                   core->exclusiveThread->id, core->id);
        } else {
            // The thread on this core needs to be preempted. It will be
            // assigned to a new thread (one of the ones at the end of
            // threadsToReceiveCores) when the currently running thread blocks
            // or is demoted in timeoutThreadPreemption
            requestCoreRelease(core);
        }
    }
}

void
CoreArbiterServer::requestCoreRelease(struct CoreInfo* core)
{
    if (!core->exclusiveThread) {
        LOG(WARNING, "There is no thread on core %lu to preempt\n", core->id);
        return;
    }

    struct ProcessInfo* process = core->exclusiveThread->process;
    LOG(NOTICE, "Starting preemption of thread belonging to process %d "
        "on core %lu\n", process->id, core->id);

    // Tell the process that it needs to release a core
    *(process->coreReleaseRequestCount) += 1;

    int timerFd = sys->timerfd_create(CLOCK_MONOTONIC, 0);
    if (timerFd < 0) {
        LOG(ERROR, "Error on timerfd_create: %s\n", strerror(errno));
        return;
    }

    // Set timer to enforce preemption
    struct itimerspec timerSpec;
    timerSpec.it_interval.tv_sec = 0;
    timerSpec.it_interval.tv_nsec = 0;
    timerSpec.it_value.tv_sec = preemptionTimeout / 1000;
    timerSpec.it_value.tv_nsec = (preemptionTimeout % 1000) * 1000000;

    if (sys->timerfd_settime(timerFd, 0, &timerSpec, NULL) < 0) {
        LOG(ERROR, "Error on timerFd_settime: %s\n", strerror(errno));
        return;
    }

    struct epoll_event timerEvent;
    timerEvent.events = EPOLLIN | EPOLLRDHUP;
    timerEvent.data.fd = timerFd;
    if (sys->epoll_ctl(epollFd, EPOLL_CTL_ADD, timerFd, &timerEvent)
            < 0) {
        LOG(ERROR, "Error adding timerFd to epoll: %s\n",
            strerror(errno));
        return;
    }

    timerFdToProcess[timerFd] = process;
}

void
CoreArbiterServer::totalAvailableCores(int socket)
{
    size_t availableCoreCount = 0;
    for (struct CoreInfo& core : exclusiveCores) {
        if (!core.exclusiveThread) {
            availableCoreCount++;
        }
    }
    LOG(NOTICE, "There are %lu available cores\n", availableCoreCount);
    sendData(socket, &availableCoreCount, sizeof(size_t),
             "Error sending available core count\n");
}

bool
CoreArbiterServer::readData(int socket, void* buf, size_t numBytes,
                            std::string err)
{
    ssize_t readBytes = sys->recv(socket, buf, numBytes, 0);
    if (readBytes < 0) {
        LOG(ERROR, "%s: %s\n", err.c_str(), strerror(errno));
        return false;
    } else if ((size_t)readBytes < numBytes) {
        LOG(WARNING, "%s: expected %lu bytes but received %ld\n",
            err.c_str(), numBytes, readBytes);
        return false;
    }

    return true;
}

bool
CoreArbiterServer::sendData(int socket, void* buf, size_t numBytes,
                            std::string err)
{
    if (sys->send(socket, buf, numBytes, 0) < 0) {
        LOG(ERROR, "%s: %s\n", err.c_str(), strerror(errno));
        return false;
    }
    return true;
}

void CoreArbiterServer::createCpuset(std::string dirName, std::string cores,
                                     std::string mems)
{
    if (sys->mkdir(dirName.c_str(), 
                  S_IRUSR | S_IWUSR | S_IXUSR |
                  S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
        LOG(ERROR, "Error creating cpuset directory at %s: %s\n",
            dirName.c_str(), strerror(errno));
        exit(-1);
    }

    std::string memsPath = dirName + "/cpuset.mems";
    std::ofstream memsFile(memsPath);
    if (!memsFile.is_open()) {
        LOG(ERROR, "Unable to open %s\n", memsPath.c_str());
        exit(-1);
    }
    memsFile << mems;
    memsFile.close();

    std::string cpusPath = dirName + "/cpuset.cpus";
    std::ofstream cpusFile(cpusPath);
    if (!cpusFile.is_open()) {
        LOG(ERROR, "Unable to open %s\n", cpusPath.c_str());
        exit(-1);
    }
    cpusFile << cores;
    cpusFile.close();
}

void CoreArbiterServer::moveProcsToCpuset(std::string fromPath,
                                          std::string toPath)
{
    LOG(DEBUG, "Moving procs in %s to %s\n", fromPath.c_str(), toPath.c_str());
    std::ifstream fromFile(fromPath);
    if (!fromFile.is_open()) {
        LOG(ERROR, "Unable to open %s\n", fromPath.c_str());
        exit(-1);
    }

    std::ofstream toFile(toPath);
    if (!toFile.is_open()) {
        LOG(ERROR, "Unable to open %s\n", toPath.c_str());
        exit(-1);
    }

    pid_t processId;
    while (fromFile >> processId) {
        toFile << processId;
        toFile << std::endl;
        if (toFile.bad()) {
            // The ofstream errors out if we try to move a kernel process. This
            // is normal behavior, but it means we need to reopen the file.
            toFile.close();
            toFile.open(toPath, std::fstream::app);
            if (!toFile.is_open()) {
                LOG(ERROR, "Unable top open %s\n", toPath.c_str());
                exit(-1);
            }
        }
    }

    fromFile.close();
    toFile.close();
}

void
CoreArbiterServer::removeOldCpusets(std::string arbiterCpusetPath)
{
    std::string procsDestFilename = cpusetPath + "/cgroup.procs";
    DIR* dir = sys->opendir(arbiterCpusetPath.c_str());
    if (!dir) {
        // This is likely just because we don't have old cpusets to remove
        LOG(ERROR, "Error on opendir %s: %s\n",
            arbiterCpusetPath.c_str(), strerror(errno));
        return;
    }

    // Iterate over all directories in the given path
    for (struct dirent* entry = sys->readdir(dir); entry != NULL;
         entry = sys->readdir(dir)) {
        
        if (entry->d_type == DT_DIR && entry->d_name[0] != '.') {
            std::string dirName = arbiterCpusetPath + "/" +
                                  std::string(entry->d_name);
            std::string procsFilename = dirName + "/cgroup.procs";

            // Remove all processes from this cpuset so we can delete it
            moveProcsToCpuset(procsFilename, procsDestFilename);
            if (sys->rmdir(dirName.c_str()) < 0) {
                LOG(ERROR, "Eror on rmdir %s: %s\n",
                    dirName.c_str(), strerror(errno));
                exit(-1);
            }
        }
    }

    // Remove the whole CoreArbiter cpuset directory
    if (sys->rmdir(arbiterCpusetPath.c_str()) < 0) {
        LOG(ERROR, "Error on rmdir %s: %s\n",
            arbiterCpusetPath.c_str(), strerror(errno));
        exit(-1);
    }

    if (sys->closedir(dir) < 0) {
        LOG(ERROR, "Error on closedir %s: %s\n",
            arbiterCpusetPath.c_str(), strerror(errno));
        exit(-1);
    }
}

void
CoreArbiterServer::moveThreadToExclusiveCore(struct ThreadInfo* thread,
                                             struct CoreInfo* core)
{
    if (!testingSkipCpusetAllocation) {
        core->cpusetFile.seekp(0);
        core->cpusetFile << thread->id;
        core->cpusetFile.flush();
        if (core->cpusetFile.bad()) {
            // TODO: handle this elegantly. It shouldn't happen, so I'm killing
            // the server for now.
            LOG(ERROR, "Unable to write %d to cpuset file for core %lu",
                thread->id, core->id);
            exit(-1);
        }
    }

    changeThreadState(thread, RUNNING_EXCLUSIVE);
    thread->process->totalCoresOwned++;
    thread->core = core;
    core->exclusiveThread = thread;

    exclusiveThreads.insert(thread);
}

void
CoreArbiterServer::removeThreadFromExclusiveCore(struct ThreadInfo* thread)
{
    if (!thread->core) {
        LOG(WARNING, "Thread %d was already on unmanaged core\n",
            thread->id);
    }

    if (!testingSkipCpusetAllocation) {
        // Writing a thread to a new cpuset automatically removes it from the
        // one it belonged to before
        unmanagedCore.cpusetFile << thread->id;
        unmanagedCore.cpusetFile.flush();
        if (unmanagedCore.cpusetFile.bad()) {
            // TODO: handle this elegantly. It shouldn't happen, so I'm killing
            // the server for now.
            LOG(ERROR, "Unable to write %d to cpuset file for core %lu",
                thread->id, unmanagedCore.id);
            exit(-1);
        }
    }

    thread->process->totalCoresOwned--;
    thread->core->exclusiveThread = NULL;
    thread->core = NULL;
    exclusiveThreads.erase(thread);
}

void
CoreArbiterServer::changeThreadState(struct ThreadInfo* thread,
                                     ThreadState state)
{
    ThreadState prevState = thread->state;
    thread->state = state;
    thread->process->threadStateToSet[prevState].erase(thread);
    thread->process->threadStateToSet[state].insert(thread);
}

}


