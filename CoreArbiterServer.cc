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

namespace CoreArbiter {

std::string CoreArbiterServer::cpusetPath = "/sys/fs/cgroup/cpuset";

static Syscall defaultSyscall;
Syscall* CoreArbiterServer::sys = &defaultSyscall;
bool CoreArbiterServer::testingSkipCpusetAllocation = false;

CoreArbiterServer::CoreArbiterServer(std::string socketPath,
                                     std::string sharedMemPathPrefix,
                                     std::vector<core_t> exclusiveCoreIds)
    : sharedMemPathPrefix(sharedMemPathPrefix)
    , epollFd(-1)
    , listenFd(-1)
    , exclusiveCores(exclusiveCoreIds.size())
    , corePriorityQueues(NUM_PRIORITIES)
{
    if (sys->geteuid()) {
        fprintf(stderr, "The core arbiter server must be run as root\n");
        exit(-1);
    }

    if (!testingSkipCpusetAllocation) {
        // Remove any old cpusets from a previous server
        std::string arbiterCpusetPath = cpusetPath + "/CoreArbiter";
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
        // shared.
        std::string sharedCpusetPath = arbiterCpusetPath + "/Shared";
        createCpuset(sharedCpusetPath, "0", "0");

        // Move all of the currently running processes to the shared cpuset
        std::string allProcsPath = cpusetPath + "/cgroup.procs";
        std::string sharedProcsPath = sharedCpusetPath + "/cgroup.procs";
        moveProcsToCpuset(allProcsPath, sharedProcsPath);

        // Cpusets should be set up properly now, so we'll save the files needed
        // for moving processes between cpusets
        std::string sharedTasksPath = sharedCpusetPath + "/tasks";
        sharedCore.coreId = 0;
        sharedCore.cpusetFile.open(sharedTasksPath);
        if (!sharedCore.cpusetFile.is_open()) {
            fprintf(stderr, "Unable to open %s\n", sharedTasksPath.c_str());
            exit(-1);
        }

        for (size_t i = 0; i < exclusiveCoreIds.size(); i++) {
            core_t coreId = exclusiveCoreIds[i];
            std::string exclusiveTasksPath = arbiterCpusetPath + "/Exclusive" +
                                             std::to_string(coreId) + "/tasks";

            struct CoreInfo* coreInfo = &exclusiveCores[i];
            coreInfo->coreId = coreId;
            coreInfo->cpusetFile.open(exclusiveTasksPath);
            if (!coreInfo->cpusetFile.is_open()) {
                fprintf(stderr, "Unable to open %s\n",
                        exclusiveTasksPath.c_str());
                exit(-1);
            }
        }
    }

    ensureParents(socketPath.c_str(), 0777);
    ensureParents(sharedMemPathPrefix.c_str(), 0777);

    // Set up unix domain socket
    listenFd = sys->socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenFd < 0) {
        fprintf(stderr, "Error creating listen socket: %s\n", strerror(errno));
        exit(-1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

    // This will fail if the socket doesn't already exist. Ignore the error.
    sys->unlink(addr.sun_path);

    if (sys->bind(listenFd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listenFd);
        fprintf(stderr, "Error binding listen socket: %s\n", strerror(errno));
        exit(-1);
    }

    if (sys->listen(listenFd, 10) < 0) { // TODO: backlog size?
        close(listenFd);
        fprintf(stderr, "Error listening: %s\n", strerror(errno));
        exit(-1);
    }

    // Our clients are not necessarily root
    if (sys->chmod(addr.sun_path, 0777) < 0) {
        close(listenFd);
        fprintf(stderr, "Error on chmod for %s: %s\n",
                addr.sun_path, strerror(errno));
        exit(-1);
    }

    // Set up epoll
    epollFd = sys->epoll_create(MAX_EPOLL_EVENTS);
    if (epollFd < 0) {
        close(listenFd);
        fprintf(stderr, "Error on epoll_create: %s\n", strerror(errno));
        exit(-1);
    }

    struct epoll_event listenEvent;
    listenEvent.events = EPOLLIN | EPOLLRDHUP;
    listenEvent.data.fd = listenFd;
    if (sys->epoll_ctl(epollFd, EPOLL_CTL_ADD, listenFd, &listenEvent) < 0) {
        sys->close(listenFd);
        fprintf(stderr, "Error adding listenFd %d to epoll: %s\n",
                listenFd, strerror(errno));
        exit(-1);
    }
}

CoreArbiterServer::~CoreArbiterServer()
{

}

void
CoreArbiterServer::startArbitration()
{
    struct epoll_event events[MAX_EPOLL_EVENTS];

    while (true) {
        int numFds = sys->epoll_wait(epollFd, events, MAX_EPOLL_EVENTS, -1);
        if (numFds < 0) {
            fprintf(stderr, "Error on epoll_wait: %s\n", strerror(errno));
            continue;
        }

        for (int i = 0; i < numFds; i++) {
            int connectingFd = events[i].data.fd;

            if (events[i].events & EPOLLRDHUP) {
                // A thread exited or otherwise closed its connection
                printf("detected closed connection for fd %d\n", connectingFd);
                sys->epoll_ctl(epollFd, EPOLL_CTL_DEL,
                               connectingFd, &events[i]);
                cleanupConnection(connectingFd);
            } else if (connectingFd == listenFd) {
                // A new thread is connecting
                acceptConnection(listenFd);
            } else if (timerFdToProcess.find(connectingFd)
                        != timerFdToProcess.end()) {
                // Core retrieval timer timeout
                timeoutCoreRetrieval(connectingFd);
                sys->epoll_ctl(epollFd, EPOLL_CTL_DEL,
                               connectingFd, &events[i]);
            } else {
                // Thread is making some sort of request
                if (!(events[i].events & EPOLLIN)) {
                    printf("Expecting a message type.\n");
                    continue;
                }

                uint8_t msgType;
                if (!readData(connectingFd, &msgType, sizeof(uint8_t),
                             "Error reading message type")) {
                    continue;
                }

                switch(msgType) {
                    case THREAD_BLOCK:
                        threadBlocking(connectingFd);
                        break;
                    case CORE_REQUEST:
                        coresRequested(connectingFd);
                        break;
                    default:
                        fprintf(stderr, "Unknown message type: %u\n", msgType);
                        break;
                }
            }
        }
        printf("\n");
    }
}

void
CoreArbiterServer::acceptConnection(int listenFd)
{
    struct sockaddr_un remoteAddr;
    socklen_t len = sizeof(struct sockaddr_un);
    int remoteFd =
        sys->accept(listenFd, (struct sockaddr *)&remoteAddr, &len);
    if (remoteFd < 0) {
        fprintf(stderr, "Error accepting connection on listenFd: %s\n",
                strerror(errno));
        return;
    }

    // Add new connection to epoll events list
    struct epoll_event processEvent;
    processEvent.events = EPOLLIN | EPOLLRDHUP;
    processEvent.data.fd = remoteFd;
    if (sys->epoll_ctl(epollFd, EPOLL_CTL_ADD, remoteFd, &processEvent) < 0) {
        fprintf(stderr, "Error adding remoteFd to epoll: %s\n",
                strerror(errno));
        return;
    }

    // Read connecting process ID from socket.
    pid_t processId;
    if (!readData(remoteFd, &processId, sizeof(pid_t),
                   "Error receiving process ID")) {
        return;
    }

    pid_t threadId;
    if (!readData(remoteFd, &threadId, sizeof(pid_t),
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
            fprintf(stderr, "Error opening shared memory page: %s\n",
                    strerror(errno));
            return;
        }

        // Our clients are not necessarily root
        sys->chmod(sharedMemPath.c_str(), 0777);

        sys->ftruncate(sharedMemFd, sizeof(core_t));
        core_t* coreReleaseRequestCount =
            (core_t *)sys->mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
                                 MAP_SHARED, sharedMemFd, 0);
        if (coreReleaseRequestCount == MAP_FAILED) {
            fprintf(stderr, "Error on mmap: %s\n", strerror(errno));
            // TODO: send error to client
            return;
        }
        *coreReleaseRequestCount = 0;

        // Send location of shared memory to the application.
        // First in the packet is the size of the path, followed by the path
        // itself. The path is null termianted, and the size includes the \0.
        size_t pathLen = sharedMemPath.size() + 1;
        char pathPacket[sizeof(size_t) + pathLen];
        memcpy(pathPacket, &pathLen, sizeof(size_t));
        memcpy(pathPacket + sizeof(size_t), sharedMemPath.c_str(), pathLen);
        if (sys->send(remoteFd, pathPacket, sizeof(pathPacket), 0) < 0) {
            fprintf(stderr, "Send failed: %s\n", strerror(errno));
            return;
        }

        // Update process information since everything succeeded
        processIdToInfo[processId] = new ProcessInfo(
            processId, sharedMemFd, coreReleaseRequestCount);

        printf("Registered process with id %d on socket %d\n",
               processId, remoteFd);
    }

    struct ThreadInfo* thread = new ThreadInfo(threadId,
                                               processIdToInfo[processId],
                                               remoteFd);
    threadFdToInfo[remoteFd] = thread;
    processIdToInfo[processId]->threadStateToSet[RUNNING_SHARED].insert(thread);

    printf("Registered thread with id %d on process %d\n",
           threadId, processId);
}


void
CoreArbiterServer::threadBlocking(int threadFd)
{
    if (threadFdToInfo.find(threadFd) == threadFdToInfo.end()) {
        fprintf(stderr, "Unknown thread is blocking\n");
        return;
    }

    struct ThreadInfo* thread = threadFdToInfo[threadFd];
    printf("Thread %d is blocking\n", thread->threadId);

    if (thread->state == BLOCKED) {
        fprintf(stderr, "Thread %d was already blocked\n",
                thread->threadId);
        return;
    }

    struct ProcessInfo* process = thread->process;
    if (thread->state == RUNNING_EXCLUSIVE) {
        if (*(process->coreReleaseRequestCount) ==
            process->coreReleaseCount) {
            // Cores should be given up voluntarily by calling setNumCores with
            // a number of cores smaller than the process owns. Blocking the
            // thread when not asked to causes races.
            fprintf(stderr, "Thread %d should not be blocking\n",
                    thread->threadId);
            return;
        }

        printf("Removing thread %d from core %lu\n",
               thread->threadId, thread->core->coreId);
        process->coreReleaseCount++;
        process->totalCoresOwned--;
        removeThreadFromExclusiveCore(thread);
    }

    changeThreadState(thread, BLOCKED);
    distributeCores();
}

void
CoreArbiterServer::coresRequested(int connectingFd)
{
    core_t numCoresArr[NUM_PRIORITIES];
    if (!readData(connectingFd, &numCoresArr, sizeof(core_t) * NUM_PRIORITIES,
                 "Error receiving number of cores requested")) {
        return;
    }

    struct ThreadInfo* thread = threadFdToInfo[connectingFd];
    struct ProcessInfo* process = thread->process;

    printf("Received core request from process %d:", process->id);
    for (size_t i = 0; i < NUM_PRIORITIES; i++) {
        printf(" %lu", numCoresArr[i]);
    }
    printf("\n");

    bool desiredCoresChanged = false;
    process->totalCoresDesired = 0;
    core_t remainingCoresOwned = process->totalCoresOwned;

    for (size_t priority = 0; priority < NUM_PRIORITIES; priority++) {
        // Update information for a single priority
        core_t prevNumCoresDesired = process->desiredCorePriorities[priority];
        core_t numCoresDesired = numCoresArr[priority];
        core_t numCoresOwned = std::min(remainingCoresOwned, numCoresDesired);
        remainingCoresOwned -= numCoresOwned;

        process->desiredCorePriorities[priority] = numCoresDesired;
        process->totalCoresDesired += numCoresDesired;

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
CoreArbiterServer::timeoutCoreRetrieval(int timerFd)
{
    uint64_t time;
    read(timerFd, &time, sizeof(uint64_t));


    struct ProcessInfo* process = timerFdToProcess[timerFd];

    if (*(process->coreReleaseRequestCount) == process->coreReleaseCount) {
        // This process gave up the core it was supposed to
        printf("Core retrieval timer went off for process %d, but process "
               "already released the core it was supposed to.\n", process->id);
        return;
    }

    printf("Core retrieval timer went off for process %d. Moving one of its "
           "threads to the shared core.\n", process->id);

    // Remove one of this process's threads from its exclusive core
    struct ThreadInfo* thread =
        *(process->threadStateToSet[RUNNING_EXCLUSIVE].begin());
    removeThreadFromExclusiveCore(thread);

    distributeCores();
}

void
CoreArbiterServer::cleanupConnection(int connectingFd)
{
    sys->close(connectingFd);
    ThreadInfo* thread = threadFdToInfo[connectingFd];
    ProcessInfo* process = thread->process;
    process->threadStateToSet[thread->state].erase(thread);

    // Remove thread from map of threads
    threadFdToInfo.erase(thread->socket);

    if (thread->state == RUNNING_EXCLUSIVE) {
        exclusiveThreads.erase(thread);
        thread->core->exclusiveThread = NULL;
    }

    if (process->threadStateToSet.empty()) {
        printf("All of process %d's threads have exited. Removing all "
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
    printf("Distributing cores among threads...\n");

    // First, build the set of threads that should receive cores
    std::deque<struct ThreadInfo*> threadsToReceiveCores;

    // Iterate from highest to lowest priority
    for (std::deque<struct ProcessInfo*>& processes : corePriorityQueues) {
        bool threadAdded = true;

        // Continue at this priority level as long as we are still able to add
        // threads
        while (threadAdded &&
               threadsToReceiveCores.size() < exclusiveCores.size()) {
            threadAdded = false;

            // Iterate over every process at this priority level
            for (size_t i = 0; i < processes.size() &&
                 threadsToReceiveCores.size() < exclusiveCores.size();
                 i++) {
                // Pop off the first processes and put it at the back of the
                // deque (so that we share cores accross threads at this
                // priority level)
                struct ProcessInfo* process = processes.front();
                processes.pop_front();
                processes.push_back(process);

                // Favor keeping existing exclusive threads on the core
                std::unordered_set<struct ThreadInfo*>* threadSet =
                    &process->threadStateToSet[RUNNING_EXCLUSIVE];
                if (threadSet->empty()) {
                    threadSet = &process->threadStateToSet[BLOCKED];
                }

                // If this process has blocked threads, add one to the set
                if (!threadSet->empty()) {
                    struct ThreadInfo* thread = *(threadSet->begin());
                    threadsToReceiveCores.push_back(thread);
                    threadAdded = true;

                    // Temporarily remove the thread from the process's set
                    // of threads so that we don't double count it
                    threadSet->erase(thread);
                }
            }
        }
    }

    // Add threads back to the correct sets in their process
    for (struct ThreadInfo* thread : threadsToReceiveCores) {
        thread->process->threadStateToSet[thread->state].insert(thread);
    }

    if (threadsToReceiveCores.empty()) {
        printf("There are no threads available to move to a core\n");
        return;
    }

    // Find the intersection of threads that should receive cores and threads
    // that are already exclusive
    std::unordered_set<struct ThreadInfo*> threadsAlreadyExclusive;
    for (struct ThreadInfo* thread : exclusiveThreads) {
        auto threadIter = std::find(threadsToReceiveCores.begin(),
                                    threadsToReceiveCores.end(), thread);
        if (threadIter != threadsToReceiveCores.end()) {
            threadsToReceiveCores.erase(threadIter);
            threadsAlreadyExclusive.insert(*threadIter);
        }
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
            
            printf("Granting core %lu to thread %d\n",
                   core->coreId, thread->threadId);
            moveThreadToExclusiveCore(thread, core);

            // Wake up the thread
            if (sys->send(thread->socket, &core->coreId,
                          sizeof(core_t), 0) < 0) {
                fprintf(stderr, "Error sending core ID to thread %d\n",
                        thread->threadId);
                continue;
            }
        } else if (threadsAlreadyExclusive.find(core->exclusiveThread) !=
                   threadsAlreadyExclusive.end()) {
            // This thread is supposed to have a core, so do nothing.
            printf("Keeping thread %d on core %lu\n",
                   core->exclusiveThread->threadId, core->coreId);
        } else {
            // The thread on this core needs to be preempted. It will be
            // assigned to a new thread (one of the ones at the end of
            // threadsToReceiveCores) when the currently running thread blocks
            // or is demoted in timeoutCoreRetrieval
            struct ProcessInfo* process = core->exclusiveThread->process;
            printf("Starting preemption of thread belonging to process %d on "
                   "core %lu\n", process->id, core->coreId);
            
            // Tell the process that it needs to release a core
            *(process->coreReleaseRequestCount) += 1;

            int timerFd = sys->timerfd_create(CLOCK_MONOTONIC, 0);
            if (timerFd < 0) {
                fprintf(stderr, "Error on timerfd_create: %s\n",
                        strerror(errno));
                continue;
            }

            // Set timer to enforce preemption
            struct itimerspec timerSpec;
            timerSpec.it_value.tv_sec = RELEASE_TIMEOUT_MS / 1000;
            timerSpec.it_value.tv_nsec = (RELEASE_TIMEOUT_MS % 1000) * 1000000;

            if (sys->timerfd_settime(timerFd, 0, &timerSpec, NULL) < 0) {
                fprintf(stderr, "Error on timerFd_settime: %s\n",
                        strerror(errno));
                continue;
            }

            struct epoll_event timerEvent;
            timerEvent.events = EPOLLIN | EPOLLRDHUP;
            timerEvent.data.fd = timerFd;
            if (sys->epoll_ctl(epollFd, EPOLL_CTL_ADD, timerFd, &timerEvent)
                    < 0) {
                fprintf(stderr, "Error adding timerFd to epoll: %s\n",
                        strerror(errno));
                return;
            }

            timerFdToProcess[timerFd] = process;
        }
    }
}

bool
CoreArbiterServer::readData(int fd, void* buf, size_t numBytes,
                                        std::string err)
{
    ssize_t readBytes = sys->recv(fd, buf, numBytes, 0);
    if (readBytes < 0) {
        fprintf(stderr, "%s: %s\n", err.c_str(), strerror(errno));
        return false;
    } else if ((size_t)readBytes < numBytes) {
        fprintf(stderr, "%s: expected %lu bytes but received %ld\n",
                err.c_str(), numBytes, readBytes);
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
        fprintf(stderr, "Error creating cpuset directory at %s: %s\n",
                dirName.c_str(), strerror(errno));
        exit(-1);
    }

    std::string memsPath = dirName + "/cpuset.mems";
    std::cout << memsPath << std::endl;
    std::ofstream memsFile(memsPath);
    if (!memsFile.is_open()) {
        fprintf(stderr, "Unable to open %s\n", memsPath.c_str());
        exit(-1);
    }
    memsFile << mems;
    memsFile.close();

    std::string cpusPath = dirName + "/cpuset.cpus";
    std::ofstream cpusFile(cpusPath);
    if (!cpusFile.is_open()) {
        fprintf(stderr, "Unable to open %s\n", cpusPath.c_str());
        exit(-1);
    }
    cpusFile << cores;
    cpusFile.close();
}

void CoreArbiterServer::moveProcsToCpuset(std::string fromPath,
                                          std::string toPath)
{
    printf("Moving procs in %s to %s\n", fromPath.c_str(), toPath.c_str());
    std::ifstream fromFile(fromPath);
    if (!fromFile.is_open()) {
        fprintf(stderr, "Unable to open %s\n", fromPath.c_str());
        exit(-1);
    }

    std::ofstream toFile(toPath);
    if (!toFile.is_open()) {
        fprintf(stderr, "Unable to open %s\n", toPath.c_str());
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
                fprintf(stderr, "Unable top open %s\n", toPath.c_str());
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
        fprintf(stderr, "Error on opendir %s: %s\n",
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
                fprintf(stderr, "Eror on rmdir %s: %s\n",
                        dirName.c_str(), strerror(errno));
                exit(-1);
            }
        }
    }

    // Remove the whole CoreArbiter cpuset directory
    if (sys->rmdir(arbiterCpusetPath.c_str()) < 0) {
        fprintf(stderr, "Error on rmdir %s: %s\n",
                arbiterCpusetPath.c_str(), strerror(errno));
        exit(-1);
    }

    if (sys->closedir(dir) < 0) {
        fprintf(stderr, "Error on closedir %s: %s\n",
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
        core->cpusetFile << thread->threadId;
        core->cpusetFile.flush();
        if (core->cpusetFile.bad()) {
            // TODO: handle this elegantly. It shouldn't happen, so I'm killing
            // the server for now.
            fprintf(stderr, "Unable to write %d to cpuset file for core %lu",
                    thread->threadId, core->coreId);
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
        fprintf(stderr, "Thread %d was already on shared core\n",
                thread->threadId);
    }

    if (!testingSkipCpusetAllocation) {
        // Writing a thread to a new cpuset automatically removes it from the
        // one it belonged to before
        sharedCore.cpusetFile << thread->threadId;
        sharedCore.cpusetFile.flush();
        if (sharedCore.cpusetFile.bad()) {
            // TODO: handle this elegantly. It shouldn't happen, so I'm killing
            // the server for now.
            fprintf(stderr, "Unable to write %d to cpuset file for core %lu",
                    thread->threadId, sharedCore.coreId);
            exit(-1);
        }
    }

    thread->core->exclusiveThread = NULL;
    thread->core = NULL;
    changeThreadState(thread, RUNNING_SHARED);
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


