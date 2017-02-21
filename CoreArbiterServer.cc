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
{
    if (sys->geteuid()) {
        fprintf(stderr, "The core arbiter server must be run as root\n");
        exit(-1);
    }

    if (!testingSkipCpusetAllocation) {
        // Remove any old cpusets from a previous server
        std::string arbiterCpusetPath = cpusetPath + "/CoreArbiter";
        removeOldCpusets(arbiterCpusetPath);

        // Create a new cpuset directory for core arbitration. Since this is going
        // to be a parent of all the arbiter's individual core cpusets, it needs to
        // include every core.
        unsigned numCores = std::thread::hardware_concurrency();
        std::string allCores = "0-" + std::to_string(numCores - 1);
        createCpuset(arbiterCpusetPath, allCores, "0");
        // Set up exclusive cores
        for (core_t core : exclusiveCoreIds) {
            std::string exclusiveCpusetPath =
                arbiterCpusetPath + "/Exclusive" + std::to_string(core);
            createCpuset(exclusiveCpusetPath, std::to_string(core), "0");
        }

        // Set up cpuset for all other processes. For now, core 0 is always shared.
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
                fprintf(stderr, "Unable to open %s\n", exclusiveTasksPath.c_str());
                exit(-1);
            }
        }
    }

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
                printf("detected closed connection for fd %d\n", connectingFd);
                sys->epoll_ctl(epollFd, EPOLL_CTL_DEL,
                               connectingFd, &events[i]);
                cleanupConnection(connectingFd);
            } else if (connectingFd == listenFd) {
                acceptConnection(listenFd);
            } else {
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
        std::string socketPath = sharedMemPathPrefix +
                                 std::to_string(processId);
        int sharedMemFd = sys->open(socketPath.c_str(),
                                   O_CREAT | O_RDWR | O_TRUNC, S_IRWXU);
        if (sharedMemFd < 0) {
            fprintf(stderr, "Error opening shared memory page: %s\n",
                    strerror(errno));
            return;
        }

        // Our clients are not necessarily root
        sys->chmod(socketPath.c_str(), 0777);

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
        size_t pathLen = socketPath.size() + 1;
        char pathPacket[sizeof(size_t) + pathLen];
        memcpy(pathPacket, &pathLen, sizeof(size_t));
        memcpy(pathPacket + sizeof(size_t), socketPath.c_str(), pathLen);
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

    struct ThreadInfo* threadInfo = new ThreadInfo(threadId, processId,
                                                   remoteFd);
    threadFdToInfo[remoteFd] = threadInfo;
    processIdToInfo[processId]->threads.push_back(threadInfo);

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

    struct ThreadInfo* threadInfo = threadFdToInfo[threadFd];
    printf("Thread %d is blocking\n", threadInfo->threadId);

    if (threadInfo->state == BLOCKED) {
        fprintf(stderr, "Thread %d was already blocked\n",
                threadInfo->threadId);
        return;
    }

    struct ProcessInfo* processInfo = processIdToInfo[threadInfo->processId];

    if (threadInfo->state == RUNNING_EXCLUSIVE) {
        if (*(processInfo->coreReleaseRequestCount) ==
            processInfo->coreReleaseCount) {
            // Cores should be given up voluntarily by calling setNumCores with
            // a number of cores smaller than the process owns. Blocking the
            // thread when not asked to causes races.
            fprintf(stderr, "Thread %d should not be blocking\n",
                    threadInfo->threadId);
            return;
        }

        processInfo->coreReleaseCount++;
        removeThreadFromCore(threadInfo);
    }

    threadInfo->state = BLOCKED;

    if (processInfo->numCoresDesired > processInfo->numCoresOwned) {
        grantCores();
    }
}

void
CoreArbiterServer::coresRequested(int connectingFd)
{
    core_t numCores;
    if (!readData(connectingFd, &numCores, sizeof(core_t),
                 "Error receiving number of cores requested")) {
        return;
    }

    printf("%ld cores requested\n", numCores);
    struct ThreadInfo* threadInfo = threadFdToInfo[connectingFd];
    struct ProcessInfo* processInfo = processIdToInfo[threadInfo->processId];
    core_t prevNumCoresDesired = processInfo->numCoresDesired;
    processInfo->numCoresDesired = numCores;

    if (processInfo->numCoresDesired > processInfo->numCoresOwned) {
        if (prevNumCoresDesired <= processInfo->numCoresOwned) {
            processesOwedCores.push_back(processInfo);
        }
        grantCores();
    } else if (processInfo->numCoresDesired < processInfo->numCoresOwned) {
        // The application is voluntarily giving up cores, so we need to give
        // them permission to block threads.
        *(processInfo->coreReleaseRequestCount) +=
            processInfo->numCoresOwned - processInfo->numCoresDesired;

        for (auto processIter = processesOwedCores.begin();
             processIter != processesOwedCores.end(); processIter++) {
            if (*processIter == processInfo) {
                processesOwedCores.erase(processIter);
                break;
            }
        }
    }
}

void
CoreArbiterServer::timeoutCoreRetrieval()
{

}

void
CoreArbiterServer::cleanupConnection(int connectingFd)
{
    sys->close(connectingFd);
    ThreadInfo* thread = threadFdToInfo[connectingFd];
    ProcessInfo* process = processIdToInfo[thread->processId];

    // Remove this thread from the process's list of threads
    for (auto threadIter = process->threads.begin();
         threadIter != process->threads.end(); threadIter++) {
        if (*threadIter == thread) {
            process->threads.erase(threadIter);
            break;
        }
    }

    // Remove thread from map of threads
    threadFdToInfo.erase(thread->threadId);

    if (process->threads.empty()) {
        // All of this process's threads have exited, so remove it
        sys->close(process->sharedMemFd);
        delete processIdToInfo[thread->processId];
        processIdToInfo.erase(thread->processId);
    }

    delete thread;
}

void
CoreArbiterServer::grantCores()
{
    if (processesOwedCores.empty()) {
        printf("There are no processes in need of cores\n");
        return;
    }

    for (size_t i = 0; i < exclusiveCores.size() && !processesOwedCores.empty();
         i++) {
        struct CoreInfo* core = &exclusiveCores[i];
        if (core->exclusiveThreadId < 0) {
            // This core is available
            struct ProcessInfo* process = processesOwedCores.front();
            assert(process->numCoresOwned < process->numCoresDesired);

            for (struct ThreadInfo* thread : process->threads) {
                if (thread->state == BLOCKED) {
                    // This thread is blocked and belongs to a process who wants
                    // more cores than it has
                    printf("Granting core %lu to thread %d\n",
                           core->coreId, thread->threadId);

                    moveThreadToCore(thread, core);
                    
                    // Wake up the thread
                    if (sys->send(thread->socket, &core->coreId,
                                  sizeof(core_t), 0) < 0) {
                        fprintf(stderr, "Error sending core ID to thread %d\n",
                                thread->threadId);
                        continue;
                    }

                    core->exclusiveThreadId = thread->threadId;
                    thread->state = RUNNING_EXCLUSIVE;
                    process->numCoresOwned++;
                    if (process->numCoresOwned == process->numCoresDesired) {
                        processesOwedCores.pop_front();
                    }

                    break;
                }
            }
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
CoreArbiterServer::moveThreadToCore(struct ThreadInfo* thread,
                                    struct CoreInfo* core)
{
    if (testingSkipCpusetAllocation) {
        return;
    }

    core->cpusetFile.seekp(0);
    core->cpusetFile << thread->threadId;
    core->cpusetFile.flush();
    if (core->cpusetFile.bad()) {
        // TODO: handle this elegantly. It shouldn't happen, so I'm killing the
        // server for now.
        fprintf(stderr, "Unable to write %d to cpuset file for core %lu",
                thread->threadId, core->coreId);
        exit(-1);
    }
}

void
CoreArbiterServer::removeThreadFromCore(struct ThreadInfo* thread)
{
    if (testingSkipCpusetAllocation) {
        return;
    }

    sharedCore.cpusetFile << thread->threadId;
    sharedCore.cpusetFile.flush();
    if (sharedCore.cpusetFile.bad()) {
        // TODO: handle this elegantly. It shouldn't happen, so I'm killing the
        // server for now.
        fprintf(stderr, "Unable to write %d to cpuset file for core %lu",
                thread->threadId, sharedCore.coreId);
        exit(-1);
    }
}

}


