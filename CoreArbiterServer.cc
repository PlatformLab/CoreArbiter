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

#include <iostream>
#include <fstream>
#include <sys/un.h>
#include <thread>

#include "CoreArbiterServer.h"

namespace CoreArbiter {

std::string CoreArbiterServer::cpusetPath = "/sys/fs/cgroup/cpuset";

static Syscall defaultSyscall;
Syscall* CoreArbiterServer::sys = &defaultSyscall;

CoreArbiterServer::CoreArbiterServer(std::string socketPath,
                                     std::string sharedMemPathPrefix,
                                     std::vector<uint32_t> exclusiveCores)
    : sharedMemPathPrefix(sharedMemPathPrefix)
    , epollFd(-1)
    , listenFd(-1)
{
    if (sys->geteuid()) {
        fprintf(stderr, "The core arbiter server must be run as root\n");
        exit(-1);
    }

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
    for (uint32_t core : exclusiveCores) {
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
                sys->close(connectingFd);
                // TODO: cleanup state
                
            } else if (connectingFd == listenFd) {
                acceptConnection(listenFd);
            } else {
                if (!(events[i].events & EPOLLIN)) {
                    printf("Expecting a message type.\n");
                    continue;
                }

                uint8_t msgType;
                ssize_t bytesRead =
                    sys->recv(connectingFd, &msgType, sizeof(uint8_t), 0);
                if (bytesRead < 0) {
                    fprintf(stderr, "Error reading message type: %s\n",
                            strerror(errno));
                    continue;
                } else if (bytesRead < 1) {
                    fprintf(stderr, "Expecing message type, but got empty "
                                    "message\n");
                    continue;
                }

                switch(msgType) {
                    case PROCESS_CONN:
                        registerProcessInfo(connectingFd);
                        break;
                    case THREAD_CONN:
                        registerThreadInfo(connectingFd);
                        break;
                    case THREAD_BLOCK:
                        threadBlocking(connectingFd);
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

    unregisteredConnections.insert(remoteFd);

    printf("Accepted new connection on socket %d\n", remoteFd);
}

void
CoreArbiterServer::registerProcessInfo(int connectingFd)
{
    if (unregisteredConnections.find(connectingFd) ==
            unregisteredConnections.end()) {
        fprintf(stderr, "Fd %d has already registered as a process\n",
                connectingFd);
        return;
    }

    // Read connecting process ID from socket. If a thread is connecting, its
    // corresponding process ID should come first.
    pid_t processId;
    if (sys->recv(connectingFd, &processId, sizeof(size_t), 0) < 0) {
        fprintf(stderr, "Error receiving process ID: %s\n", strerror(errno));
        return;
    }

    // Construct shared memory page
    std::string socketPath = sharedMemPathPrefix + std::to_string(processId);
    int sharedMemFd = sys->open(socketPath.c_str(),
                               O_CREAT | O_RDWR | O_TRUNC, S_IRWXU);
    if (sharedMemFd < 0) {
        fprintf(stderr, "Error opening shared memory page: %s\n",
                strerror(errno));
        return;
    }

    // Our clients are not necessarily root
    sys->chmod(socketPath.c_str(), 0777);

    sys->ftruncate(sharedMemFd, sizeof(core_count_t));
    core_count_t* coreReleaseRequestCount =
        (core_count_t *)sys->mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
                             MAP_SHARED, sharedMemFd, 0);
    if (coreReleaseRequestCount == MAP_FAILED) {
        fprintf(stderr, "Error on mmap: %s\n", strerror(errno));
        // TODO: send error to client
        return;
    }
    *coreReleaseRequestCount = 0;

    // Send location of shared memory to the application.
    // First in the packet is the size of the path, followed by the path itself.
    // The path is null termianted, and the size includes the \0.
    size_t pathLen = socketPath.size() + 1;
    char pathPacket[sizeof(size_t) + pathLen];
    memcpy(pathPacket, &pathLen, sizeof(size_t));
    memcpy(pathPacket + sizeof(size_t), socketPath.c_str(), pathLen);
    if (sys->send(connectingFd, pathPacket, sizeof(pathPacket), 0) < 0) {
        fprintf(stderr, "Send failed: %s\n", strerror(errno));
        return;
    }

    // Update process information since everything succeeded
    processIdToInfo[processId] = ProcessInfo(
        processId, connectingFd, sharedMemFd, coreReleaseRequestCount);

    printf("Registered process with id %d on socket %d\n",
           processId, connectingFd);

    unregisteredConnections.erase(connectingFd);
}

void
CoreArbiterServer::registerThreadInfo(int connectingFd)
{
    // Read connecting process ID from socket. If a thread is connecting, its
    // corresponding process ID should come first.
    pid_t processId;
    ssize_t read = sys->recv(connectingFd, &processId, sizeof(pid_t), 0);
    if (read < 0) {
        fprintf(stderr, "Error receiving process ID: %s\n", strerror(errno));
        return;
    }
    printf("read %ld bytes of process id: %d\n", read, processId);

    if (processIdToInfo.find(processId) == processIdToInfo.end()) {
        fprintf(stderr, "Received request for thread whose process has "
                "not registered.\n");
        return;
    }

    pid_t threadId;
    read = sys->recv(connectingFd, &threadId, sizeof(pid_t), 0);
    if (read < 0) {
        fprintf(stderr, "Error receiving thread ID: %s\n", strerror(errno));
        return;
    }
    printf("read %ld bytes of thread id: %d\n", read, threadId);

    threadFdToInfo[connectingFd] =
        ThreadInfo(threadId, processId, connectingFd);
    processIdToInfo[processId].activeThreadIds.insert(threadId);

    printf("Registered thread with id %d on process %d\n",
           threadId, processId);
    
    // This connection may have been registered already, in the case where
    // the fd is used to register a process and then a thread. If it's a new
    // thread, then it was unregistered.
    unregisteredConnections.erase(connectingFd);
}

void
CoreArbiterServer::threadBlocking(int threadFd)
{
    struct ThreadInfo* threadInfo = &threadFdToInfo[threadFd];
    pid_t processId = threadInfo->processId;
    pid_t threadId = threadInfo->threadId;
    struct ProcessInfo* processInfo = &processIdToInfo[processId];
    if (processInfo->activeThreadIds.find(threadId) !=
        processInfo->activeThreadIds.end()) {
        
        processInfo->activeThreadIds.erase(threadId);
        processInfo->blockedThreadIds.insert(threadId);
        printf("Added thread %d as blocked\n", threadId);

    } else {
        printf("Thread %d was already blocked\n", threadId);
    }

    // TODO: change this to actual arbitration code
    printf("sleeping...\n");
    sleep(3);
    uint8_t wakeup;
    if (sys->send(threadFd, &wakeup, sizeof(uint8_t), 0) < 0) {
        fprintf(stderr, "Send failed: %s\n", strerror(errno));
        return;
    }
    printf("Woke up thread\n");
}

void
CoreArbiterServer::coresRequested()
{

}

void
CoreArbiterServer::timeoutCoreRetrieval()
{

}

void CoreArbiterServer::createCpuset(std::string dirName, std::string cores,
                                     std::string mems) {
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
                                          std::string toPath) {
    printf("Moving procs in %s to %s\n", fromPath.c_str(), toPath.c_str());
    std::ifstream fromFile(fromPath);
    if (!fromFile.is_open()) {
        fprintf(stderr, "Unable to open %s\n", fromPath.c_str());
        exit(-1);
    }

    std::ofstream toFile(toPath);
    if (!toFile.is_open()) {
        fprintf(stderr, "Unable top open %s\n", toPath.c_str());
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

void CoreArbiterServer::removeOldCpusets(std::string arbiterCpusetPath) {
    std::string procsDestFilename = cpusetPath + "/cgroup.procs";
    DIR* dir = sys->opendir(arbiterCpusetPath.c_str());
    if (!dir) {
        fprintf(stderr, "Error on opendir %s: %s\n",
                arbiterCpusetPath.c_str(), strerror(errno));
        exit(-1);
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

}
