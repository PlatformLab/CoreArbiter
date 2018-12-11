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
#include <sched.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/un.h>

#include <algorithm>
#include <iostream>
#include <thread>

#include "CoreArbiterServer.h"
#include "PerfUtils/TimeTrace.h"
#include "PerfUtils/Util.h"

using PerfUtils::TimeTrace;

// Uncomment the following line to enable time traces.
// #define TIME_TRACE 1

namespace CoreArbiter {

std::string CoreArbiterServer::cpusetPath = "/sys/fs/cgroup/cpuset";

static Syscall defaultSyscall;
Syscall* CoreArbiterServer::sys = &defaultSyscall;
CoreArbiterServer* volatile CoreArbiterServer::mostRecentInstance = NULL;
bool CoreArbiterServer::testingSkipCpusetAllocation = false;
bool CoreArbiterServer::testingSkipCoreDistribution = false;
bool CoreArbiterServer::testingSkipSocketCommunication = false;
bool CoreArbiterServer::testingSkipMemoryDeallocation = false;
bool CoreArbiterServer::testingDoNotChangeManagedCores = false;

// Provides a cleaner way of invoking TimeTrace::record, with the code
// conditionally compiled in or out by the TIME_TRACE #ifdef. Arguments
// are made uint64_t (as opposed to uin32_t) so the caller doesn't have to
// frequently cast their 64-bit arguments into uint32_t explicitly: we will
// help perform the casting internally.
static inline void
timeTrace(const char* format, uint64_t arg0 = 0, uint64_t arg1 = 0,
          uint64_t arg2 = 0, uint64_t arg3 = 0) {
#if TIME_TRACE
    TimeTrace::record(format, uint32_t(arg0), uint32_t(arg1), uint32_t(arg2),
                      uint32_t(arg3));
#endif
}

/**
 * Constructs a CoreArbiterServer object and sets up all necessary state for
 * server operation. This includes creating a socket to listen for new
 * connections on the socket path and creating subdirectories in the
 * /sys/fs/cgroup/cpuset directory for each managed core ID given. Creating
 * a new server will delete all cpuset state left over from a previous server.
 * The server must be run as root; this constraint is enforced before any
 * state in the filesystem is established.
 *
 * If the optional arbitrateImmediately flag is set, this constructor will not
 * return. Instead, the server will immediately start listening for client
 * connections and arbitrating between them.
 *
 * \param socketPath
 *     The path at which to create a socket that will listen for client
 *     connections
 * \param sharedMemPathPrefix
 *     The filename prefix (can be a directory) to use for creating shared
 *     memory files. There is a separate shared memory file for each process
 *     connected to the server.
 * \param managedCoreIds
 *     A vector of core IDs that the server will arbitrate between. If this
 *     parameter is not provided, or if an empty vector is provided, the server
 *     will automatically allocate all cores except core 0 as cores available to
 *     be managed. We assume that all cores on a system are sequentially
 *     numbered starting at 0. Currently, core 0 is always left as an unmanaged
 *     core. It should never be passed as an element of managedCoreIds.
 * \param arbitrateImmediately
 *     If true, the server will begin arbitrating after a successful
 *     construction
 */
CoreArbiterServer::CoreArbiterServer(std::string socketPath,
                                     std::string sharedMemPathPrefix,
                                     std::vector<int> managedCoreIds,
                                     bool arbitrateImmediately)
    : socketPath(socketPath),
      listenSocket(-1),
      sharedMemPathPrefix(sharedMemPathPrefix),
      globalSharedMemPath(sharedMemPathPrefix + "Global"),
      globalSharedMemFd(-1),
      advisoryLockPath("/tmp/coreArbiterAdvisoryLock"),
      advisoryLockFd(-1),
      epollFd(-1),
      preemptionTimeout(RELEASE_TIMEOUT_MS),
      alwaysUnmanagedString(""),
      cpusetUpdateTimeout(CPUSET_UPDATE_TIMEOUT_MS),
      corePriorityQueues(NUM_PRIORITIES),
      terminationFd(eventfd(0, 0)) {
    if (sys->geteuid()) {
        LOG(ERROR, "The core arbiter server must be run as root");
        exit(-1);
    }

    // Try to acquire the advisory lock.
    // If another CoreArbiter server is running, then exit.
    advisoryLockFd = sys->open(advisoryLockPath.c_str(),
                               O_CREAT | O_RDWR | O_TRUNC, S_IRWXU);
    if (advisoryLockFd < 0) {
        LOG(ERROR, "Error opening advisory lock file: %s", strerror(errno));
        exit(-1);
    }

    if (sys->flock(advisoryLockFd, LOCK_EX | LOCK_NB) == -1) {
        LOG(ERROR,
            "Error acquiring advisory lock: %s "
            "(Another CoreAriber server running?)",
            strerror(errno));
        exit(-1);
    }

    // If managedCoreIds is empty, populate it with everything except
    // core 0
    unsigned int numCores = std::thread::hardware_concurrency();
    if (!testingDoNotChangeManagedCores) {
        if (managedCoreIds.empty() || managedCoreIds.size() == numCores) {
            // If no managed cores are specified or if every core is given,
            // make every core available to be managed except for CPU 0. We
            // need to ensure that at least one core remains unmanaged so that
            // the arbiter has something to run on.
            managedCoreIds.clear();
            for (int id = 1; id < static_cast<int>(numCores); id++) {
                managedCoreIds.push_back(id);
            }
            alwaysUnmanagedString = "0,";
        } else {
            alwaysUnmanagedString = "";
            std::sort(managedCoreIds.begin(), managedCoreIds.end());
            size_t idx = 0;
            for (int i = 0; i < static_cast<int>(numCores); i++) {
                if (idx < managedCoreIds.size() && managedCoreIds[idx] == i) {
                    idx++;
                } else {
                    alwaysUnmanagedString += std::to_string(i) + ",";
                }
            }
        }
    }

    std::string arbiterCpusetPath = cpusetPath + "/CoreArbiter";
    if (!testingSkipCpusetAllocation) {
        // Remove any old cpusets from a previous server
        removeOldCpusets(arbiterCpusetPath);

        // Create a new cpuset directory for core arbitration. Since this is
        // going to be a parent of all the arbiter's individual core cpusets, it
        // needs to include every core.
        std::string allCores = "0-" + std::to_string(numCores - 1);
        createCpuset(arbiterCpusetPath, allCores, "0");

        // Set up managed cores
        for (int core : managedCoreIds) {
            std::string managedCpusetPath =
                arbiterCpusetPath + "/Managed" + std::to_string(core);
            createCpuset(managedCpusetPath, std::to_string(core), "0");
        }

        // Set up the unmanaged cpuset. This starts with all cores and is
        // scaled down as processes ask for managed cores.
        std::string unmanagedCpusetPath = arbiterCpusetPath + "/Unmanaged";
        createCpuset(unmanagedCpusetPath, allCores, "0");

        // Move all of the currently running processes to the unmanaged cpuset
        std::string allProcsPath = cpusetPath + "/cgroup.procs";
        std::string unmanagedProcsPath = unmanagedCpusetPath + "/cgroup.procs";
        moveProcsToCpuset(allProcsPath, unmanagedProcsPath);

        // Set up the file we will use to control how many cores are in the
        // unmanaged cpuset.
        std::string unmanagedCpusPath = unmanagedCpusetPath + "/cpuset.cpus";
        unmanagedCpusetCpus.open(unmanagedCpusPath);
        if (!unmanagedCpusetCpus.is_open()) {
            LOG(ERROR, "Unable to open %s", unmanagedCpusPath.c_str());
            exit(-1);
        }

        // Set up the file we will use to control which threads are in the
        // unmanaged cpuset.
        std::string unmanagedTasksPath = unmanagedCpusetPath + "/tasks";
        unmanagedCpusetTasks.open(unmanagedTasksPath);
        if (!unmanagedCpusetTasks.is_open()) {
            LOG(ERROR, "Unable to open %s", unmanagedTasksPath.c_str());
            exit(-1);
        }
    }

    for (int coreId : managedCoreIds) {
        std::string managedTasksPath =
            arbiterCpusetPath + "/Managed" + std::to_string(coreId) + "/tasks";
        struct CoreInfo* core = new CoreInfo(coreId, managedTasksPath);
        unmanagedCores.push_back(core);
    }

    ensureParents(socketPath.c_str(), 0777);
    ensureParents(sharedMemPathPrefix.c_str(), 0777);

    // Set up global shared memory
    globalSharedMemFd = sys->open(globalSharedMemPath.c_str(),
                                  O_CREAT | O_RDWR | O_TRUNC, S_IRWXU);
    if (globalSharedMemFd < 0) {
        LOG(ERROR, "Error opening shared memory page: %s", strerror(errno));
        return;
    }

    // Our clients are not necessarily root
    sys->chmod(globalSharedMemPath.c_str(), 0777);

    size_t globalSharedMemSize = sizeof(struct GlobalStats);
    sys->ftruncate(globalSharedMemFd, globalSharedMemSize);
    stats = (struct GlobalStats*)sys->mmap(NULL, getpagesize(),
                                           PROT_READ | PROT_WRITE, MAP_SHARED,
                                           globalSharedMemFd, 0);
    if (stats == MAP_FAILED) {
        LOG(ERROR, "Error on global stats mmap: %s", strerror(errno));
        exit(-1);
    }
    stats->numUnoccupiedCores = (uint32_t)unmanagedCores.size();

    // Set up unix domain socket
    listenSocket = sys->socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenSocket < 0) {
        LOG(ERROR, "Error creating listen socket: %s", strerror(errno));
        exit(-1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

    // This will fail if the socket doesn't already exist. Ignore the error.
    sys->unlink(addr.sun_path);

    if (sys->bind(listenSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG(ERROR, "Error binding listen socket %s: %s", addr.sun_path,
            strerror(errno));
        sys->close(listenSocket);
        if (remove(socketPath.c_str()) != 0) {
            LOG(ERROR, "Error deleting socket file %s: %s", socketPath.c_str(),
                strerror(errno));
        }
        exit(-1);
    }

    if (sys->listen(listenSocket, 100) < 0) {  // TODO(jspeiser): backlog size?
        LOG(ERROR, "Error listening: %s", strerror(errno));
        sys->close(listenSocket);
        if (remove(socketPath.c_str()) != 0) {
            LOG(ERROR, "Error deleting socket file: %s", strerror(errno));
        }
        exit(-1);
    }

    // Our clients are not necessarily root
    if (sys->chmod(addr.sun_path, 0777) < 0) {
        LOG(ERROR, "Error on chmod for %s: %s", addr.sun_path, strerror(errno));
        sys->close(listenSocket);
        if (remove(socketPath.c_str()) != 0) {
            LOG(ERROR, "Error deleting socket file: %s", strerror(errno));
        }
        exit(-1);
    }

    // Set up epoll
    epollFd = sys->epoll_create(MAX_EPOLL_EVENTS);
    if (epollFd < 0) {
        LOG(ERROR, "Error on epoll_create: %s", strerror(errno));
        sys->close(listenSocket);
        if (remove(socketPath.c_str()) != 0) {
            LOG(ERROR, "Error deleting socket file: %s", strerror(errno));
        }
        exit(-1);
    }

    struct epoll_event listenEvent;
    listenEvent.events = EPOLLIN | EPOLLRDHUP;
    listenEvent.data.fd = listenSocket;
    if (sys->epoll_ctl(epollFd, EPOLL_CTL_ADD, listenSocket, &listenEvent) <
        0) {
        LOG(ERROR, "Error adding listenSocket %d to epoll: %s", listenSocket,
            strerror(errno));
        sys->close(listenSocket);
        if (remove(socketPath.c_str()) != 0) {
            LOG(ERROR, "Error deleting socket file: %s", strerror(errno));
        }
        exit(-1);
    }

    // Add the termination fd to allow us to return from epoll_wait.
    struct epoll_event terminationEvent;
    terminationEvent.events = EPOLLIN;
    terminationEvent.data.fd = terminationFd;
    if (sys->epoll_ctl(epollFd, EPOLL_CTL_ADD, terminationFd,
                       &terminationEvent) < 0) {
        LOG(ERROR, "Error adding terminationFd %d to epoll: %s", terminationFd,
            strerror(errno));
        sys->close(terminationFd);
        if (remove(socketPath.c_str()) != 0) {
            LOG(ERROR, "Error deleting socket file: %s", strerror(errno));
        }
        exit(-1);
    }

    mostRecentInstance = this;
    installSignalHandler();
    if (arbitrateImmediately) {
        startArbitration();
    }
}

/**
 * In addition to cleaning up memory and closing file descriptors, when
 * deconstructed the CoreArbiterServer removes the socket file that it was
 * listening for connections on and removes all cpusets it established.
 */
CoreArbiterServer::~CoreArbiterServer() {
#if TIME_TRACE
    TimeTrace::setOutputFileName("CoreArbiterServer.log");
    TimeTrace::print();
#endif

    if (!testingSkipMemoryDeallocation) {
        for (struct CoreInfo* core : managedCores) {
            core->cpusetFile.close();
            delete core;
        }

        for (auto& proccessIdAndInfo : processIdToInfo) {
            struct ProcessInfo* process = proccessIdAndInfo.second;
            for (auto& threadStateAndSet : process->threadStateToSet) {
                auto& threadSet = threadStateAndSet.second;
                for (struct ThreadInfo* thread : threadSet) {
                    delete thread;
                }
            }
            delete process;
        }
    }

    if (sys->close(listenSocket) < 0) {
        LOG(ERROR, "Error closing listenSocket: %s", strerror(errno));
    }
    if (sys->close(epollFd) < 0) {
        LOG(ERROR, "Error closing epollFd: %s", strerror(errno));
    }
    if (sys->close(terminationFd) < 0) {
        LOG(ERROR, "Error closing terminationFd: %s", strerror(errno));
    }
    if (remove(socketPath.c_str()) != 0) {
        LOG(ERROR, "Error deleting socket file: %s", strerror(errno));
    }

    removeOldCpusets(cpusetPath + "/CoreArbiter");

    if (mostRecentInstance == this)
        mostRecentInstance = NULL;

    if (sys->flock(advisoryLockFd, LOCK_UN | LOCK_NB) == -1) {
        LOG(ERROR, "Error releasing advisory lock: %s ", strerror(errno));
        exit(-1);
    }
}

/**
 * A wrapper around handleEvents() which does the meat of request
 * handling. It's useful to separate out the loop for testing.
 */
void
CoreArbiterServer::startArbitration() {
    while (handleEvents()) {
    }
}

/**
 * Writes to a special socket connection that tells the server to exit its
 * arbitration loop.
 */
void
CoreArbiterServer::endArbitration() {
    uint64_t terminate = 0xdeadbeef;
    ssize_t ret = sys->write(terminationFd, &terminate, 8);
    if (ret < 0) {
        LOG(ERROR, "Error writing to terminationFd: %s", strerror(errno));
    }
}

/**
 * This is the top-level event handling method for the Core Arbiter Server.
 * It returns true to indicate that event handling should continue and false
 * to indicate that event handling should cease.
 */
bool
CoreArbiterServer::handleEvents() {
    struct epoll_event events[MAX_EPOLL_EVENTS];
    uint64_t msSinceLastCpusetUpdate =
        Cycles::toMilliseconds(Cycles::rdtsc() - unmanagedCpusetLastUpdate);
    uint64_t nextCpusetUpdate =
        msSinceLastCpusetUpdate >= cpusetUpdateTimeout
            ? 0
            : cpusetUpdateTimeout - msSinceLastCpusetUpdate;
    int numFds = sys->epoll_wait(epollFd, events, MAX_EPOLL_EVENTS,
                                 static_cast<int>(nextCpusetUpdate));
    LOG(DEBUG, "SERVER: epoll_wait returned with %d file descriptors.", numFds);
    if (numFds < 0) {
        // Interrupted system calls are normal, so there is no need to log them
        // as errors.
        if (errno != EINTR)
            LOG(ERROR, "Error on epoll_wait: %s", strerror(errno));
        return true;
    }

#if TIME_TRACE
    PerfUtils::Util::serialize();
    if (numFds != 0) {
        TimeTrace::record("SERVER: After epoll_wait");
    }
#endif

    for (int i = 0; i < numFds; i++) {
        int socket = events[i].data.fd;
        if (events[i].events & EPOLLRDHUP) {
            // A thread exited or otherwise closed its connection
            LOG(NOTICE, "Detected closed connection for fd %d", socket);
            sys->epoll_ctl(epollFd, EPOLL_CTL_DEL, socket, &events[i]);
            cleanupConnection(socket);
        } else if (socket == listenSocket) {
            // A new thread is connecting
            acceptConnection(listenSocket);
        } else if (timerFdToInfo.find(socket) != timerFdToInfo.end()) {
            // Core retrieval timer timeout
            LOG(WARNING, "Timer fire closing socket %d", socket);
            timeoutThreadPreemption(socket);
            if (sys->epoll_ctl(epollFd, EPOLL_CTL_DEL, socket, &events[i]) <
                0) {
                LOG(ERROR, "Error removing timer from epoll: %s",
                    strerror(errno));
            }
            if (sys->close(socket) < 0) {
                LOG(ERROR, "Error closing socket: %s", strerror(errno));
            }
            timerFdToInfo.erase(socket);
        } else if (socket == terminationFd) {
            return false;
        } else {
            // Thread is making some sort of request
            if (!(events[i].events & EPOLLIN)) {
                LOG(WARNING, "Did not receive a message type.");
                continue;
            }

            uint8_t msgType;
            if (!readData(socket, &msgType, sizeof(uint8_t),
                          "Error reading message type")) {
                continue;
            }

            switch (msgType) {
                case THREAD_BLOCK:
                    threadBlocking(socket);
                    break;
                case CORE_REQUEST:
                    coresRequested(socket);
                    break;
                default:
                    LOG(ERROR, "Unknown message type: %u", msgType);
                    break;
            }
        }
    }

    // Update the unmanaged cpuset if we haven't in a while
    msSinceLastCpusetUpdate =
        Cycles::toMilliseconds(Cycles::rdtsc() - unmanagedCpusetLastUpdate);
    if (msSinceLastCpusetUpdate >= cpusetUpdateTimeout) {
        bool cpusetChanged = false;
        uint64_t now = Cycles::rdtsc();

        for (auto coreIter = managedCores.begin();
             coreIter != managedCores.end();) {
            struct CoreInfo* core = *coreIter;
            // Remove unrelated threads that may have arisen if some core did a
            // std::thread creation.
            if (core->managedThread) {
                removeUnmanagedThreadsFromCore(core);
            }
            if (!core->managedThread &&
                Cycles::toMilliseconds(now - core->threadRemovalTime) >=
                    cpusetUpdateTimeout) {
                // This core hasn't been used as an managed core in a while,
                // so we'll move it to the unmanaged cpuset
                LOG(NOTICE, "Moving core %d to the unmanaged cpuset", core->id);
                managedCores.erase(coreIter);
                unmanagedCores.push_back(core);
                cpusetChanged = true;
            } else {
                coreIter++;
            }
        }
        unmanagedCpusetLastUpdate = now;

        if (cpusetChanged) {
            updateUnmanagedCpuset();
        }
    }

    return true;
}

/**
 * Accepts a connection from a new thread and sets up all associated state. Also
 * establishes state for a process if this is the first thread in its process
 * that has established a connection. New threads are all assumed to be running
 * in the unmanaged cpuset. This method should only be called when it is known
 * that the listening socket has a new connection waiting.
 *
 * \param listenSocket
 *     The socket to accept a new connection from.
 */
void
CoreArbiterServer::acceptConnection(int listenSocket) {
    timeTrace("SERVER: Starting acceptConnection");

    struct sockaddr_un remoteAddr;
    socklen_t len = sizeof(struct sockaddr_un);
    int socket = sys->accept(listenSocket, (struct sockaddr*)&remoteAddr, &len);
    if (socket < 0) {
        LOG(ERROR, "Error accepting connection on listenSocket: %s",
            strerror(errno));
        return;
    }

    // Add new connection to epoll events list
    struct epoll_event processEvent;
    processEvent.events = EPOLLIN | EPOLLRDHUP;
    processEvent.data.fd = socket;
    if (sys->epoll_ctl(epollFd, EPOLL_CTL_ADD, socket, &processEvent) < 0) {
        LOG(ERROR, "Error adding socket to epoll: %s", strerror(errno));
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
        std::string processSharedMemPath =
            sharedMemPathPrefix + std::to_string(processId);
        int processSharedMemFd = sys->open(processSharedMemPath.c_str(),
                                           O_CREAT | O_RDWR | O_TRUNC, S_IRWXU);
        if (processSharedMemFd < 0) {
            LOG(ERROR, "Error opening shared memory page: %s", strerror(errno));
            return;
        }

        // Our clients are not necessarily root
        sys->chmod(processSharedMemPath.c_str(), 0777);

        size_t processSharedMemSize = sizeof(struct ProcessStats);
        sys->ftruncate(processSharedMemFd, processSharedMemSize);
        struct ProcessStats* processStats = (struct ProcessStats*)sys->mmap(
            NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED,
            processSharedMemFd, 0);
        if (processStats == MAP_FAILED) {
            LOG(ERROR, "Error on mmap: %s", strerror(errno));
            // TODO(jspeiser): send error to client
            return;
        }

        // Send location of global shared memory to the application.
        // First in the packet is the size of the path, followed by the path
        // itself. The path is null termianted, and the size includes the \0.
        size_t pathLen = globalSharedMemPath.size() + 1;
        char globalPathPacket[sizeof(size_t) + pathLen];
        memcpy(globalPathPacket, &pathLen, sizeof(size_t));
        memcpy(globalPathPacket + sizeof(size_t), globalSharedMemPath.c_str(),
               pathLen);
        if (!sendData(socket, globalPathPacket, sizeof(globalPathPacket),
                      "Sending global shared memory path failed")) {
            return;
        }

        // Send the size of the process shared memory path to the process,
        // followed by the path itself. The path is null terminated, and the
        // size includes the \0.
        pathLen = processSharedMemPath.size() + 1;
        char processPathPacket[sizeof(size_t) + pathLen];
        memcpy(processPathPacket, &pathLen, sizeof(size_t));
        memcpy(processPathPacket + sizeof(size_t), processSharedMemPath.c_str(),
               pathLen);
        if (!sendData(socket, processPathPacket, sizeof(processPathPacket),
                      "Sending process shared memory path failed")) {
            return;
        }

        // Update process information since everything succeeded
        processIdToInfo[processId] =
            new ProcessInfo(processId, processSharedMemFd, processStats);

        stats->numProcesses++;

        LOG(NOTICE, "Registered process with id %d on socket %d", processId,
            socket);
    }

    struct ThreadInfo* thread =
        new ThreadInfo(threadId, processIdToInfo[processId], socket);
    threadSocketToInfo[socket] = thread;
    processIdToInfo[processId]->threadStateToSet[RUNNING_UNMANAGED].insert(
        thread);

    LOG(NOTICE, "Registered thread with id %d on process %d on socket %d",
        threadId, processId, socket);

    timeTrace("SERVER: Finished acceptConnection");
}

/**
 * Registers a thread as blocked so that it can be assigned to a managed core.
 * If appropriate, this method also reassigns cores. Note that this method can
 * cause inconsistent state between the server and client if the client does not
 * call recv() after it sends its blocking message to the server.
 *
 * \param socket
 *     The socket whose associated thread is blocking.
 */
void
CoreArbiterServer::threadBlocking(int socket) {
    timeTrace("SERVER: Start handling thread blocking request");

    if (threadSocketToInfo.find(socket) == threadSocketToInfo.end()) {
        LOG(WARNING, "Unknown thread is blocking");
        return;
    }

    struct ThreadInfo* thread = threadSocketToInfo[socket];
    LOG(DEBUG, "Thread %d is blocking", thread->id);

    struct ProcessInfo* process = thread->process;
    bool shouldDistributeCores = true;

    if (thread->state == BLOCKED) {
        LOG(WARNING, "Thread %d was already blocked", thread->id);
        return;
    } else if (thread->state == RUNNING_UNMANAGED) {
        // No need to do anything; later code will handle this case
    } else if (thread->state == RUNNING_MANAGED) {
        int coreId =
            thread->core ? thread->core->id : thread->corePreemptedFrom->id;
        bool coreReleaseRequested =
            process->stats->threadCommunicationBlocks[coreId]
                .coreReleaseRequested;
        if (coreReleaseRequested) {
            LOG(NOTICE, "Removing thread %d from core %d", thread->id, coreId);
            removeThreadFromManagedCore(thread, false);
            process->stats->threadCommunicationBlocks[coreId]
                .coreReleaseRequested = false;
        } else {
            // This thread has not been asked to release its core, so don't
            // allow it to block.
            LOG(WARNING, "Thread %d should not be blocking", thread->id);
            wakeupThread(thread, thread->core);
            return;
        }
    } else if (thread->state == RUNNING_PREEMPTED) {
        int coreId =
            thread->core ? thread->core->id : thread->corePreemptedFrom->id;
        bool coreReleaseRequested =
            process->stats->threadCommunicationBlocks[coreId]
                .coreReleaseRequested;
        if (!coreReleaseRequested) {
            // If we did not ask for the core back, there should be no reason
            // for the thread to be in a preempted state.
            LOG(ERROR,
                "Thread %d should not be unmanaged, since no core preemption "
                "was requested!",
                thread->id);
            abort();
        }
        LOG(DEBUG, "Preempted thread %d is blocking", thread->id);
        process->stats->unpreemptedCount++;
        process->stats->threadCommunicationBlocks[coreId].coreReleaseRequested =
            false;
        assert(process->coresPreemptedFrom.find(thread->corePreemptedFrom) !=
               process->coresPreemptedFrom.end());
        process->coresPreemptedFrom.erase(thread->corePreemptedFrom);
        thread->corePreemptedFrom = NULL;
        shouldDistributeCores = false;
    }

    changeThreadState(thread, BLOCKED);
    process->stats->numBlockedThreads++;

    LOG(DEBUG, "Process %d now has %u blocked threads", process->id,
        process->stats->numBlockedThreads.load());
    if (shouldDistributeCores) {
        distributeCores();
    }

    timeTrace("SERVER: Finished thread blocking request");
}

/**
 * Handles a new core request from a client. The request comes from a thread's
 * socket, but is applied to the entire process. Managed cores are reassigned if
 * necessary. This method should only be called once it is known that the given
 * socket has pending data to be read.
 *
 * \param socket
 *     The socket to read the core request from
 */
void
CoreArbiterServer::coresRequested(int socket) {
    timeTrace("SERVER: Starting to serve core request");

    // TODO(jspeiser): maybe combine this and the original read into one read
    uint32_t numCoresArr[NUM_PRIORITIES];
    if (!readData(socket, &numCoresArr, sizeof(uint32_t) * NUM_PRIORITIES,
                  "Error receiving number of cores requested")) {
        return;
    }
    timeTrace("SERVER: Read number of cores requested");

    struct ProcessInfo* process = threadSocketToInfo[socket]->process;

    LOG(DEBUG, "Received core request from process %d:", process->id);
    for (size_t i = 0; i < NUM_PRIORITIES; i++) {
        LOG(DEBUG, " %u", numCoresArr[i]);
    }

    bool desiredCoresChanged = false;
    for (size_t priority = 0; priority < NUM_PRIORITIES; priority++) {
        // Update information for a single priority
        uint32_t prevNumCoresDesired = process->desiredCorePriorities[priority];
        uint32_t numCoresDesired = numCoresArr[priority];

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

    if (desiredCoresChanged) {
        // Even if the total number of cores this process wants is the same, we
        // may need to shuffle cores around because of priority changes.
        distributeCores();
    }

    timeTrace("SERVER: Finished serving core request");
}

/**
 * This method is called whenever a timer for thread preemption goes off. If the
 * process in question has not released the core it was supposed to, it is moved
 * to the unmanaged cpuset and all cores are redistributed. Otherwise nothing
 * happens.
 *
 * \param timerFd
 *     The timer that went off
 */
void
CoreArbiterServer::timeoutThreadPreemption(int timerFd) {
    if (!testingSkipSocketCommunication) {
        uint64_t time;
        ssize_t ret = read(timerFd, &time, sizeof(uint64_t));
        if (ret == -1) {
            LOG(ERROR, "Error reading number of expirations of the timer: %s",
                strerror(errno));
            exit(1);
        }
    }

    struct TimerInfo* timer = &timerFdToInfo[timerFd];
    if (processIdToInfo.find(timer->processId) == processIdToInfo.end()) {
        // This process is no longer registered with the server
        LOG(DEBUG,
            "Core retrieval timer went off for process %d, which "
            "is no longer registered with the server",
            timer->processId);
        return;
    }
    struct ProcessInfo* process = processIdToInfo[timer->processId];
    struct ThreadInfo* thread = timer->coreInfo->managedThread;

    if (!thread || thread->process != process) {
        // This process gave up the core it was supposed to
        LOG(DEBUG,
            "Core retrieval timer went off for process %d, but process "
            "already released the core it was supposed to.\n",
            process->id);
        return;
    }

    timeTrace("SERVER: Timing out thread preemption");

    LOG(DEBUG,
        "Core retrieval timer went off for process %d. Moving one of "
        "its threads to the unmanaged core.\n",
        process->id);

    // Remove the thread we requested preemption on from its managed core.
    // Keep around the original core that a thread was preempted from to ensure
    // that it is restored to this core when it is unpreempted.
    thread->corePreemptedFrom = thread->core;
    // Track at the process level the cores that have threads preempted from
    // them, so that another thread from the same process does not get
    // scheduled onto the core.
    thread->process->coresPreemptedFrom.insert(thread->core);

    removeThreadFromManagedCore(thread);
    changeThreadState(thread, RUNNING_PREEMPTED);
    process->stats->preemptedCount++;
    distributeCores();

    timeTrace("SERVER: Finished thread preemption");
}

/**
 * This method should be called when a thread hangs up its socket connection. It
 * cleans up all state associated with the thread, and will also clean up
 * process state if the process no longer has any threads connected. If this
 * thread was running on a managed core, then cores are redistributed.
 *
 * \param socket
 *     The socket whose thread disconnected
 */
void
CoreArbiterServer::cleanupConnection(int socket) {
    if (threadSocketToInfo.find(socket) == threadSocketToInfo.end()) {
        return;
    }
    ThreadInfo* thread = threadSocketToInfo[socket];
    ProcessInfo* process = thread->process;

    LOG(DEBUG, "Cleaning up state for thread %d", thread->id);

    if (sys->close(socket) < 0) {
        LOG(ERROR, "Error closing socket: %s", strerror(errno));
    }

    // We'll only distribute cores at the end if necessary
    bool shouldDistributeCores = false;

    // Update state pertaining to cores
    if (thread->state == RUNNING_MANAGED) {
        managedThreads.erase(
            std::remove(managedThreads.begin(), managedThreads.end(), thread),
            managedThreads.end());
        thread->core->managedThread = NULL;
        thread->core->threadRemovalTime = Cycles::rdtsc();
        process->stats->numOwnedCores--;

        // If we hand this core to another thread of the same process, do not
        // ask it to give back the core immediately.
        process->stats->threadCommunicationBlocks[thread->core->id]
            .coreReleaseRequested = false;
        stats->numUnoccupiedCores++;
        shouldDistributeCores = true;
    } else if (thread->state == RUNNING_PREEMPTED) {
        process->stats->unpreemptedCount++;
        assert(process->coresPreemptedFrom.find(thread->corePreemptedFrom) !=
               process->coresPreemptedFrom.end());
        process->coresPreemptedFrom.erase(thread->corePreemptedFrom);
        thread->corePreemptedFrom = NULL;
    }

    // Remove thread from all maps
    process->threadStateToSet[thread->state].erase(thread);
    threadSocketToInfo.erase(thread->socket);

    // If there are no remaining threads in this process, also delete all
    // process state
    bool noRemainingThreads = true;
    for (auto& kv : process->threadStateToSet) {
        if (!kv.second.empty()) {
            noRemainingThreads = false;
            break;
        }
    }

    if (noRemainingThreads) {
        LOG(NOTICE,
            "All of process %d's threads have exited. Removing all "
            "process records.\n",
            process->id);
        if (sys->close(process->sharedMemFd) < 0) {
            LOG(ERROR, "Error closing sharedMemFd: %s", strerror(errno));
        }
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

        stats->numProcesses--;
        LOG(NOTICE, "The server now has %u processes connected.",
            stats->numProcesses.load());

        delete process;
    }

    delete thread;

    if (shouldDistributeCores) {
        distributeCores();
    }
}

/**
 * Get the core id of the hypertwin of the given core. This code assumes there
 * is only one such hypertwin on the system it is running on. It also assumes
that hypertwins are delimited by the comma separator.
 *
 * \param coreId
 *     The coreId whose hypertwin's ID will be returned.
 */
int
getHyperTwin(int coreId) {
    // This file contains the siblings of core coreId.
    std::string siblingFilePath = "/sys/devices/system/cpu/cpu" +
                                  std::to_string(coreId) +
                                  "/topology/thread_siblings_list";
    FILE* siblingFile = fopen(siblingFilePath.c_str(), "r");
    int twin1, twin2;
    // The first cpuid in the file is always that of the physical core
    fscanf(siblingFile, "%d,%d", &twin1, &twin2);
    fclose(siblingFile);
    if (coreId == twin1)
        return twin2;
    return twin1;
}

/**
 * Find the best core for a given process from the candidate deque, and remove
 * it from the candidate deque.
 */
CoreArbiterServer::CoreInfo*
CoreArbiterServer::findGoodCoreForProcess(
    ProcessInfo* process, std::deque<struct CoreInfo*>& candidates) {
    // Compute the set of cores this process currently has managed threads
    // on, which may be empty.
    std::unordered_set<int> coresOwnedByProcess;
    for (struct ThreadInfo* threadInfo :
         process->threadStateToSet[RUNNING_MANAGED]) {
        // We assume managed threads have a core.
        coresOwnedByProcess.insert(threadInfo->core->id);
    }

    std::unordered_set<int> availableManagedCoreIds;

    // First look for a core which is the hypertwin of one of this
    // process's existing cores
    for (struct CoreInfo* candidate : candidates) {
        LOG(DEBUG, "Considering candidate %d, hypertwin of %d", candidate->id,
            getHyperTwin(candidate->id));
        if (coresOwnedByProcess.find(getHyperTwin(candidate->id)) !=
            coresOwnedByProcess.end()) {
            LOG(NOTICE, "candidate %d, hypertwin of %d has been selected",
                candidate->id, getHyperTwin(candidate->id));
            candidates.erase(
                std::find(candidates.begin(), candidates.end(), candidate));
            return candidate;
        }

        availableManagedCoreIds.insert(candidate->id);
    }

    // Next look for a core whose hypertwin is also in the set of
    // available cores.
    for (struct CoreInfo* candidate : candidates) {
        if (availableManagedCoreIds.find(getHyperTwin(candidate->id)) !=
            availableManagedCoreIds.end()) {
            candidates.erase(
                std::find(candidates.begin(), candidates.end(), candidate));
            return candidate;
        }
    }

    // Finally, find any available core
    CoreInfo* core = candidates.front();
    candidates.pop_front();
    return core;
}

/**
 * Utility function for waking up a given thread on the specific core.
 */
void
CoreArbiterServer::wakeupThread(ThreadInfo* thread, CoreInfo* core) {
    if (!sendData(
            thread->socket, &core->id, sizeof(int),
            "Error sending core ID to thread " + std::to_string(thread->id))) {
        if (errno == EPIPE) {
            // The system got a broken pipe error, then clean
            // up the connection.
            sys->epoll_ctl(epollFd, EPOLL_CTL_DEL, thread->socket, NULL);
            cleanupConnection(thread->socket);
        } else {
            exit(-1);
        }
    }
}

/**
 * This method handles all the logic of deciding which threads should receive
 * which cores and actually changing the underlying cpusets, both to scale
 * up/down the number of managed cores and to assign threads to managed cpusets.
 * If a thread needs to be preempted a timer is set and the process is notified
 * that it should release a core, but no changes to the cpuset occur.
 *
 * Threads are assigned to cores based on their priorities. All higher priority
 * requests are granted before lower priorities. Within a priority, cores are
 * split evenly among processes.
 */
void
CoreArbiterServer::distributeCores() {
    timeTrace("SERVER: Starting core distribution");

    if (testingSkipCoreDistribution) {
        LOG(DEBUG, "Skipping core distribution");
        return;
    }

    LOG(DEBUG, "Distributing cores among threads...");

    size_t maxManagedCores = managedCores.size() + unmanagedCores.size();

    // First, find the threads that should receive cores.
    // This is a queue (front has higher priority) of threads not currently
    // managed that should be placed on cores
    std::deque<struct ThreadInfo*> threadsToReceiveCores;

    // Keep track of the threads that are already managed and should remain
    // so. Threads that will be preempted do not make it into this set.
    std::unordered_set<struct ThreadInfo*> threadsAlreadyManaged;

    // Iterate from highest to lowest priority
    bool coresFilled = false;
    for (size_t priority = 0;
         priority < corePriorityQueues.size() && !coresFilled; priority++) {
        auto& processes = corePriorityQueues[priority];
        bool threadAdded = true;

        // A running count of how many cores we have assigned to a process at
        // this priority. This makes it easy to ensure that we don't assign
        // more cores to a process than it has requested.
        std::unordered_map<struct ProcessInfo*, uint32_t> processToCoreCount;

        // Any threads that are already managed should remain so at this
        // priority.
        for (struct ThreadInfo* thread : managedThreads) {
            if (threadsAlreadyManaged.find(thread) !=
                threadsAlreadyManaged.end()) {
                continue;
            }

            struct ProcessInfo* process = thread->process;
            if (processToCoreCount[process] <
                process->desiredCorePriorities[priority]) {
                // We want to keep this thread on its core
                threadsAlreadyManaged.insert(thread);
                processToCoreCount[process]++;

                if (threadsToReceiveCores.size() +
                        threadsAlreadyManaged.size() ==
                    maxManagedCores) {
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
                std::unordered_set<struct ThreadInfo*>* threadSet =
                    &(process->threadStateToSet[RUNNING_PREEMPTED]);
                if (threadSet->empty()) {
                    threadSet = &(process->threadStateToSet[BLOCKED]);
                }
                if (!threadSet->empty()) {
                    // Choose some blocked thread to put on a core
                    struct ThreadInfo* thread = *(threadSet->begin());
                    threadsToReceiveCores.push_back(thread);
                    processToCoreCount[process]++;
                    threadAdded = true;

                    // Temporarily remove the thread from the process's set of
                    // threads so that we don't assign it to a core more than
                    // once
                    threadSet->erase(thread);

                    if (threadsToReceiveCores.size() +
                            threadsAlreadyManaged.size() ==
                        maxManagedCores) {
                        coresFilled = true;
                        break;
                    }
                }
            }
        }
    }

    timeTrace("SERVER: Finished deciding which threads to put on cores");

    // Add threads back to the correct sets in their process
    for (struct ThreadInfo* thread : threadsToReceiveCores) {
        thread->process->threadStateToSet[thread->state].insert(thread);
    }

    size_t numAssignedCores =
        threadsToReceiveCores.size() + threadsAlreadyManaged.size();
    if (numAssignedCores > managedCores.size()) {
        // We need to make more cores managed
        size_t numCoresToMakeManaged = numAssignedCores - managedCores.size();
        LOG(DEBUG, "Making %lu cores managed", numCoresToMakeManaged);
        // Choose the right cores to make unmanaged, based on the set of
        // threads to receive cores.
        // This is the number of already-managed cores that can be used to
        // service threadsToReceiveCores.
        uint32_t offset = static_cast<uint32_t>(managedCores.size() -
                                                threadsAlreadyManaged.size());
        // The following loop assumes that the set of already-managed cores
        // which will be considered by threadsToReceiveCores is already a good
        // set. A more strict calculation would throw out all parts of the
        // managed core set which do not already have a thread, and reconsider
        // the additions to the managed core set from scratch.
        for (uint32_t i = 0; i < numCoresToMakeManaged; i++) {
            CoreInfo* coreToAdd = findGoodCoreForProcess(
                threadsToReceiveCores[i + offset]->process, unmanagedCores);
            managedCores.push_back(coreToAdd);
        }

        // Update the unmanaged cpuset now so that threads it will be updated
        // by the time we wake up managed threads
        updateUnmanagedCpuset();
    }

    // Extract the subset of managedCores that do not have a managedThread
    // under the current distribution, as well as the subset of managedCores
    // that have a premptible thread on them.
    std::deque<struct CoreInfo*> availableManagedCores;
    std::deque<struct CoreInfo*> preemptibleManagedCores;
    for (struct CoreInfo* core : managedCores) {
        if (!core->managedThread) {
            availableManagedCores.push_back(core);
        } else if (threadsAlreadyManaged.find(core->managedThread) ==
                   threadsAlreadyManaged.end()) {
            preemptibleManagedCores.push_back(core);
        } else {
            LOG(DEBUG, "Keeping thread %d on core %d", core->managedThread->id,
                core->id);
        }
    }

    // First restore all previously preempted threads among the
    // threadsToReceiveCores and ensure that they are satisfied.
    for (auto it = threadsToReceiveCores.begin();
         it != threadsToReceiveCores.end();) {
        ThreadInfo* thread = *it;
        if (thread->corePreemptedFrom == NULL) {
            it++;
            continue;
        }
        // Check if the desired core is among the available managed cores. If
        // so, then claim it immediately.
        // In either case, remove it from threadsToReceiveCores.
        auto availableCoresIt =
            std::find(availableManagedCores.begin(),
                      availableManagedCores.end(), thread->corePreemptedFrom);
        if (availableCoresIt != availableManagedCores.end()) {
            CoreInfo* core = thread->corePreemptedFrom;
            struct ProcessInfo* process = thread->process;
            LOG(NOTICE, "Re-granting core %d to thread %d from process %d",
                core->id, thread->id, process->id);

            // Move the thread before waking it up so that it wakes up in its
            // new cpuset
            if (!moveThreadToManagedCore(thread, core)) {
                // We were probably unable to move this thread to a managed
                // core because it has exited. To handle this case, it is
                // easiest to leave this core unoccupied for now, since we will
                // receive a hangup message from the thread's socket at which
                // point distributeCores() will be called again and this core
                // will be filled.
                LOG(DEBUG,
                    "Skipping assignment of core %d because were were "
                    "unable to write to it\n",
                    core->id);
            }
            availableManagedCores.erase(availableCoresIt);
        }
        it = threadsToReceiveCores.erase(it);
    }
    // TODO(hq6): Consider all cores; currently there is an explicit set of
    // managed vs unmanaged cores, and the managed core set is too small.
    // Somehow we need to consider all cores when we decide what to do.

    // Go through threads and try to find a core for them.
    while (!threadsToReceiveCores.empty() && !availableManagedCores.empty()) {
        struct ThreadInfo* thread = threadsToReceiveCores.front();
        threadsToReceiveCores.pop_front();

        struct ProcessInfo* process = thread->process;
        CoreInfo* core = findGoodCoreForProcess(process, availableManagedCores);

        // Refuse to take cores which threads were previously booted from.
        while (process->coresPreemptedFrom.find(core) !=
               process->coresPreemptedFrom.end()) {
            LOG(WARNING,
                "Skipping over core %d which was previously preempted from.",
                core->id);
            if (availableManagedCores.empty()) {
                core = NULL;
                break;
            }
            core = findGoodCoreForProcess(process, availableManagedCores);
        }
        // We ran out of cores which are not bespoken for a particular kernel
        // thread (because said kernel thread was previously preempted and not
        // yet restored).
        if (core == NULL) {
            break;
        }

        LOG(NOTICE, "Granting core %d to thread %d from process %d", core->id,
            thread->id, process->id);

        // Ensure that the new thread is not preempted immediately due to
        // stale state left behind by a previously preempted thread from
        // the same process.
        if (process->stats->threadCommunicationBlocks[core->id]
                .coreReleaseRequested) {
            LOG(ERROR,
                "Invariant Violated: Attempted to grant preempted core %d to a "
                "thread other than the preempted thread.",
                core->id);
            abort();
        }

        // Move the thread before waking it up so that it wakes up in its
        // new cpuset
        ThreadState prevState = thread->state;
        if (!moveThreadToManagedCore(thread, core)) {
            // We were probably unable to move this thread to a managed
            // core because it has exited. To handle this case, it is
            // easiest to leave this core unoccupied for now, since we will
            // receive a hangup message from the thread's socket at which
            // point distributeCores() will be called again and this core
            // will be filled.
            LOG(DEBUG,
                "Skipping assignment of core %d because were were "
                "unable to write to it\n",
                core->id);
            continue;
        }

        if (prevState == RUNNING_PREEMPTED) {
            LOG(DEBUG,
                "Thread %d was previously running preempted on the "
                "unmanaged core\n",
                thread->id);
            process->stats->unpreemptedCount++;
        } else {
            // Thread was blocked
            if (!testingSkipSocketCommunication) {
                // Wake up the thread
                // TimeTrace::record("SERVER: Sending wakeup");
                wakeupThread(thread, core);
                // TimeTrace::record("SERVER: Finished sending wakeup\n");
                LOG(DEBUG, "Sent wakeup");
            }

            process->stats->numBlockedThreads--;
            LOG(DEBUG, "Process %d now has %u blocked threads", process->id,
                process->stats->numBlockedThreads.load());
        }
    }
    // Sanity check; make sure we have enough preemptible cores to cover the
    // threads that should receive cores.
    if (preemptibleManagedCores.size() < threadsToReceiveCores.size()) {
        LOG(ERROR,
            "Invariant violated: threadsToReceiveCores is not empty, but "
            "there are no cores to preempt.");
        abort();
    }

    // All cores which are preemptible must be preempted; otherwise
    // applications cannot scale down unless there is competition from other
    // applications.
    while (!preemptibleManagedCores.empty()) {
        struct CoreInfo* core = preemptibleManagedCores.front();
        preemptibleManagedCores.pop_front();
        requestCoreRelease(core);
    }

    timeTrace("SERVER: Finished core distribution");
}

/**
 * Tells the process with a thread running on the given managed core that it
 * should release a core and sets a timer to enforce this request. When the
 * timer goes off, if the process has not released a core then the thread should
 * be forceably preempted.
 *
 * \param core
 *     The managed core that the server wants back for another process
 */
void
CoreArbiterServer::requestCoreRelease(struct CoreInfo* core) {
    // TODO(jspeiser): Setting up this timer takes ~3us. Could be optimized by
    // keeping a single timer for everything.

    if (!core->managedThread) {
        LOG(WARNING, "There is no thread on core %d to preempt", core->id);
        return;
    }

    timeTrace("SERVER: Requesting core release");

    struct ProcessInfo* process = core->managedThread->process;
    LOG(NOTICE,
        "Starting preemption of thread belonging to process %d "
        "on core %d\n",
        process->id, core->id);

    // Tell the thread that it needs to release its core.
    process->stats->threadCommunicationBlocks[core->id].coreReleaseRequested =
        true;

    int timerFd = sys->timerfd_create(CLOCK_MONOTONIC, 0);
    LOG(DEBUG, "Created timerFd %d", timerFd);
    if (timerFd < 0) {
        LOG(ERROR, "Error on timerfd_create: %s", strerror(errno));
        return;
    }

    // Set timer to enforce preemption
    struct itimerspec timerSpec;
    timerSpec.it_interval.tv_sec = 0;
    timerSpec.it_interval.tv_nsec = 0;
    timerSpec.it_value.tv_sec = preemptionTimeout / 1000;
    timerSpec.it_value.tv_nsec = (preemptionTimeout % 1000) * 1000000;

    if (sys->timerfd_settime(timerFd, 0, &timerSpec, NULL) < 0) {
        LOG(ERROR, "Error on timerFd_settime: %s", strerror(errno));
        return;
    }

    struct epoll_event timerEvent;
    timerEvent.events = EPOLLIN | EPOLLRDHUP;
    timerEvent.data.fd = timerFd;
    if (sys->epoll_ctl(epollFd, EPOLL_CTL_ADD, timerFd, &timerEvent) < 0) {
        LOG(ERROR, "Error adding timerFd to epoll: %s", strerror(errno));
        return;
    }

    timerFdToInfo[timerFd] = {process->id, core};

    timeTrace("SERVER: Finished requesting core release");
}

/**
 * Attempts to read numBytes from the provided socket connection into buf. If
 * the read fails or does not read the expected amount of data, the provided
 * error message is printed and false is returned. Otherwise returns true.
 *
 * \param socket
 *     The socket connection to read from
 * \param buf
 *     The buffer to write data to
 * \param numBytes
 *     The number of bytes to read
 * \param err
 *     An error string for if the read fails
 * \return
 *     True if the read succeeds and false otherwise
 */
bool
CoreArbiterServer::readData(int socket, void* buf, size_t numBytes,
                            std::string err) {
    ssize_t readBytes = sys->recv(socket, buf, numBytes, 0);
    if (readBytes < 0) {
        LOG(ERROR, "%s: %s", err.c_str(), strerror(errno));
        return false;
    } else if ((size_t)readBytes < numBytes) {
        LOG(WARNING, "%s: expected %lu bytes but received %ld", err.c_str(),
            numBytes, readBytes);
        return false;
    }

    return true;
}

/**
 * Attempts to send numBytes data of the provided buffer to the provided socket.
 * If the send fails, the provided error message is printed and false is
 * returned. Otherwise returns true.
 *
 * \param socket
 *     The socket connection to write to
 * \param buf
 *     The buffer to read data from
 * \param numBytes
 *     The number of bytes to write
 * \param err
 *     An error string for if the send fails
 * \return
 *     True if the write succeeds and false otherwise
 */
bool
CoreArbiterServer::sendData(int socket, void* buf, size_t numBytes,
                            std::string err) {
    // Don't generate a SIGPIPE signal if the peer on a stream-
    // oriented socket has closed the connection.
    // The EPIPE error is still returned.
    ssize_t bytesSent = sys->send(socket, buf, numBytes, MSG_NOSIGNAL);
    if (bytesSent < 0) {
        LOG(ERROR, "%s: %s", err.c_str(), strerror(errno));
        return false;
    }
    if (bytesSent != static_cast<ssize_t>(numBytes)) {
        LOG(ERROR, "%s: Expected to send %zu bytes, only sent %ld bytes.",
            err.c_str(), numBytes, bytesSent);
        return false;
    }
    return true;
}

/**
 * Creates a new cpuset at dirName (this should be within the cpuset filesystem)
 * and assigns it the given cores and memories. Exits on error.
 *
 * \param dirName
 *     The path at which to create the cpuset. This should be within the cpuset
 *     filesystem.
 * \param cores
 *     A comma- and/or dash-delimited string representing the cores that should
 *     belong to this cpuset.
 * \param mems
 *     A comma- and/or dash-delimited string representing the memories that
 *     should belong to this cpuset.
 */
void
CoreArbiterServer::createCpuset(std::string dirName, std::string cores,
                                std::string mems) {
    if (sys->mkdir(dirName.c_str(), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP |
                                        S_IXGRP | S_IROTH | S_IXOTH) < 0) {
        LOG(ERROR, "Error creating cpuset directory at %s: %s", dirName.c_str(),
            strerror(errno));
        exit(-1);
    }

    std::string memsPath = dirName + "/cpuset.mems";
    std::ofstream memsFile(memsPath);
    if (!memsFile.is_open()) {
        LOG(ERROR, "Unable to open %s", memsPath.c_str());
        exit(-1);
    }
    memsFile << mems;
    memsFile.close();

    std::string cpusPath = dirName + "/cpuset.cpus";
    std::ofstream cpusFile(cpusPath);
    if (!cpusFile.is_open()) {
        LOG(ERROR, "Unable to open %s", cpusPath.c_str());
        exit(-1);
    }
    cpusFile << cores;
    cpusFile.close();
}

/**
 * Moves all processes in the cpuset at fromPath to the cpuset at toPath. This
 * is useful at startup to move all processes into the unmanaged cpuset.
 *
 * \param fromPath
 *     The path to the cpuset.cpus file to move processes from
 * \param toPath
 *     The path to the cpuset.cpus file to move all processes to
 */
void
CoreArbiterServer::moveProcsToCpuset(std::string fromPath, std::string toPath) {
    if (testingSkipCpusetAllocation) {
        return;
    }

    LOG(DEBUG, "Moving procs in %s to %s", fromPath.c_str(), toPath.c_str());

    std::ifstream fromFile(fromPath);
    if (!fromFile.is_open()) {
        LOG(ERROR, "Unable to open %s", fromPath.c_str());
        exit(-1);
    }

    std::ofstream toFile(toPath);
    if (!toFile.is_open()) {
        LOG(ERROR, "Unable to open %s", toPath.c_str());
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
                LOG(ERROR, "Unable top open %s", toPath.c_str());
                exit(-1);
            }
        }
    }

    fromFile.close();
    toFile.close();
}

/**
 * Examines all the threads on a given core, and removes threads which are not
 * the managed thread from that core.
 */
void
CoreArbiterServer::removeUnmanagedThreadsFromCore(CoreInfo* core) {
    if (testingSkipCpusetAllocation) {
        return;
    }

    std::ifstream fromFile(core->cpusetFilename);
    if (!fromFile.is_open()) {
        LOG(ERROR, "Unable to open %s", core->cpusetFilename.c_str());
        exit(-1);
    }

    int threadId;
    while (fromFile >> threadId) {
        // The managed thread should stay put.
        if (threadId == core->managedThread->id)
            continue;

        // Every other thread should be moved to the unmanagedCpusetTasks.
        unmanagedCpusetTasks << threadId;
        unmanagedCpusetTasks.flush();
        if (unmanagedCpusetTasks.bad()) {
            // This error is likely because the thread has exited. Sleeping
            // helps keep the kernel from giving more errors the next time we
            // try to move a legitimate thread.
            LOG(ERROR, "Unable to write %d to unmanaged cpuset file", threadId);
            usleep(750);
        }
    }
    fromFile.close();
}

/**
 * Removes all cpusets at the given directory, including the directory itself.
 * This should be called at both server startup and shutdown, to ensure a clean
 * cpuset setup for the server and as a courtesy to the system when the server
 * exits.
 *
 * \param arbiterCpusetPath
 *     The path to the CoreArbiterServer's cpuset subtree
 */
void
CoreArbiterServer::removeOldCpusets(std::string arbiterCpusetPath) {
    if (testingSkipCpusetAllocation) {
        return;
    }

    std::string procsDestFilename = cpusetPath + "/cgroup.procs";
    DIR* dir = sys->opendir(arbiterCpusetPath.c_str());
    if (!dir) {
        // This is likely just because we don't have old cpusets to remove
        LOG(WARNING, "Error on opendir %s: %s", arbiterCpusetPath.c_str(),
            strerror(errno));
        return;
    }

    // Remove all processes from a cpuset
    for (struct dirent* entry = sys->readdir(dir); entry != NULL;
         entry = sys->readdir(dir)) {
        if (entry->d_type == DT_DIR && entry->d_name[0] != '.') {
            std::string dirName =
                arbiterCpusetPath + "/" + std::string(entry->d_name);
            std::string procsFilename = dirName + "/cgroup.procs";
            moveProcsToCpuset(procsFilename, procsDestFilename);
        }
    }

    // We need to sleep here to give the kernel time to actually move processes
    // into different cpusets. (Retrying doesn't work.)
    usleep(750);
    rewinddir(dir);

    // Delete all CoreArbiter cpuset subdirectories
    for (struct dirent* entry = sys->readdir(dir); entry != NULL;
         entry = sys->readdir(dir)) {
        if (entry->d_type == DT_DIR && entry->d_name[0] != '.') {
            std::string dirName =
                arbiterCpusetPath + "/" + std::string(entry->d_name);

            LOG(DEBUG, "removing %s", dirName.c_str());
            if (sys->rmdir(dirName.c_str()) < 0) {
                LOG(ERROR, "Error on rmdir %s: %s", dirName.c_str(),
                    strerror(errno));
                exit(-1);
            }
        }
    }

    // Remove the whole CoreArbiter cpuset directory
    if (sys->rmdir(arbiterCpusetPath.c_str()) < 0) {
        LOG(ERROR, "Error on rmdir %s: %s", arbiterCpusetPath.c_str(),
            strerror(errno));
        exit(-1);
    }

    if (sys->closedir(dir) < 0) {
        LOG(ERROR, "Error on closedir %s: %s", arbiterCpusetPath.c_str(),
            strerror(errno));
        exit(-1);
    }
}

/**
 * Moves the given thread to the given managed core and updates all associated
 * thread/core state. The core must already be part of a managed cpuset.
 *
 * \param thread
 *     The thread to move to a managed core
 * \param core
 *     The managed core to move the thread to
 * \return
 *     True if the thread is successfully placed on the core and false
 *     otherwise
 */
bool
CoreArbiterServer::moveThreadToManagedCore(struct ThreadInfo* thread,
                                           struct CoreInfo* core) {
    if (!testingSkipCpusetAllocation) {
        timeTrace("SERVER: Moving thread to managed cpuset");

        core->cpusetFile << thread->id;
        core->cpusetFile.flush();
        if (core->cpusetFile.bad()) {
            // This error is likely because the thread has exited. We need to
            // close and reopen the file to prevent future errors.
            LOG(ERROR, "Unable to write %d to cpuset file for core %d",
                thread->id, core->id);
            core->cpusetFile.close();
            core->cpusetFile.clear();
            core->cpusetFile.open(core->cpusetFilename);
            return false;
        }

        timeTrace("SERVER: Finished moving thread to managed cpuset");
    }

    changeThreadState(thread, RUNNING_MANAGED);
    thread->core = core;
    core->managedThread = thread;
    managedThreads.push_back(thread);
    thread->process->stats->numOwnedCores++;
    stats->numUnoccupiedCores--;

    if (thread->corePreemptedFrom) {
        ProcessInfo* process = thread->process;
        assert(process->coresPreemptedFrom.find(thread->corePreemptedFrom) !=
               process->coresPreemptedFrom.end());
        thread->process->coresPreemptedFrom.erase(thread->corePreemptedFrom);
        thread->corePreemptedFrom = NULL;
    }

    return true;
}

/**
 * Removes the given thread from its managed core and updates all associated
 * state. The thread is only moved to the unmanaged cpuset if the changeCpuset
 * flag is set. This flag is useful to prevent the unnecessary moving of a
 * thread when it blocks.
 *
 * \param thread
 *     The thread being removed from its managed core
 * \param changeCpuset
 *     If true, then the provided thread willbe moved to the unmanaged cpuset
 */
void
CoreArbiterServer::removeThreadFromManagedCore(struct ThreadInfo* thread,
                                               bool changeCpuset) {
    // For unknown reasons, this sometimes takes 6us and sometimes takes 14us.
    // It likely has something to do with how the kernel handles moving
    // processes between cpusets.

    if (!thread) {
        LOG(WARNING, "No thread to remove from managed core");
        return;
    }

    if (!thread->core) {
        LOG(WARNING, "Thread %d was already on unmanaged core", thread->id);
        return;
    }

    if (changeCpuset && !testingSkipCpusetAllocation) {
        // Writing a thread to a new cpuset automatically removes it from the
        // one it belonged to before
        timeTrace("SERVER: Removing thread from managed cpuset");

        unmanagedCpusetTasks << thread->id;
        unmanagedCpusetTasks.flush();
        if (unmanagedCpusetTasks.bad()) {
            // This error is likely because the thread has exited. Sleeping
            // helps keep the kernel from giving more errors the next time we
            // try to move a legitimate thread.
            LOG(ERROR, "Unable to write %d to unmanaged cpuset file",
                thread->id);
            usleep(750);
        }

        timeTrace("SERVER: Finished removing thread from managed cpuset");
    }

    thread->process->stats->numOwnedCores--;
    thread->core->managedThread = NULL;
    thread->core->threadRemovalTime = Cycles::rdtsc();
    thread->core = NULL;
    managedThreads.erase(
        std::remove(managedThreads.begin(), managedThreads.end(), thread),
        managedThreads.end());

    stats->numUnoccupiedCores++;
}

/**
 * Updates the unmanaged cpuset with the cores in the unmanagedCores vector.
 * This method should not be called too often, as changing cpusets frequently
 * can cause the kernel to throw errors.
 */
void
CoreArbiterServer::updateUnmanagedCpuset() {
    if (testingSkipCpusetAllocation) {
        return;
    }

    std::string unmanagedCoresString = alwaysUnmanagedString;
    for (CoreInfo* core : unmanagedCores) {
        unmanagedCoresString += std::to_string(core->id) + ",";
    }

    LOG(DEBUG, "Changing unmanaged cpuset to %s", unmanagedCoresString.c_str());
    unmanagedCpusetCpus << unmanagedCoresString << std::endl;

    if (unmanagedCpusetCpus.bad()) {
        LOG(ERROR, "Error changing unmanaged cpuset cpus");
        exit(-1);  // TODO(jspeiser): handle elegantly
    }
}

/**
 * Updates the provided thread's state and all associated mappings.
 *
 * \param thread
 *     The thread to update
 * \param state
 *     The state the thread has changed to
 */
void
CoreArbiterServer::changeThreadState(struct ThreadInfo* thread,
                                     ThreadState state) {
    ThreadState prevState = thread->state;
    thread->state = state;
    thread->process->threadStateToSet[prevState].erase(thread);
    thread->process->threadStateToSet[state].insert(thread);
}

/**
 * This method attempts to attach gdb to the currently running process.
 */
void
invokeGDB(int signum) {
    char buf[256];
    snprintf(buf, sizeof(buf), "/usr/bin/gdb -p %d", getpid());
    int ret = system(buf);

    if (ret == -1) {
        std::cerr << "Failed to attach gdb upon receiving the signal "
                  << strsignal(signum) << std::endl;
    }
}

void
signalHandler(int signum) {
    // Prevent repeated invocations
    struct sigaction signalAction;
    signalAction.sa_handler = SIG_DFL;
    signalAction.sa_flags = SA_RESTART;
    sigaction(signum, &signalAction, NULL);

    // Process the signal
    if ((signum == SIGINT) || (signum == SIGTERM)) {
        std::thread([&] {
            CoreArbiterServer* mostRecentInstance =
                CoreArbiterServer::mostRecentInstance;
            if (mostRecentInstance != NULL) {
                mostRecentInstance->endArbitration();
            }
        })
            .detach();
    } else if ((signum == SIGSEGV) || (signum == SIGABRT)) {
        invokeGDB(signum);
    }
}

/**
 * This method enables us to perform cleanup when we are interrupted, and drop
 * into gdb immediately when we segfault.
 */
void
CoreArbiterServer::installSignalHandler() {
    struct sigaction signalAction;
    signalAction.sa_handler = signalHandler;
    signalAction.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &signalAction, NULL) != 0)
        LOG(ERROR, "Couldn't set signal handler for SIGINT");
    if (sigaction(SIGTERM, &signalAction, NULL) != 0)
        LOG(ERROR, "Couldn't set signal handler for SIGTERM");

    if (sigaction(SIGSEGV, &signalAction, NULL) != 0)
        LOG(ERROR, "Couldn't set signal handler for SIGSEGV");
    if (sigaction(SIGABRT, &signalAction, NULL) != 0)
        LOG(ERROR, "Couldn't set signal handler for SIGABRT");
}

}  // namespace CoreArbiter
