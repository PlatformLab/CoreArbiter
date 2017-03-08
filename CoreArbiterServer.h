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

#ifndef CORE_ARBITER_SERVER_H_
#define CORE_ARBITER_SERVER_H_

#include <deque>
#include <fstream>
#include <sys/types.h>
#include <unordered_map>
#include <unordered_set>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <stdexcept>
#include <vector>

#include "CoreArbiterCommon.h"
#include "Syscall.h"

#define MAX_EPOLL_EVENTS 100

namespace CoreArbiter {

class CoreArbiterServer {
  public:
    CoreArbiterServer(std::string socketPath,
                      std::string sharedMemPathPrefix,
                      std::vector<core_t> exclusiveCores);
    ~CoreArbiterServer();
    void startArbitration();

  private:
    struct ThreadInfo;
    struct ProcessInfo;
    struct CoreInfo;

    struct CoreInfo {
        core_t id;
        struct ThreadInfo* exclusiveThread;
        std::ofstream cpusetFile;

        CoreInfo()
            : exclusiveThread(NULL)
        {}
    };

    enum ThreadState { RUNNING_EXCLUSIVE, RUNNING_SHARED, BLOCKED };
    struct ThreadInfo {
        pid_t id;
        struct ProcessInfo* process;
        int socket;
        struct CoreInfo* core;
        ThreadState state;

        ThreadInfo() {}

        ThreadInfo(pid_t threadId, struct ProcessInfo* process, int socket)
            : id(threadId)
            , process(process)
            , socket(socket)
            , core(NULL)
            , state(RUNNING_SHARED)
        {}
    };

    struct ProcessInfo {
        pid_t id;
        int sharedMemFd;
        
        core_t* coreReleaseRequestCount; // only ever incremented by server
        core_t coreReleaseCount;

        core_t totalCoresOwned;
        core_t totalCoresDesired;
        std::vector<core_t> desiredCorePriorities;

        // std::unordered_set<struct ThreadInfo*> threads;
        std::unordered_map<ThreadState, std::unordered_set<struct ThreadInfo*>,
                          std::hash<int>> threadStateToSet;

        ProcessInfo()
            : totalCoresOwned(0)
            , totalCoresDesired(0)
            , desiredCorePriorities(NUM_PRIORITIES)
        {}

        ProcessInfo(pid_t id, int sharedMemFd, core_t* coreReleaseRequestCount)
            : id(id)
            , sharedMemFd(sharedMemFd)
            , coreReleaseRequestCount(coreReleaseRequestCount)
            , coreReleaseCount(0)
            , totalCoresOwned(0)
            , totalCoresDesired(0)
            , desiredCorePriorities(NUM_PRIORITIES)
        {}
    };

    void acceptConnection(int listenSocket);
    void threadBlocking(int socket);
    void coresRequested(int socket);
    void countBlockedThreads(int socket);
    void timeoutCoreRetrieval(int timerFd);
    void cleanupConnection(int socket);

    void distributeCores();
    bool readData(int socket, void* buf, size_t numBytes, std::string err);
    bool sendData(int socket, void* buf, size_t numBytes, std::string err);
    void createCpuset(std::string dirName, std::string cores, std::string mems);
    void moveProcsToCpuset(std::string fromPath, std::string toPath);
    void removeOldCpusets(std::string arbiterCpusetPath);
    void moveThreadToExclusiveCore(struct ThreadInfo* thread,
                                   struct CoreInfo* core);
    void removeThreadFromExclusiveCore(struct ThreadInfo* thread);
    void changeThreadState(struct ThreadInfo* thread, ThreadState state);

    static std::string cpusetPath;

    std::string socketPath;
    std::string sharedMemPathPrefix;
    int epollFd;
    int listenSocket;
    std::unordered_map<int, struct ProcessInfo*> timerFdToProcess;

    std::unordered_map<int, struct ThreadInfo*> threadSocketToInfo;
    std::unordered_map<pid_t, struct ProcessInfo*> processIdToInfo;

    std::vector<struct CoreInfo> exclusiveCores;
    std::unordered_set<struct ThreadInfo*> exclusiveThreads;
    struct CoreInfo sharedCore;

    // The smallest index in the vector is the highest priority and the first
    // entry in the deque is the process that requested a core at that priority
    // first
    std::vector<std::deque<struct ProcessInfo*>> corePriorityQueues;

    static Syscall* sys;
    static bool testingSkipCpusetAllocation;
    static bool testingSkipCoreDistribution;
};

}

int ensureParents(const char *path, mode_t mode = S_IRWXU);

#endif // CORE_ARBITER_SERVER_H_
