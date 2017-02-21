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
    enum ThreadState { RUNNING_EXCLUSIVE, RUNNING_SHARED, BLOCKED };
    struct ThreadInfo {
        pid_t threadId;
        pid_t processId;
        int socket;
        core_t coreId;
        ThreadState state;

        ThreadInfo() {}

        ThreadInfo(pid_t threadId, pid_t processId, int socket)
            : threadId(threadId)
            , processId(processId)
            , socket(socket)
            , coreId(0)
            , state(RUNNING_SHARED)
        {}
    };

    struct ProcessInfo {
        pid_t id;
        int sharedMemFd;
        
        core_t* coreReleaseRequestCount; // only ever incremented by server
        core_t coreReleaseCount;

        core_t numCoresOwned;
        core_t numCoresDesired;

        std::vector<struct ThreadInfo*> threads;

        ProcessInfo() {}

        ProcessInfo(pid_t id, int sharedMemFd, core_t* coreReleaseRequestCount)
            : id(id)
            , sharedMemFd(sharedMemFd)
            , coreReleaseRequestCount(coreReleaseRequestCount)
            , coreReleaseCount(0)
            , numCoresOwned(0)
            , numCoresDesired(0)
        {}
    };

    struct CoreInfo {
        core_t coreId;
        pid_t exclusiveThreadId;
        std::ofstream cpusetFile;

        CoreInfo()
            : coreId(0)
            , exclusiveThreadId(-1)
        {}
    };

    void acceptConnection(int listenFd);
    void threadBlocking(int threadFd);
    void coresRequested(int connectingFd);
    void timeoutCoreRetrieval();
    void cleanupConnection(int connectingFd);

    void grantCores();
    bool readData(int fd, void* buf, size_t numBytes, std::string err);
    void createCpuset(std::string dirName, std::string cores, std::string mems);
    void moveProcsToCpuset(std::string fromPath, std::string toPath);
    void removeOldCpusets(std::string arbiterCpusetPath);
    void moveThreadToCore(struct ThreadInfo* thread, struct CoreInfo* core);
    void removeThreadFromCore(struct ThreadInfo* thread);

    static std::string cpusetPath;

    std::string sharedMemPathPrefix;
    int epollFd;
    int listenFd;

    std::unordered_map<int, ThreadInfo*> threadFdToInfo;
    std::unordered_map<pid_t, ProcessInfo*> processIdToInfo;

    std::vector<struct CoreInfo> exclusiveCores;
    struct CoreInfo sharedCore;

    // The front of the queue has the highest priority (for now, longest
    // blocking) threads.
    std::deque<struct ProcessInfo*> processesOwedCores;

    static Syscall* sys;
    static bool testingSkipCpusetAllocation;
};

}


#endif // CORE_ARBITER_SERVER_H_