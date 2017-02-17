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
                      std::vector<uint32_t> exclusiveCores);
    ~CoreArbiterServer();
    void startArbitration();

    // class ServerException: public std::runtime_error {
    //   public:
    //     ServerException(std::string err) : runtime_error(err) {}
    // };

  private:
    void acceptConnection(int listenFd);
    void registerProcessInfo(int connectingFd);
    void registerThreadInfo(int connectingFd);
    void threadBlocking(int threadFd);
    void coresRequested(); // TODO: pass in core priorities
    void timeoutCoreRetrieval();

    void createCpuset(std::string dirName, std::string cores, std::string mems);
    void moveProcsToCpuset(std::string fromPath, std::string toPath);
    void removeOldCpusets(std::string arbiterCpusetPath);

    struct ProcessInfo {
        pid_t id;
        int socket;
        int sharedMemFd;
        core_count_t* coreReleaseRequestCount; // only ever incremented by server
        std::unordered_set<pid_t> activeThreadIds;
        std::unordered_set<pid_t> blockedThreadIds;

        ProcessInfo()
            : id(-1)
            , socket(-1)
            , sharedMemFd(-1)
            , coreReleaseRequestCount(NULL)
           {} 

        ProcessInfo(pid_t id, int socket, int sharedMemFd, core_count_t* coreReleaseRequestCount)
            : id(id)
            , socket(socket)
            , sharedMemFd(sharedMemFd)
            , coreReleaseRequestCount(coreReleaseRequestCount)
        {}
    };

    struct ThreadInfo {
        pid_t threadId;
        pid_t processId;
        int socket;

        ThreadInfo()
            : threadId(-1)
            , processId(-1)
            ,  socket(-1)
        {}

        ThreadInfo(pid_t threadId, pid_t processId, int socket)
            : threadId(threadId)
            , processId(processId)
            , socket(socket)
        {}
    };

    static std::string cpusetPath;

    std::string sharedMemPathPrefix;
    int epollFd;
    int listenFd;

    std::unordered_map<int, ThreadInfo> threadFdToInfo;
    std::unordered_map<pid_t, ProcessInfo> processIdToInfo;
    std::unordered_set<int> unregisteredConnections;

    static Syscall* sys;
};

}


#endif // CORE_ARBITER_SERVER_H_