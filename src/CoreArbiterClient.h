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

#ifndef CORE_ARBITER_CLIENT_H_
#define CORE_ARBITER_CLIENT_H_

#include <string.h>
#include <sys/types.h>
#include <atomic>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <vector>

#include "CoreArbiterCommon.h"
#include "Syscall.h"


namespace CoreArbiter {

/**
 * This class provides an interface for running threads on managed cores. We say
 * that a thread is on a managed core if it can only run on that core and is the
 * only thread that will do so. (The term "managed" comes from the fact that
 * this invariant is enforced by the CoreArbiterServer.)
 *
 * This class is a singleton because applications are expected to manage their
 * threads in a coordinated fashion. The user only interacts with the
 * CoreArbiterClient, but this class is closely tied to the CoreArbiterServer,
 * which is a separate process expected to be running on the same machine.
 */
class CoreArbiterClient {
  public:
    // Singleton methods
    static CoreArbiterClient& getInstance(std::string serverSocketPath) {
        static CoreArbiterClient instance(serverSocketPath);
        return instance;
    }
    CoreArbiterClient(CoreArbiterClient const&) = delete;
    void operator=(CoreArbiterClient const&) = delete;

    ~CoreArbiterClient();

    void setRequestedCores(std::vector<uint32_t> numCores);
    bool mustReleaseCore();
    bool threadPreempted();
    core_t blockUntilCoreAvailable();
    uint32_t getNumOwnedCores();
    void unregisterThread();

    // Meant for testing, not general use
    uint32_t getNumOwnedCoresFromServer();
    uint32_t getNumBlockedThreadsFromServer();
    uint32_t getNumBlockedThreads();
    size_t getNumUnoccupiedCores();
    uint32_t getNumProcessesOnServer();

    class ClientException: public std::runtime_error {
      public:
        explicit ClientException(std::string err) : runtime_error(err) {}
    };

  private:
    // Constructor is private because CoreArbiterClient is a singleton
    explicit CoreArbiterClient(std::string serverSocketPath);

    void createNewServerConnection();
    int openSharedMemory(void** bufPtr);
    void registerThread();
    void readData(int socket, void* buf, size_t numBytes, std::string err);
    void sendData(int socket, void* buf, size_t numBytes, std::string err);

    typedef std::unique_lock<std::mutex> Lock;

    // Used to guard data shared across threads, such as processStats,
    // coreReleaseCount, and coreReleasePendingCount.
    std::mutex mutex;

    // Information about this processes in shared memory. The server uses this
    // struct to communicate with the client about whether it should release a
    // core and whether it has a thread preempted.
    struct ProcessStats* processStats;

    // Information in shared memory about all processes connected to the same
    // server as this client. This is useful primarily for debugging and
    // benchmarking.
    struct GlobalStats* globalStats;

    // A monotonically increasing count of the number of cores this process has
    // released back to the server (by calling blockUntilCoreAvailable()). It
    // is incremented by the client.
    std::atomic<uint64_t> coreReleaseCount;

    // The number of cores that the client has been told it is obligated to
    // release but has not yet done so.
    std::atomic<uint64_t> coreReleasePendingCount;

    // The number of cores that this processes currently owns, i.e. the number
    // of threads that it has running on managed cores. This value is also in
    // shared memory, but it's useful to have a local copy to know the current
    // state of the system from the client's perspective (since socket
    // communication lags behind shared memory).
    std::atomic<uint32_t> numOwnedCores;

    // The number of threads this process currently has blocked waiting to be
    // woken up by the server. This value is also in shared memory, but it's
    // useful to have a local copy to know the current state of the system from
    // the client's perspective (since socket communication lags behind shared
    // memory).
    std::atomic<uint32_t> numBlockedThreads;

    // The path to the socket that the CoreArbiterServer is listening on.
    std::string serverSocketPath;

    // The file descriptor whose file contains process-specific information.
    // This is mmapped for fast access.
    int processSharedMemFd;

    // The file descriptor whose file contains global information aboub all
    // clients connected to the server. This is mmapped for fast access.
    int globalSharedMemFd;

    // The socket file descriptor used to communicate with the server. Every
    // thread has its own socket connection to the server.
    static thread_local int serverSocket;

    // The ID of the core that this thread is running on. A value of -1
    // indicates that the server has not assigned a core to this thread. Every
    // thread has its own coreId. This ID is NOT accurate for threads that have
    // been preempted from their managed core.
    static thread_local core_t coreId;

    // Used for all syscalls for easier unit testing.
    static Syscall* sys;

    // Useful for unit testing.
    static bool testingSkipConnectionSetup;
};

} // namespace CoreArbiter

#endif // CORE_ARBITER_CLIENT_H_