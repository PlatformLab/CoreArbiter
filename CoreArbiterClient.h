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

#include <sys/types.h>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string.h>
#include <vector>

#include "CoreArbiterCommon.h"
#include "Syscall.h"


namespace CoreArbiter {

/**
 * This class provides an interface for running threads on dedicated cores. We
 * say that a thread is on a dedicated core or running exclusively if it is both
 * the only userspace thread on that core and only able to run on that core.
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

    void setNumCores(std::vector<core_t>& numCores);
    bool shouldReleaseCore();
    core_t blockUntilCoreAvailable();
    core_t getOwnedCoreCount();

    class ClientException: public std::runtime_error {
      public:
        ClientException(std::string err) : runtime_error(err) {}
    };

  private:
    // Constructor is private because CoreArbiterClient is a singleton
    CoreArbiterClient(std::string serverSocketPath);

    void createNewServerConnection();
    void registerThread();
    void readData(int fd, void* buf, size_t numBytes, std::string err);

    typedef std::unique_lock<std::mutex> Lock;

    // A mutex for locking around accesses to coreReleaseRequestCount,
    // coreReleaseCount, and ownedCoreCount, since they are shared across
    // threads.
    std::mutex mutex;

    // A monotonically increasing count of the number of cores the server has
    // requested that this process release in the client object's lifetime. It
    // is incremented by the server; the client should only read its value.
    core_t* coreReleaseRequestCount;

    // A monotonically increasing count of the number of cores this process has
    // released back to the server (by calling blockUntilCoreAvailable()). It
    // is incremented by the client.
    core_t coreReleaseCount;

    // The number of cores that this processes currently owns, i.e. the number
    // of threads that it has running exclusively on cores.
    core_t ownedCoreCount;

    // The path to the socket that the CoreArbiterServer is listening on.
    std::string serverSocketPath;

    // The file descriptor whose file contains coreReleaseRequestCount. This
    // file is mmapped more fast access.
    int sharedMemFd;

    // The socket file descriptor used to communicate with the server. Every
    // thread has its own socket connection to the server.
    static thread_local int serverSocket;

    // The ID of the core that this thread is running on. A value of -1
    // indicates that the server has not assigned a core to this thread. Every
    // thread has its own coreId.
    static thread_local core_t coreId;

    // Used for all syscalls for easier unit testing.
    static Syscall* sys;

    static bool testingSkipConnectionSetup;
};

}

#endif // CORE_ARBITER_CLIENT_H_