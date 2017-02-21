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

#include "CoreArbiterCommon.h"
#include "Syscall.h"

namespace CoreArbiter {

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

    void setNumCores(core_t numCores);
    bool shouldReleaseCore();
    core_t blockUntilCoreAvailable();
    core_t getOwnedCoreCount();

    class ClientException: public std::runtime_error {
      public:
        ClientException(std::string err) : runtime_error(err) {}
    };

    typedef std::unique_lock<std::mutex> Lock;

  private:
    // Constructor is private because CoreArbiterClient is a singleton
    CoreArbiterClient(std::string serverSocketPath);

    void createNewServerConnection();
    void registerThread();
    void readData(int fd, void* buf, size_t numBytes, std::string err);

    std::mutex mutex;
    core_t* coreReleaseRequestCount; // shared memory, incremented by server
    core_t coreReleaseCount; // local, incremented by client
    core_t ownedCoreCount;

    std::string serverSocketPath;
    static thread_local int serverSocket;
    int sharedMemFd;

    static Syscall* sys;
    static thread_local core_t coreId;
};

}

#endif // CORE_ARBITER_CLIENT_H_