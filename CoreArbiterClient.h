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
#include <string.h>

#include "CoreArbiterCommon.h"
#include "Syscall.h"

namespace CoreArbiter {

class CoreArbiterClient {
  public:
    CoreArbiterClient(std::string serverSocketPath);
    ~CoreArbiterClient();

    void setNumCores(/* priority array */);
    void blockUntilCoreAvailable();

  private:
    void createNewServerConnection(std::string serverSocketPath);
    void registerThread();

    std::string serverSocketPath;
    static thread_local int serverSocket;
    int sharedMemFd;
    core_count_t* coreReleaseRequestCount; // shared memory, incremented by server
    core_count_t coreReleaseCount; // local, incremented by client
    static thread_local bool registeredAsThread;

    static Syscall* sys;
};

}

#endif // CORE_ARBITER_CLIENT_H_