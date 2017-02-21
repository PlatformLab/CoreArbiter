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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "CoreArbiterClient.h"

namespace CoreArbiter {

thread_local int CoreArbiterClient::serverSocket = -1;
thread_local core_t CoreArbiterClient::coreId = -1;

static Syscall defaultSyscall;
Syscall* CoreArbiterClient::sys = &defaultSyscall;

CoreArbiterClient::CoreArbiterClient(std::string serverSocketPath)
    : mutex()
    , coreReleaseRequestCount(NULL)
    , coreReleaseCount(0)
    , ownedCoreCount(0)
    , serverSocketPath(serverSocketPath)
    , sharedMemFd(-1)
{
}

CoreArbiterClient::~CoreArbiterClient()
{

}

void
CoreArbiterClient::setNumCores(core_t numCores)
{
    if (serverSocket < 0) {
        // This thread has not yet registered with the server
        createNewServerConnection();
    }

    uint8_t coreRequestMsg = CORE_REQUEST;
    if (sys->send(serverSocket, &coreRequestMsg, sizeof(uint8_t), 0) < 0) {
        std::string err = "Core request prefix send failed: " +
                          std::string(strerror(errno));
        fprintf(stderr, "%s\n", err.c_str());
        throw ClientException(err);
    }

    if (sys->send(serverSocket, &numCores, sizeof(core_t), 0) < 0) {
        std::string err = "Core request send failed: " +
                          std::string(strerror(errno));
        fprintf(stderr, "%s\n", err.c_str());
        throw ClientException(err);
    }
}

bool
CoreArbiterClient::shouldReleaseCore()
{
    Lock lock(mutex);
    return *coreReleaseRequestCount - coreReleaseCount > 0;
}

core_t
CoreArbiterClient::blockUntilCoreAvailable()
{
    if (serverSocket < 0) {
        // This thread has not yet registered with the server
        createNewServerConnection();
    } else if (coreId >= 0) {
        // This thread currently has exclusive access to a core. We need to
        // check whether it should be blocking.
        Lock lock(mutex);
        if (*coreReleaseRequestCount - coreReleaseCount == 0) {
            printf("Not blocking thread %d because its process has not been "
                   "asked to give up a core\n", sys->gettid());
            return coreId;
        } else {
            coreReleaseCount++;
            ownedCoreCount--;
        }
    }

    uint8_t threadBlockMsg = THREAD_BLOCK;
    if (sys->send(serverSocket, &threadBlockMsg, sizeof(uint8_t), 0) < 0) {
        std::string err = "Block send failed: " + std::string(strerror(errno));
        fprintf(stderr, "%s\n", err.c_str());
        throw ClientException(err);
    }

    printf("Thread %d is blocking until message received from server\n",
           sys->gettid());
    coreId = -1;
    readData(serverSocket, &coreId, sizeof(core_t),
             "Error receiving core ID from server");
    
    printf("Thread %d woke up on core %lu.\n", sys->gettid(), coreId);
    ownedCoreCount++;

    return coreId;
}

core_t
CoreArbiterClient::getOwnedCoreCount()
{
    Lock lock(mutex);
    return ownedCoreCount;
}

void
CoreArbiterClient::createNewServerConnection()
{
    if (serverSocket != -1) {
        fprintf(stderr,
                "This thread already has a connection to the server.\n");
        return;
    }

    // Set up a socket
    serverSocket = sys->socket(AF_UNIX, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::string err = "Error creating socket: " +
                          std::string(strerror(errno));
        fprintf(stderr, "%s\n", err.c_str());
        throw ClientException(err);
    }

    struct sockaddr_un remote;
    memset(&remote, 0, sizeof(remote));
    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, serverSocketPath.c_str(),
            sizeof(remote.sun_path) - 1);
    if (sys->connect(
            serverSocket, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        std::string err = "Error connecting: " + std::string(strerror(errno));
        fprintf(stderr, "%s\n", err.c_str());
        throw ClientException(err);
    }

    // Tell the server our process ID
    pid_t processId = sys->getpid();
    if (sys->send(serverSocket, &processId, sizeof(pid_t), 0) < 0) {
        std::string err = "Send process ID failed: " +
                          std::string(strerror(errno));
        fprintf(stderr, "%s\n", err.c_str());
        throw ClientException(err);
    }

    // Tell the server our thread ID
    pid_t threadId = sys->gettid();
    if (sys->send(serverSocket, &threadId, sizeof(pid_t), 0) < 0) {
        std::string err = "Send process ID failed: " +
                          std::string(strerror(errno));
        fprintf(stderr, "%s\n", err.c_str());
        throw ClientException(err);
    }

    Lock lock(mutex);
    if (coreReleaseRequestCount == NULL) {
        // This is the first time this process is registering so we need to
        // set up the shared memory page.

        // Read the shared memory path length from the server
        size_t pathLen;
        readData(serverSocket, &pathLen, sizeof(size_t),
                 "Error receiving shared memory path length");

        // Read the shared memory path from the server
        char sharedMemPath[pathLen];
        readData(serverSocket, sharedMemPath, pathLen,
                 "Error receiving shared memory path");

        // Open the shared memory
        sharedMemFd = sys->open(sharedMemPath, O_RDONLY);
        if (sharedMemFd < 0) {
            std::string err = "Opening shared memory at path " +
                              std::string(sharedMemPath) + " failed" +
                              std::string(strerror(errno));
            fprintf(stderr, "%s\n", err.c_str());
            throw ClientException(err);
        }
        int pagesize = getpagesize();
        coreReleaseRequestCount = (core_t*)sys->mmap(
            NULL, pagesize, PROT_READ, MAP_SHARED, sharedMemFd, 0);
        if (coreReleaseRequestCount == (core_t*)(-1)) {
            std::string err = "mmap failed: " + std::string(strerror(errno));
            fprintf(stderr, "%s\n", err.c_str());
            throw ClientException(err);
        }
    }

    printf("Successfully registered process %d, thread %d with server.\n",
           processId, threadId);
}

/**
 * Throws ClientException on failure.
 */
void CoreArbiterClient::readData(int fd, void* buf, size_t numBytes,
                                 std::string err)
{
    ssize_t readBytes = sys->recv(fd, buf, numBytes, 0);
    if (readBytes < 0) {
        std::string fullErrStr = err + ": " + std::string(strerror(errno));
        fprintf(stderr, "%s\n", fullErrStr.c_str());
        throw ClientException(fullErrStr);
    } else if ((size_t)readBytes < numBytes) {
        std::string fullErrStr = err + ": Expected " + std::to_string(numBytes)
                                 + " bytes but received "
                                 + std::to_string(readBytes);
        fprintf(stderr, "%s\n", fullErrStr.c_str());
        throw ClientException(fullErrStr);
    }
}

}
