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

bool CoreArbiterClient::testingSkipConnectionSetup = false;

/**
 * Private constructor because CoreArbiterClient is a singleton class. The
 * constructor itself doesn't do anything except establish the path to the
 * server. A connection with the server is established the first time a thread
 * needs to communicate with it (i.e., calls setNumCores or shouldReleaseCore).
 *
 * The server is expected to be running before the client is initialized.
 *
 * \param serverSocketPath
 *     The path to the socket that the server is listening for connections on.
 */
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
    close(sharedMemFd);
}

/**
 * Requests a specified number of cores at various priority levels from the
 * server. The server expects NUM_PRIORITIES priority levels; a request
 * specifying more or fewer levels is considered an error. For example, if the
 * application wants 2 threads at priority 1 and 1 thread at priority 2 (with
 * 0-indexed priorities), it should send:
 *     0 2 1 0 0 0 0 0
 * Lower indexes have higher priority. Priorities are on a per-process basis.
 * One thread calling setNumCores will changed the desired number of cores for
 * all threads in its process.
 *
 * This request for cores is handled asynchronously by the server. See
 * blockUntilCoreAvailable() and getOwnedCoreCount() for how to actually place
 * a thread on a core and check how many cores the process currently owns.
 *
 * Throws a ClientException on error.
 *
 * \param numCores
 *     A vector specifying the number of cores requested at every priority
 *     level. The vector must of NUM_PRIORITIES entries. Lower indexes have
 *     higher priority.
 */
void
CoreArbiterClient::setNumCores(std::vector<core_t>& numCores)
{
    if (numCores.size() != NUM_PRIORITIES) {
        std::string err = "Core request must have " +
                          std::to_string(NUM_PRIORITIES) + " priorities\n";
        fprintf(stderr, "%s\n", err.c_str());
        throw ClientException(err);
    }

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

    if (sys->send(serverSocket, &numCores[0],
                  sizeof(core_t) * NUM_PRIORITIES, 0) < 0) {
        std::string err = "Core request send failed: " +
                          std::string(strerror(errno));
        fprintf(stderr, "%s\n", err.c_str());
        throw ClientException(err);
    }
}

/**
 * Returns true if the server has requested that this process release a core
 * (which it can do by calling blockUntilCoreAvailable() on a thread running
 * exclusively on a core). This method should be called periodically. An
 * uncooperative process will have its threads moved to an unmanaged core after
 * RELEASE_TIMEOUT_MS milliseconds.
 */
bool
CoreArbiterClient::shouldReleaseCore()
{
    Lock lock(mutex);
    if (!coreReleaseRequestCount) {
        // This process hasn't established a connection with the server yet.
        return false;
    }

    return *coreReleaseRequestCount - coreReleaseCount > 0;
}

/**
 * This method should be called by a thread that wants to run exclusively on a
 * core. It blocks the thread and does not return until it has been placed on a
 * core. In general it is safe to call blockUntilCoreAvailable() before
 * setNumCores(), but if a process calls blockUntilCoreAvailable() on all of its
 * threads it cannot get any work done, including calling setNumCores(). At most
 * the number of threads specified by setNumCores() will be woken up from a call
 * to blockUntilCoreAvailable().
 *
 * Throws a ClientException on error.
 */
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

/**
 * Returns the number of threads this process owns that are running exclusively
 * on a core.
 */
core_t
CoreArbiterClient::getOwnedCoreCount()
{
    Lock lock(mutex);
    return ownedCoreCount;
}

// -- private methods

/**
 * Opens a new connection with the server for this thread. If this is the first
 * time this process has communicated with the server, it will also set up the
 * necessary per-process state.
 *
 * Throws a ClientException on error.
 */
void
CoreArbiterClient::createNewServerConnection()
{
    if (serverSocket != -1) {
        fprintf(stderr,
                "This thread already has a connection to the server.\n");
        return;
    }

    if (testingSkipConnectionSetup) {
        serverSocket = 999; // To tell the test that this method was called
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
 * Attempts to read numBytes from the provided socket connection into buf. If
 * the read fails or does not read the expected amount of data, a
 * ClientException is thrown with the provided error message.
 *
 * \param socket
 *     The socket connection to read from
 * \param buf
 *     The buffer to write data to
 * \param numBytes
 *     The number of bytes to read
 * \param err
 *     An error string for if the read fails
 */
void CoreArbiterClient::readData(int socket, void* buf, size_t numBytes,
                                 std::string err)
{
    ssize_t readBytes = sys->recv(socket, buf, numBytes, 0);
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
