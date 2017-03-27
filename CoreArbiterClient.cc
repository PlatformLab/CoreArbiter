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
#include "Logger.h"

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
    , coreReleaseCount(0)
    , numOwnedCores(0)
    , numBlockedThreads(0)
    , serverSocketPath(serverSocketPath)
    , processSharedMemFd(-1)
    , globalSharedMemFd(-1)
{
}

CoreArbiterClient::~CoreArbiterClient()
{
    if (!testingSkipConnectionSetup) {
        sys->close(processSharedMemFd);
        sys->close(globalSharedMemFd);
    }
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
 * blockUntilCoreAvailable() and getnumOwnedCores() for how to actually place
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
CoreArbiterClient::setNumCores(std::vector<uint32_t> numCores)
{
    if (numCores.size() != NUM_PRIORITIES) {
        std::string err = "Core request must have " +
                          std::to_string(NUM_PRIORITIES) + " priorities";
        LOG(ERROR, "%s\n", err.c_str());
        throw ClientException(err);
    }

    if (serverSocket < 0) {
        // This thread has not yet registered with the server
        createNewServerConnection();
    }

    LOG(NOTICE, "Core request:");
    for (uint32_t num : numCores) {
        LOG(NOTICE, " %u", num);
    }
    LOG(NOTICE, "\n");

    uint8_t coreRequestMsg = CORE_REQUEST;
    sendData(serverSocket, &coreRequestMsg, sizeof(uint8_t),
             "Error sending core request prefix");

    sendData(serverSocket, &numCores[0], sizeof(uint32_t) * NUM_PRIORITIES,
             "Error sending core request priorities");
}

/**
 * Returns true if the server has requested that this client release a core. It
 * will only return true once per core that should be released. The caller is
 * obligated to ensure that some thread on an exclusive core calls
 * blockUntilCoreAvailable() if this method returns true. This method should be
 * called periodically, as the server will move an uncooperative process's
 * threads to an unmanaged core after RELEASE_TIMEOUT_MS milliseconds.
 */
bool
CoreArbiterClient::mustReleaseCore()
{
    if (serverSocket < 0) {
        // This thread hasn't established a connection with the server yet.
        createNewServerConnection();
    }

    // Do an initial check without the lock
    if (coreReleaseCount + coreReleasePendingCount >=
            processStats->coreReleaseRequestCount) {
        LOG(DEBUG, "No core release requested\n");
        return false;
    }

    Lock lock(mutex);

    // Check again now that we have the lock
    if (coreReleaseCount + coreReleasePendingCount >=
            processStats->coreReleaseRequestCount) {
        LOG(DEBUG, "No core release requested\n");
        return false;
    }

    coreReleasePendingCount++;
    LOG(NOTICE, "Core release requested\n");
    return true;
}

/**
 * Returns true if this process has a thread that was previously running
 * exclusively but was moved to the unmanaged core.
 */
bool
CoreArbiterClient::threadPreempted()
{
    return processStats->preemptedCount > processStats->unpreemptedCount;
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
        if (coreReleaseCount == processStats->coreReleaseRequestCount) {
            LOG(WARNING, "Not blocking thread %d because its process has not "
                "been asked to give up a core\n", sys->gettid());
            return coreId;
        } else {
            coreReleaseCount++;
            numOwnedCores--;

            if (coreReleasePendingCount > 0) {
                coreReleasePendingCount--;
            }
        }
    }

    uint8_t threadBlockMsg = THREAD_BLOCK;
    sendData(serverSocket, &threadBlockMsg, sizeof(uint8_t),
             "Error sending block message");

    LOG(NOTICE, "Thread %d is blocking until message received from server\n",
        sys->gettid());
    numBlockedThreads++;
    coreId = -1;
    readData(serverSocket, &coreId, sizeof(core_t),
             "Error receiving core ID from server");
    
    LOG(NOTICE, "Thread %d woke up on core %lu.\n", sys->gettid(), coreId);
    numOwnedCores++;
    numBlockedThreads--;

    return coreId;
}

/**
 * Tells the server that this thread no longer wishes to run on exclusive cores.
 * This should always be called before a thread exits to ensure that the server
 * doesn't keep stale threads on cores.
 */
void
CoreArbiterClient::unregisterThread()
{
    if (serverSocket < 0) {
        LOG(WARNING, "Cannot unregister a thread that was not previously "
                     "registered\n");
        return;
    }

    printf("Unregistering thread %d\n", sys->gettid());

    // Closing this socket alerts the server, which will clean up this thread's
    // state
    if (sys->close(serverSocket) < 0) {
        LOG(ERROR, "Error closing socket: %s\n", strerror(errno));
    }
}

/**
 * Returns the number of threads this process owns that are running exclusively
 * on a core.
 */
uint32_t
CoreArbiterClient::getNumOwnedCores()
{
    return numOwnedCores.load();
}

/**
 * Returns the number of threads belonging to this process that are currently
 * blocked waiting on a core.
 */
uint32_t
CoreArbiterClient::getNumBlockedThreads()
{
    return numBlockedThreads.load();
}

/**
 * Returns the number of cores under the server's control that do not currently
 * have a thread running exclusively.
 */
size_t
CoreArbiterClient::getNumUnoccupiedCores()
{
    if (serverSocket < 0) {
        createNewServerConnection();
    }

    return globalStats->numUnoccupiedCores;
}

/**
 * Returns the number of processes currently connected to the server.
 */
uint32_t
CoreArbiterClient::getNumProcessesOnServer() {
    if (serverSocket < 0) {
        createNewServerConnection();
    }

    return globalStats->numProcesses;
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
        LOG(WARNING, "This thread already has a connection to the server.\n");
        return;
    }

    if (testingSkipConnectionSetup) {
        LOG(DEBUG, "Skipping connection setup\n");
        serverSocket = 999; // To tell the test that this method was called
        return;
    }

    // Set up a socket
    serverSocket = sys->socket(AF_UNIX, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::string err = "Error creating socket: " +
                          std::string(strerror(errno));
        LOG(ERROR, "%s\n", err.c_str());
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
        LOG(ERROR, "%s\n", err.c_str());
        throw ClientException(err);
    }

    // Tell the server our process ID
    pid_t processId = sys->getpid();
    sendData(serverSocket, &processId, sizeof(pid_t),
             "Error sending process ID");

    // Tell the server our thread ID
    pid_t threadId = sys->gettid();
    sendData(serverSocket, &threadId, sizeof(pid_t),
             "Error sending thread ID");

    Lock lock(mutex);
    if (!processStats) {
        // This is the first time this process is registering so we need to
        // set up the shared memory pages
        globalSharedMemFd = openSharedMemory((void**)&globalStats);
        processSharedMemFd = openSharedMemory((void**)&processStats);
    }

    LOG(NOTICE, "Successfully registered process %d, thread %d with server.\n",
        processId, threadId);
}

int CoreArbiterClient::openSharedMemory(void** bufPtr) {
    // Read the shared memory path length from the server
    size_t pathLen;
    readData(serverSocket, &pathLen, sizeof(size_t),
             "Error receiving shared memory path length");

    // Read the shared memory path from the server
    char sharedMemPath[pathLen];
    readData(serverSocket, sharedMemPath, pathLen,
             "Error receiving shared memory path");

    // Open the shared memory
    int fd = sys->open(sharedMemPath, O_RDONLY);
    if (fd < 0) {
        std::string err = "Opening shared memory at path " +
                          std::string(sharedMemPath) + " failed" +
                          std::string(strerror(errno));
        LOG(ERROR, "%s\n", err.c_str());
        throw ClientException(err);
    }

    *bufPtr = sys->mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, 0);
    if (*bufPtr == MAP_FAILED) {
        std::string err = "mmap failed: " + std::string(strerror(errno));
        LOG(ERROR, "%s\n", err.c_str());
        throw ClientException(err);
    }

    return fd;
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
        LOG(ERROR, "%s\n", fullErrStr.c_str());
        throw ClientException(fullErrStr);
    } else if ((size_t)readBytes < numBytes) {
        std::string fullErrStr = err + ": Expected " + std::to_string(numBytes)
                                 + " bytes but received "
                                 + std::to_string(readBytes);
        LOG(ERROR, "%s\n", fullErrStr.c_str());
        throw ClientException(fullErrStr);
    }
}

/**
 * Attempts to send numBytes data of the provided buffer to the provided socket.
 * If the send fails, a ClientException is thrown with the provided error
 * message.
 *
 * \param socket
 *     The socket connection to write to
 * \param buf
 *     The buffer to read data from
 * \param numBytes
 *     The number of bytes to write
 * \param err
 *     An error string for if the send fails
 */
void CoreArbiterClient::sendData(int socket, void* buf, size_t numBytes,
                                 std::string err) {
    if (sys->send(socket, buf, numBytes, 0) < 0) {
        std::string fullErrStr = err + ": " + std::string(strerror(errno));
        LOG(ERROR, "%s\n", fullErrStr.c_str());
        throw ClientException(err);
    }
}

}
