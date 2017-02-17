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
thread_local bool CoreArbiterClient::registeredAsThread = false;

static Syscall defaultSyscall;
Syscall* CoreArbiterClient::sys = &defaultSyscall;

CoreArbiterClient::CoreArbiterClient(std::string serverSocketPath)
    : serverSocketPath(serverSocketPath)
    , sharedMemFd(-1)
{
    // Create pool of socket 
    createNewServerConnection(serverSocketPath);

    // Tell the server that we're a process
    uint8_t process = PROCESS_CONN;
    if (sys->send(serverSocket, &process, sizeof(uint8_t), 0) < 0) {
        fprintf(stderr, "Send process flag failed: %s\n", strerror(errno));
        return;
    }

    // Tell the server our process ID
    pid_t processId = getpid();
    if (sys->send(serverSocket, &processId, sizeof(pid_t), 0) < 0) {
        fprintf(stderr, "Send process ID failed: %s\n", strerror(errno));
        return;
    }

    // Read the shared memory path length from the server
    size_t pathLen;
    if (sys->recv(serverSocket, &pathLen, sizeof(size_t), 0) < 0) {
        fprintf(stderr, "Receive shared memory path length failed: %s\n",
                strerror(errno));
        return;
    }

    // Read the shared memory path from the server
    char sharedMemPath[pathLen];
    if (sys->recv(serverSocket, sharedMemPath, pathLen, 0) < 0) {
        fprintf(stderr, "Receive shared memory path failed: %s\n",
                strerror(errno));
        return;
    }

    // Open the shared memory
    sharedMemFd = sys->open(sharedMemPath, O_RDONLY);
    if (sharedMemFd < 0) {
        fprintf(stderr, "Opening shared memory at path %s failed: %s\n",
                sharedMemPath, strerror(errno));
        return;
    }
    int pagesize = getpagesize();
    coreReleaseRequestCount = (core_count_t*)sys->mmap(
        NULL, pagesize, PROT_READ, MAP_SHARED, sharedMemFd, 0);
    if (coreReleaseRequestCount == (core_count_t*)(-1)) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        return;
    }

    printf("Successfully registered process %d with server. "
           "We have %lu cores available\n",
           processId, *coreReleaseRequestCount);
}

CoreArbiterClient::~CoreArbiterClient()
{

}

void
CoreArbiterClient::setNumCores()
{

}

void
CoreArbiterClient::blockUntilCoreAvailable()
{
    if (!registeredAsThread) {
        // This is the first time this thread is communicating with the server
        // (not including process startup), so we need to set up a new
        // connection 
        registerThread();
    }

    uint8_t threadBlockMsg = THREAD_BLOCK;
    if (sys->send(serverSocket, &threadBlockMsg, sizeof(uint8_t), 0) < 0) {
        fprintf(stderr, "Block send failed: %s\n", strerror(errno));
        return;
    }

    printf("Thread %d is blocking until message received from server\n",
           sys->gettid());

    uint8_t wakeupMsg;
    sys->recv(serverSocket, &wakeupMsg, sizeof(uint8_t), 0);

    printf("woke up\n");
}

void
CoreArbiterClient::createNewServerConnection(std::string serverSocketPath)
{
    if (serverSocket != -1) {
        fprintf(stderr,
                "This thread already has a connection to the server.\n");
        return;
    }

    serverSocket = sys->socket(AF_UNIX, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
        return;
    }

    struct sockaddr_un remote;
    memset(&remote, 0, sizeof(remote));
    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, serverSocketPath.c_str(),
            sizeof(remote.sun_path) - 1);
    if (sys->connect(
            serverSocket, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        fprintf(stderr, "Error connecting: %s\n", strerror(errno));
        return;
    }
}

void
CoreArbiterClient::registerThread()
{
    if (serverSocket < 0) {
        // We don't need to do this in the case where we are the same thread
        // that registered our process
        createNewServerConnection(serverSocketPath);
    }

    // Tell the server that we're a thread
    uint8_t threadConnectMsg = THREAD_CONN;
    if (sys->send(serverSocket, &threadConnectMsg, sizeof(uint8_t), 0) < 0) {
        fprintf(stderr, "Send thread flag failed: %s\n", strerror(errno));
        return;
    }

    // Tell the server our process ID
    pid_t processId = sys->getpid();
    if (sys->send(serverSocket, &processId, sizeof(pid_t), 0) < 0) {
        fprintf(stderr, "Send processId ID failed: %s\n", strerror(errno));
        return;
    }

    // Tell the server our thread ID
    pid_t threadId = sys->gettid();
    if (sys->send(serverSocket, &threadId, sizeof(pid_t), 0) < 0) {
        fprintf(stderr, "Send thread ID failed: %s\n", strerror(errno));
        return;
    }

    registeredAsThread = true;
    printf("Registered thread %d with server.\n", threadId);
}

}
