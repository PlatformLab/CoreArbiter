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

#ifndef CORE_ARBITER_COMMON_H
#define CORE_ARBITER_COMMON_H

#include <stdint.h>
#include <atomic>
#include <cstddef>

#define NUM_PRIORITIES 8
#define RELEASE_TIMEOUT_MS 10
#define CPUSET_UPDATE_TIMEOUT_MS 10

#define THREAD_BLOCK 1
#define CORE_REQUEST 2

namespace CoreArbiter{

/**
 * Statistics kept per process. The server creates a file with this information
 * which is mmapped into memory by both the server and client. Only the server
 * can write to the shared memory.
 */
struct ProcessStats {
    // A monotonically increasing count of the number of cores the server has
    // requested that a process release in the client object's lifetime.
    std::atomic<uint64_t> coreReleaseRequestCount;

    // A monotonically increasing count of the number of times the server has
    // forceably moved a thread belonging to this process to the unmanaged core
    // because it did not release a core when requested to.
    std::atomic<uint64_t> preemptedCount;

    // A monotonically increasing count of the number of times the server has
    // moved a forceably preempted thread back to an exclusive core.
    // preemptedCount - unpreemptedCount tells you the number of threads that a
    // process currently has running on the unmanaged core that were moved from
    // exclusive cores.
    std::atomic<uint64_t> unpreemptedCount;

    // The number of threads that a processes currently has blocked waiting for
    // the server to assign them a core.
    std::atomic<uint32_t> numBlockedThreads;

    // The number of cores that this process currently has threads running
    // exclusively on.
    std::atomic<uint32_t> numOwnedCores;

    ProcessStats()
        : coreReleaseRequestCount(0)
        , preemptedCount(0)
        , unpreemptedCount(0)
        , numBlockedThreads(0)
        , numOwnedCores(0)
    {}
};

/**
 * Statistics kept accross all processes. The server creates a file with this
 * information which is mmapped into memory by both the server and client. Only
 * the server can write to the shared memory.
 */
struct GlobalStats {
    // The number of cores that a CoreArbiterServer controls that do not
    // currently have a thread running on them.
    std::atomic<uint32_t> numUnoccupiedCores;

    // The total number of processes currently connected to a CoreArbiterServer
    std::atomic<uint32_t> numProcesses;

    GlobalStats()
        : numUnoccupiedCores(0)
        , numProcesses(0)
    {}
};

} // namespace CoreArbiter

#endif // CORE_ARBITER_COMMON_H
