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
#include "ArbiterClientShim.h"
#include <sched.h>
#include <atomic>

namespace Arachne {

/**
 * Implements functionality of CoreArbiterClient::blockUntilCoreAvailable.
 **/
int
ArbiterClientShim::blockUntilCoreAvailable() {
    static std::atomic<int> nextCoreId(0);
    static thread_local int coreId = nextCoreId.fetch_add(1);
    waitingForAvailableCore.wait();
    return coreId;
}

/**
 * Implements functionality of CoreArbiterClient::mustReleaseCore.
 **/
bool
ArbiterClientShim::mustReleaseCore() {
    // Avoid acquiring lock if possible.
    if (currentRequestedCores >= currentCores)
        return false;

    std::lock_guard<std::mutex> guard(shimLock);
    if (currentRequestedCores < currentCores) {
        currentCores--;
        return true;
    }
    return false;
}

/**
 * Implements functionality of CoreArbiterClient::setRequestedCores.
 *
 * \param numCores
 *     Same as in CoreArbiterClient::setRequestedCores.
 */
void
ArbiterClientShim::setRequestedCores(std::vector<uint32_t> numCores) {
    uint32_t sum = 0;
    for (uint32_t i : numCores)
        sum += i;
    currentRequestedCores = sum;

    std::lock_guard<std::mutex> guard(shimLock);
    if (currentRequestedCores > currentCores) {
        uint64_t diff = currentRequestedCores - currentCores;
        for (uint64_t i = 0; i < diff; i++)
            waitingForAvailableCore.notify();
        currentCores.store(currentRequestedCores);
    }
}

/**
 * Implements functionality of CoreArbiterClient::unregisterThread.
 **/
void
ArbiterClientShim::unregisterThread() {
    // Because there is no server, this function is a no-op.
}
}  // namespace Arachne
