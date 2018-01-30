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

#ifndef ARBITER_CLIENT_SHIM_H
#define ARBITER_CLIENT_SHIM_H

#include <stdint.h>
#include <vector>

#include "CoreArbiterClient.h"
#include "Semaphore.h"

namespace Arachne {

/**
 * This class functions as a shim, or alternative, for the CoreArbiter
 * client so that Arachne can run without the Core Arbiter when the
 * arbiter is deactivated.
 */
class ArbiterClientShim : public CoreArbiter::CoreArbiterClient {
  public:
    int blockUntilCoreAvailable();
    bool mustReleaseCore();
    void setRequestedCores(std::vector<uint32_t> numCores);
    void unregisterThread();
    void reset() {
        currentRequestedCores = 0;
        currentCores = 0;
        waitingForAvailableCore.reset();
    }

    /**
     * Allow access to singleton.  Enforce single instance.
     **/
    static ArbiterClientShim* getInstance() {
        static ArbiterClientShim instance;
        return &instance;
    }

  private:
    /**
     * Private constructor for ArbiterClientShim.
     */
    ArbiterClientShim()
        : CoreArbiter::CoreArbiterClient(""),
          waitingForAvailableCore(),
          currentRequestedCores(),
          currentCores(),
          shimLock() {}

    /**
     * Threads block on this semaphor while waiting for a core
     * to become available.
     */
    ::Semaphore waitingForAvailableCore;

    /**
     * The current number of cores this application prefers to have.
     */
    std::atomic<uint64_t> currentRequestedCores;

    /**
     * The current cores held by the application.
     */
    std::atomic<uint64_t> currentCores;

    /**
     * Synchronize between different threads trying to compare
     * currentRequestedCores and currentCores, or writing currentCores.
     */
    std::mutex shimLock;
    /*
     * NB: Since shimLock is taken inside the Arachne dispatch() method
     * which may be polling on an unocupied context, it is not safe to for the
     * lock to enter dispatch() again. This is because a wakeup flag set up by
     * a createThread() may get wiped out when the nested dispatch call
     * returns.
     */
};

}  // namespace Arachne
#endif  // ARBITER_CLIENT_SHIM_H
