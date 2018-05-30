/* Copyright (c) 2015-2018 Stanford University
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

#include <stdio.h>
#include <atomic>
#include <thread>

#include "CoreArbiterClient.h"
#include "Logger.h"
#include "PerfUtils/Cycles.h"
#include "PerfUtils/Stats.h"
#include "PerfUtils/TimeTrace.h"
#include "PerfUtils/Util.h"

/**
 * This benchmark will rapidly increase and decrease the number of cores
 * requested, to stress the core arbiter's allocation and deallocation
 * mechanism.
 */

// Uncomment the following line to make this benchmark pause for 2 seconds
// between allocations so that we observe the order of allocation and
// de-allocation.
// #define PAUSE_AT_ALLOCATION 1

using CoreArbiter::CoreArbiterClient;
using PerfUtils::Cycles;
using PerfUtils::TimeTrace;

#define NUM_TRIALS 100

std::atomic<bool> end(false);

/**
 * This thread will block and unblock on the Core Arbiter's command.
 */
void
coreExec(CoreArbiterClient* client) {
    while (!end) {
        client->blockUntilCoreAvailable();
        while (!client->mustReleaseCore())
            ;
    }
}

/**
 * This thread will request an increasing number of cores and then a decreasing
 * number of cores.
 */
int
main(int argc, const char** argv) {
    const int MAX_CORES = std::thread::hardware_concurrency() - 1;
    CoreArbiterClient* client = CoreArbiterClient::getInstance();

    // Start up several threads to actually ramp up and down
    for (int i = 0; i < MAX_CORES; i++)
        (new std::thread(coreExec, std::ref(client)))->detach();

    std::vector<uint32_t> coreRequest = {0, 0, 0, 0, 0, 0, 0, 0};

    for (int i = 0; i < NUM_TRIALS; i++) {
        // First go up and then go down.
        int j;
        for (j = 1; j < MAX_CORES; j++) {
            coreRequest[0] = j;
            client->setRequestedCores(coreRequest);
#if PAUSE_AT_ALLOCATION
            sleep(2);
#endif
        }
        for (; j > 0; j--) {
            coreRequest[0] = j;
            client->setRequestedCores(coreRequest);
#if PAUSE_AT_ALLOCATION
            sleep(2);
#endif
        }
    }
    coreRequest[0] = MAX_CORES;
    client->setRequestedCores(coreRequest);
    end.store(true);
}
