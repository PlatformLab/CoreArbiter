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
#include <sys/types.h>
#include <atomic>
#include <thread>

#include "Colors.h"
#include "CoreArbiterClient.h"
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
std::atomic<uint32_t> numActiveCores;

/**
 * This thread will block and unblock on the Core Arbiter's command.
 */
void
coreExec(CoreArbiterClient* client) {
    while (!end) {
        client->blockUntilCoreAvailable();
        numActiveCores++;
        fprintf(stderr, RED("Bumped active cores with tid %d\n"),
                (pid_t)syscall(SYS_gettid));
        while (!client->mustReleaseCore())
            ;
        fprintf(stderr, BLUE("Core release requested\n"));
        numActiveCores--;
    }
}

// Helper function for tests with timing dependencies, so that we wait for a
// finite amount of time in the case of a bug causing an infinite loop.
static void
limitedTimeWait(std::function<bool()> condition, int numIterations = 1000) {
    for (int i = 0; i < numIterations; i++) {
        if (condition()) {
            return;
        }
        usleep(1000);
    }
    fprintf(stderr, "Failed to wait for condition to be true.\n");
}

/**
 * This thread will request a large number of cores, and then gradually request
 * a smaller number of cores, verifying that we eventually get
 * mustReleaseCore() called on us.
 */
int
main(int argc, const char** argv) {
    const uint32_t MAX_CORES = std::thread::hardware_concurrency() - 1;
    CoreArbiterClient* client = CoreArbiterClient::getInstance();

    // Start up several threads to actually ramp up and down
    for (uint32_t i = 0; i < MAX_CORES; i++)
        (new std::thread(coreExec, std::ref(client)))->detach();

    std::vector<uint32_t> coreRequest = {MAX_CORES, 0, 0, 0, 0, 0, 0, 0};
    client->setRequestedCores(coreRequest);
    // Wait until we actually have that many cores
    while (numActiveCores.load() != coreRequest[0])
        ;

    // Then, verify that we can step down, with a limited time wait.
    coreRequest[0] = 0;
    client->setRequestedCores(coreRequest);
    limitedTimeWait([]() -> bool { return numActiveCores == 0; });

    // Go back up and exit.
    coreRequest[0] = MAX_CORES;
    client->setRequestedCores(coreRequest);
    end.store(true);
}
