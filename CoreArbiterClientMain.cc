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

#include <thread>
#include <vector>

#include "CoreArbiterClient.h"

int main(int argc, const char** argv) {
    CoreArbiter::CoreArbiterClient& client =
        CoreArbiter::CoreArbiterClient::getInstance("./testsocket");

    int numThreads = 2;
    std::vector<std::thread> threads(numThreads);
    for (int i = 0; i < numThreads; i++) {
        threads[i] = std::thread([&client] {
            sleep(1);
            client.blockUntilCoreAvailable();
            printf("running on core %d\n", sched_getcpu());
        });
    }

    std::vector<core_t> coresRequested(NUM_PRIORITIES);
    coresRequested[0] = 2;
    client.setNumCores(coresRequested);

    for (auto& t : threads) {
      t.join();
    }

    return 0;
}