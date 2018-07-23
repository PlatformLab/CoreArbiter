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
#include "FakeCoreSegregator.h"

namespace CoreArbiter {
FakeCoreSegregator::FakeCoreSegregator(Topology topology) {
    this->topology = topology;
    for (int i = 0; i < static_cast<int>(topology.getNumCores()); i++) {
        coreToThread[i] = UNMANAGED;
    }
}
FakeCoreSegregator::~FakeCoreSegregator() {}

bool
FakeCoreSegregator::setThreadForCore(int coreId, int threadId) {
    coreToThread[coreId] = threadId;
    return true;
}
bool
FakeCoreSegregator::removeThreadFromCore(int coreId) {
    coreToThread[coreId] = UNASSIGNED;
    return true;
}
void
FakeCoreSegregator::garbageCollect() {
    for (int i = 0; i < static_cast<int>(topology.getNumCores()); i++) {
        if (coreToThread[i] == UNASSIGNED)
            coreToThread[i] = UNMANAGED;
    }
}
}  // namespace CoreArbiter
