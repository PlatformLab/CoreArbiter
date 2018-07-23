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
#ifndef FAKE_CORE_SEGREGATOR_H_
#define FAKE_CORE_SEGREGATOR_H_

#include "CoreSegregator.h"

#include <unordered_map>

#include "Topology.h"

namespace CoreArbiter {
/**
 * This class tracks the intended state of cores, but does not invoke kernel
 * mechanisms to move threads around. Its state is public because it is
 * intended for use in unit tests.
 */
class FakeCoreSegregator : public CoreSegregator {
  public:
    FakeCoreSegregator(Topology topology);
    virtual ~FakeCoreSegregator();
    bool setThreadForCore(int coreId, int threadId);
    bool removeThreadFromCore(int coreId);
    void garbageCollect();

    // The mapping of cores to threadIds. Values above 0 are actual thread ids;
    // values below zero are special states a core may be in.
    std::unordered_map<int, int> coreToThread;

    // The topology to assume so that instances of this class and invokers can
    // agree on the set of available cores.
    Topology topology;
};
}  // namespace CoreArbiter

#endif  // FAKE_CORE_SEGREGATOR_H_
