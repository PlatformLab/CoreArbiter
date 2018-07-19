/* Copyright (c) 2018 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any purpose
 * with or without fee is hereby granted, provided that the above copyright
 * notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
 * CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef CORE_ARBITER_TOPOLOGY_H
#define CORE_ARBITER_TOPOLOGY_H

#include <unordered_map>
#include <vector>

namespace CoreArbiter {

/**
 * This class encapsulates the mechanisms for querying the operating system
 * about core topology. We define a core to be a schedulable worker for
 * execution. Instances of this class contain information about which cores
 * belong to a NUMA node, as well as which cores are hypertwins.
 */
struct Topology {
    /**
     * Represents the set of cores which share the same low-latency access to a
     * particular region of memory.
     */
    struct NUMANode {
        // The kernel's ID for a given NUMA node.
        int id;

        // The cores belonging to this NUMA node.
        std::vector<int> cores;
    };

    Topology();
    Topology(std::vector<NUMANode> nodes,
             std::unordered_map<int, int> coreToHypertwin);
    int getNumCores();

    /**
     * Path for getting names of NUMA nodes.
     */
    static const char* numaNamesPath;

    /**
     * Cores within each of these are expected to have the same latency to the
     * same memory.  In UMA machines, this vector should have only one entry.
     */
    std::vector<NUMANode> nodes;

    /**
     * Enable fast lookup of the socket a particular core belongs to.
     */
    std::unordered_map<int, int> coreToSocket;

    /**
     * Enable fast lookup of the hypertwin of a particular core. If
     * hyperthreading is disabled, all cores are mapped to -1. Note that the
     * hypertwin of a core may not be available for scheduling due to
     * constraints in allowedCoreIds.
     */
    std::unordered_map<int, int> coreToHypertwin;
};
}  // namespace CoreArbiter

#endif
