#include "Topology.h"

#include "PerfUtils/Util.h"

namespace CoreArbiter {

using PerfUtils::Util::getHyperTwin;
using PerfUtils::Util::getPhysicalCore;
using PerfUtils::Util::readRanges;

#define MAX_PATH_LEN 1024

const char* Topology::numaNamesPath = "/sys/devices/system/node/possible";

/**
 * Constructor which builds a topology for the machine it is run on.
 *
 * \param allowedCoreIds
 *     Cores not specified here will not be exposed in the resulting topology.
 *     Ignored if empty.
 */
Topology::Topology() {
    std::vector<int> nodeNames = readRanges(numaNamesPath);

    for (int n : nodeNames) {
        NUMANode node;
        node.id = n;

        char path[MAX_PATH_LEN];
        // This literal is hardcoded here to avoid "format not a string literal"
        // warning.
        sprintf(path, "/sys/devices/system/node/node%d/cpulist", n);
        node.cores = readRanges(path);
        for (int c : node.cores) {
            coreToSocket[c] = n;
            coreToHypertwin[c] = getHyperTwin(c);
        }
        nodes.push_back(node);
    }
}

/**
 * Constructor which builds a topology based on the input parameters.
 *
 * \param nodes
 *    The NUMA nodes that the topology will consist of.
 * \param coreToHypertwin
 *    A map from the coreIds of cores to coreIds of their hypertwins.
 */
Topology::Topology(std::vector<NUMANode> nodes,
                   std::unordered_map<int, int> coreToHypertwin) {
    this->nodes = nodes;
    this->coreToHypertwin = coreToHypertwin;
    for (NUMANode node : nodes) {
        for (int c : node.cores) {
            coreToSocket[c] = node.id;
        }
    }
}

/**
 * Compute the total number of schedulable units based on this topology.
 */
uint32_t
Topology::getNumCores() {
    uint32_t numCores = 0;
    for (NUMANode node : nodes) {
        numCores += static_cast<uint32_t>(node.cores.size());
    }
    return numCores;
}

}  // namespace CoreArbiter
