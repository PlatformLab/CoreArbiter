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

#define private public

#include "CpusetCoreSegregator.h"

#undef private

#include <sys/types.h>
#include <unistd.h>
#include <thread>
#include "Logger.h"
#include "PerfUtils/Util.h"
#include "gtest/gtest.h"

namespace CoreArbiter {

// Since this tests real operations on real cpusets, this test is necessarily
// architecture-dependent. However, we can try to limit the extent to which we
// depend on this by assuming only a minimum of 4 cores, and skipping the tests
// with a warning if the machine being tested on has fewer than 4 cores.
class CpusetCoreSegregatorTest : public ::testing::Test {
  public:
    CpusetCoreSegregator* cpusetCoreSegregator;

    CpusetCoreSegregatorTest()
        : cpusetCoreSegregator(new CpusetCoreSegregator()) {
        Logger::setLogLevel(ERROR);
        int numCores = static_cast<int>(std::thread::hardware_concurrency());
        if (numCores < 4) {
            fprintf(stderr,
                    "Skipping CpusetCoreSegregatorTest, which requires a "
                    "minimum of %d cores\n",
                    numCores);
            exit(0);
        }
    }

    ~CpusetCoreSegregatorTest() { delete cpusetCoreSegregator; }

    /**
     * Test whether the given thread appears in the task list of the given core.
     */
    bool threadOnCore(int thread, int core) {
        int cpusetFile = cpusetCoreSegregator->coreToCpusetFile[core];
        std::vector<int> tids = PerfUtils::Util::readIntegers(cpusetFile, '\n');
        for (int tid : tids) {
            if (tid == thread) {
                return true;
            }
        }
        return false;
    }
    /**
     * Test whether the given thread appears in the task list of the unmanaged
     * cores.
     */
    bool threadUnmanaged(int thread) {
        int cpusetFile = cpusetCoreSegregator->unmanagedCpusetTasks;
        std::vector<int> tids = PerfUtils::Util::readIntegers(cpusetFile, '\n');
        for (int tid : tids) {
            if (tid == thread) {
                return true;
            }
        }
        return false;
    }

    // Helper function for tests with timing dependencies, so that we wait for a
    // finite amount of time in the case of a bug causing an infinite loop.
    bool limitedTimeWait(std::function<bool()> condition,
                         int numIterations = 1000) {
        for (int i = 0; i < numIterations; i++) {
            if (condition()) {
                return true;
            }
            usleep(1000);
        }
        fprintf(stderr, "Failed to wait for condition to be true.\n");
        return false;
    }
};

TEST_F(CpusetCoreSegregatorTest, setThreadForCore) {
    // Special core states
    EXPECT_EQ(cpusetCoreSegregator->coreToThread[0], CoreSegregator::UNMANAGED);
    cpusetCoreSegregator->setThreadForCore(0, CoreSegregator::UNASSIGNED);
    EXPECT_EQ(cpusetCoreSegregator->coreToThread[0],
              CoreSegregator::UNASSIGNED);
    cpusetCoreSegregator->setThreadForCore(1, CoreSegregator::COERCE_IDLE);
    cpusetCoreSegregator->garbageCollect();
    EXPECT_EQ(cpusetCoreSegregator->coreToThread[0], CoreSegregator::UNMANAGED);
    EXPECT_EQ(cpusetCoreSegregator->coreToThread[1],
              CoreSegregator::COERCE_IDLE);

    // Actual threads
    int pid = static_cast<int>(getpid());
    cpusetCoreSegregator->setThreadForCore(0, pid);
    EXPECT_EQ(cpusetCoreSegregator->coreToThread[0], pid);

    EXPECT_TRUE(threadOnCore(pid, 0));

    // Verify that unmanaged cpuset does not include the allocated core.
    std::string unmanagedCpusPath =
        CpusetCoreSegregator::arbiterCpusetPath + "/Unmanaged/cpuset.cpus";
    std::vector<int> cpus =
        PerfUtils::Util::readRanges(unmanagedCpusPath.c_str());
    for (int cpu : cpus) {
        EXPECT_NE(0, cpu);
    }
}

TEST_F(CpusetCoreSegregatorTest, removeThreadFromCore) {
    int pid = static_cast<int>(getpid());
    cpusetCoreSegregator->setThreadForCore(0, pid);
    EXPECT_EQ(cpusetCoreSegregator->coreToThread[0], pid);
    EXPECT_TRUE(threadOnCore(pid, 0));
    cpusetCoreSegregator->removeThreadFromCore(0);
    EXPECT_EQ(cpusetCoreSegregator->coreToThread[0],
              CoreSegregator::UNASSIGNED);
    EXPECT_TRUE(threadUnmanaged(pid));
    sleep(1);
    EXPECT_TRUE(limitedTimeWait([=]() { return !threadOnCore(pid, 0); }));
    ASSERT_DEATH(cpusetCoreSegregator->removeThreadFromCore(1),
                 "No thread found on core");
}

TEST_F(CpusetCoreSegregatorTest, garbageCollect) {
    // Test for the garbage collection cleaning up extraneous threads, and also
    // converting UNASSIGNED to UNMANAGED.
    int pid = static_cast<int>(getpid());
    int ppid = static_cast<int>(getppid());
    cpusetCoreSegregator->setThreadForCore(0, pid);
    cpusetCoreSegregator->setThreadForCore(0, ppid);
    EXPECT_TRUE(threadOnCore(pid, 0));
    EXPECT_TRUE(threadOnCore(ppid, 0));
    cpusetCoreSegregator->setThreadForCore(1, CoreSegregator::UNASSIGNED);
    EXPECT_TRUE(cpusetCoreSegregator->unmanagedCoresNeedUpdate);

    cpusetCoreSegregator->garbageCollect();

    EXPECT_EQ(cpusetCoreSegregator->coreToThread[0], ppid);
    EXPECT_EQ(cpusetCoreSegregator->coreToThread[1], CoreSegregator::UNMANAGED);
    EXPECT_TRUE(threadUnmanaged(pid));
    sleep(1);
    limitedTimeWait([this, pid]() { return !threadOnCore(pid, 0); });
    EXPECT_FALSE(threadOnCore(pid, 0));
    limitedTimeWait([this, ppid]() { return threadOnCore(ppid, 0); });
    EXPECT_FALSE(cpusetCoreSegregator->unmanagedCoresNeedUpdate);
}

}  // namespace CoreArbiter
