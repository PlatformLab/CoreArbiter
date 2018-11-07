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
#include "CpusetCoreSegregator.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <iterator>
#include <sstream>
#include <thread>

#include "Logger.h"
#include "PerfUtils/Util.h"

namespace CoreArbiter {

#define MAX_PID_LENGTH 100

std::string CpusetCoreSegregator::cpusetPath = "/sys/fs/cgroup/cpuset";
std::string CpusetCoreSegregator::arbiterCpusetPath =
    cpusetPath + "/CoreArbiter";
static Syscall defaultSyscall;
Syscall* CpusetCoreSegregator::sys = &defaultSyscall;

/**
 * Create subdirectories in the /sys/fs/cgroup/cpuset directory for each
 * managed core ID given. Constructing a new CpusetCoreSegregator will delete
 * all cpuset state created by a previous instance.
 */
CpusetCoreSegregator::CpusetCoreSegregator() {
    // Remove any old cpusets from a previous server
    removeOldCpusets();

    // Ask the system for the number of cores and assume that they are numbered
    // sequentially from 0 to n - 1.
    unsigned int numCores = std::thread::hardware_concurrency();
    std::vector<int> managedCoreIds;
    for (int id = 0; id < static_cast<int>(numCores); id++) {
        managedCoreIds.push_back(id);
        coreToThread[id] = UNMANAGED;
    }

    // Create a new cpuset directory for core arbitration. Since this is
    // going to be a parent of all the arbiter's individual core cpusets, it
    // needs to include every core.
    std::string allCores = "0-" + std::to_string(numCores - 1);
    createCpuset(arbiterCpusetPath, allCores, "0");

    // Set up managed cores
    for (int core : managedCoreIds) {
        std::string managedCpusetPath =
            arbiterCpusetPath + "/Managed" + std::to_string(core);
        createCpuset(managedCpusetPath, std::to_string(core), "0");
    }

    // Set up the unmanaged cpuset. This starts with all cores and is
    // scaled down as processes ask for managed cores.
    std::string unmanagedCpusetPath = arbiterCpusetPath + "/Unmanaged";
    createCpuset(unmanagedCpusetPath, allCores, "0");

    // Move all of the currently running processes to the unmanaged cpuset
    std::string allProcsPath = cpusetPath + "/cgroup.procs";
    std::string unmanagedProcsPath = unmanagedCpusetPath + "/cgroup.procs";
    moveProcsToCpuset(allProcsPath, unmanagedProcsPath);

    // Set up the file we will use to control how many cores are in the
    // unmanaged cpuset.
    std::string unmanagedCpusPath = unmanagedCpusetPath + "/cpuset.cpus";
    unmanagedCpusetCpus = open(unmanagedCpusPath.c_str(), O_RDWR);
    if (unmanagedCpusetCpus < 0) {
        LOG(ERROR, "Unable to open %s; errno %d: %s", unmanagedCpusPath.c_str(),
            errno, strerror(errno));
        exit(-1);
    }

    // Set up the file we will use to control which threads are in the
    // unmanaged cpuset.
    unmanagedTasksPath = unmanagedCpusetPath + "/tasks";
    unmanagedCpusetTasks = open(unmanagedTasksPath.c_str(), O_RDWR);
    if (unmanagedCpusetTasks < 0) {
        LOG(ERROR, "Unable to open %s; errno %d: %s",
            unmanagedTasksPath.c_str(), errno, strerror(errno));
        exit(-1);
    }

    // Create separate cpuset files for every core's tasks
    for (int coreId : managedCoreIds) {
        coreToCpusetPath[coreId] =
            arbiterCpusetPath + "/Managed" + std::to_string(coreId) + "/tasks";
        coreToCpusetFile[coreId] =
            open(coreToCpusetPath[coreId].c_str(), O_RDWR);
        if (coreToCpusetFile[coreId] < 0) {
            LOG(ERROR, "Unable to open %s; errno %d: %s",
                coreToCpusetPath[coreId].c_str(), errno, strerror(errno));
            exit(-1);
        }
    }
}

// Destructor
CpusetCoreSegregator::~CpusetCoreSegregator() {
    for (auto& it : coreToCpusetFile) {
        close(it.second);
    }
    removeOldCpusets();
}

bool
CpusetCoreSegregator::setThreadForCore(int coreId, int threadId) {
    int originalCoreState = coreToThread[coreId];
    coreToThread[coreId] = threadId;
    if (originalCoreState == UNMANAGED && threadId > 0) {
        // Scale back the unmanaged cores in this case.
        setUnmanagedCores();
    }

    // If there is a special state, it will get picked up by garbage
    // collection.
    if (threadId > 0) {
        int cpusetFile = coreToCpusetFile[coreId];
        char threadIdStr[MAX_PID_LENGTH];
        snprintf(threadIdStr, MAX_PID_LENGTH, "%d\n", threadId);

        lseek(cpusetFile, 0, SEEK_SET);

        ssize_t retVal = write(cpusetFile, threadIdStr, strlen(threadIdStr));
        if (retVal < 0) {
            // This error is likely because the thread has exited. We need to
            // close and reopen the file to prevent future errors.
            LOG(ERROR,
                "Unable to write %d to cpuset file for core %d; errno %d: %s",
                threadId, coreId, errno, strerror(errno));
            return false;
        }
    } else if (threadId == UNASSIGNED) {
        // It is possible for a core to be reclaimed during GC
        unmanagedCoresNeedUpdate = true;
    }
    return true;
}

/**
 * If there are managed cores without a thread, these join the unmanaged
 * cpuset.
 */
void
CpusetCoreSegregator::setUnmanagedCores() {
    if (!unmanagedCoresNeedUpdate) {
        return;
    }
    // Determine which cores should be unmanaged by iterating over all the
    // cores in the system and checking for their status in coreToThread.
    int numCores = static_cast<int>(std::thread::hardware_concurrency());
    std::vector<int> unmanagedCoreIds;
    for (int id = 0; id < numCores; id++) {
        // Not present implies it should be unmanaged
        if (coreToThread.find(id) == coreToThread.end()) {
            unmanagedCoreIds.push_back(id);
            continue;
        }

        int& coreState = coreToThread[id];
        if (coreState < 0 && coreState != COERCE_IDLE) {
            // Record the fact that this core is physically unmanaged.
            coreState = UNMANAGED;
            unmanagedCoreIds.push_back(id);
        }
    }

    std::stringstream unmanagedCores;
    std::copy(unmanagedCoreIds.begin(), unmanagedCoreIds.end(),
              std::ostream_iterator<int>(unmanagedCores, ","));
    std::string unmanagedCoresString = unmanagedCores.str() + "\n";
    LOG(DEBUG, "Changing unmanaged cpuset to %s", unmanagedCoresString.c_str());

    ssize_t retVal = write(unmanagedCpusetCpus, unmanagedCoresString.c_str(),
                           unmanagedCoresString.size());

    if (retVal < 0) {
        LOG(ERROR, "Failed to write to unmanagedCpusetPus; errno %d: %s", errno,
            strerror(errno));
        abort();
    }
    unmanagedCoresNeedUpdate = false;
}

/**
 * Remove non-managed threads from managed cores.
 */
void
CpusetCoreSegregator::removeExtraneousThreads() {
    int numCores = static_cast<int>(std::thread::hardware_concurrency());
    for (int coreId = 0; coreId < numCores; coreId++) {
        // Not present implies it should be unmanaged
        if (coreToThread.find(coreId) == coreToThread.end()) {
            continue;
        }

        int managedThreadId = coreToThread[coreId];
        // Either a valid thread or forcibly idled core.
        if (managedThreadId > 0 || managedThreadId == COERCE_IDLE) {
            int fromFile = coreToCpusetFile[coreId];
            std::vector<int> tids =
                PerfUtils::Util::readIntegers(fromFile, '\n');

            for (int threadId : tids) {
                // The managed thread should stay put.
                if (threadId == coreToThread[coreId])
                    continue;

                // Every other thread should be moved to the
                // unmanagedCpusetTasks.
                char threadIdStr[MAX_PID_LENGTH];
                snprintf(threadIdStr, MAX_PID_LENGTH, "%d\n", threadId);
                ssize_t retVal = write(unmanagedCpusetTasks, threadIdStr,
                                       strlen(threadIdStr));
                if (retVal < 0) {
                    // This error is likely because the thread has exited.
                    // Sleeping helps keep the kernel from giving more errors
                    // the next time we try to move a legitimate thread.
                    LOG(ERROR,
                        "Unable to write %d from core %d to unmanaged cpuset file; errno "
                        "%d: %s",
                        threadId, coreId, errno, strerror(errno));
                }
            }
        }
    }
}

/**
 * Removes all cpusets at the given directory, including the directory itself.
 * This should be called at both server startup and shutdown, to ensure a clean
 * cpuset setup for the server and as a courtesy to the system when the server
 * exits.
 *
 * \param arbiterCpusetPath
 *     The path to the CoreArbiterServer's cpuset subtree
 */
void
CpusetCoreSegregator::removeOldCpusets() {
    std::string procsDestFilename = cpusetPath + "/cgroup.procs";
    DIR* dir = sys->opendir(arbiterCpusetPath.c_str());
    if (!dir) {
        // This is likely just because we don't have old cpusets to remove
        LOG(WARNING, "Error on opendir %s: %s", arbiterCpusetPath.c_str(),
            strerror(errno));
        return;
    }

    // Remove all processes from a cpuset
    for (struct dirent* entry = sys->readdir(dir); entry != NULL;
         entry = sys->readdir(dir)) {
        if (entry->d_type == DT_DIR && entry->d_name[0] != '.') {
            std::string dirName =
                arbiterCpusetPath + "/" + std::string(entry->d_name);
            std::string procsFilename = dirName + "/cgroup.procs";
            moveProcsToCpuset(procsFilename, procsDestFilename);
        }
    }

    // We need to sleep here to give the kernel time to actually move processes
    // into different cpusets. (Retrying doesn't work.)
    usleep(750);
    rewinddir(dir);

    // Delete all CoreArbiter cpuset subdirectories
    for (struct dirent* entry = sys->readdir(dir); entry != NULL;
         entry = sys->readdir(dir)) {
        if (entry->d_type == DT_DIR && entry->d_name[0] != '.') {
            std::string dirName =
                arbiterCpusetPath + "/" + std::string(entry->d_name);

            LOG(DEBUG, "removing %s", dirName.c_str());
            if (sys->rmdir(dirName.c_str()) < 0) {
                LOG(ERROR, "Error on rmdir %s: %s", dirName.c_str(),
                    strerror(errno));
                exit(-1);
            }
        }
    }

    // Remove the whole CoreArbiter cpuset directory
    if (sys->rmdir(arbiterCpusetPath.c_str()) < 0) {
        LOG(ERROR, "Error on rmdir %s: %s", arbiterCpusetPath.c_str(),
            strerror(errno));
        exit(-1);
    }

    if (sys->closedir(dir) < 0) {
        LOG(ERROR, "Error on closedir %s: %s", arbiterCpusetPath.c_str(),
            strerror(errno));
        exit(-1);
    }
}

/**
 * Creates a new cpuset at dirName (this should be within the cpuset filesystem)
 * and assigns it the given cores and memories. Exits on error.
 *
 * \param dirName
 *     The path at which to create the cpuset. This should be within the cpuset
 *     filesystem.
 * \param cores
 *     A comma- and/or dash-delimited string representing the cores that should
 *     belong to this cpuset.
 * \param mems
 *     A comma- and/or dash-delimited string representing the memories that
 *     should belong to this cpuset.
 */
void
CpusetCoreSegregator::createCpuset(std::string dirName, std::string cores,
                                   std::string mems) {
    if (sys->mkdir(dirName.c_str(), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP |
                                        S_IXGRP | S_IROTH | S_IXOTH) < 0) {
        LOG(ERROR, "Error creating cpuset directory at %s: %s", dirName.c_str(),
            strerror(errno));
        exit(-1);
    }

    std::string memsPath = dirName + "/cpuset.mems";
    int memsFile = open(memsPath.c_str(), O_WRONLY);
    if (memsFile < 0) {
        LOG(ERROR, "Unable to open %s; errno %d: %s", memsPath.c_str(), errno,
            strerror(errno));
        exit(-1);
    }
    ssize_t bytesWritten = write(memsFile, mems.c_str(), mems.size());
    if (bytesWritten < 0) {
        LOG(ERROR, "Unable to write to %s; errno %d: %s", memsPath.c_str(),
            errno, strerror(errno));
        exit(-1);
    }
    close(memsFile);

    std::string cpusPath = dirName + "/cpuset.cpus";
    int cpusFile = open(cpusPath.c_str(), O_WRONLY);
    if (cpusFile < 0) {
        LOG(ERROR, "Unable to open %s; errno %d: %s", cpusPath.c_str(), errno,
            strerror(errno));
        exit(-1);
    }
    bytesWritten = write(cpusFile, cores.c_str(), cores.size());
    if (bytesWritten < 0) {
        LOG(ERROR, "Unable to write to %s; errno %d: %s", cpusPath.c_str(),
            errno, strerror(errno));
        exit(-1);
    }
    close(cpusFile);
}

/**
 * Moves all processes in the cpuset at fromPath to the cpuset at toPath. This
 * is useful at startup to move all processes into the unmanaged cpuset.
 *
 * \param fromPath
 *     The path to the cpuset.cpus file to move processes from
 * \param toPath
 *     The path to the cpuset.cpus file to move all processes to
 */
void
CpusetCoreSegregator::moveProcsToCpuset(std::string fromPath,
                                        std::string toPath) {
    LOG(DEBUG, "Moving procs in %s to %s", fromPath.c_str(), toPath.c_str());

    int fromFile = open(fromPath.c_str(), O_RDONLY);
    if (fromFile < 0) {
        LOG(ERROR, "Unable to open %s; errno %d: %s", fromPath.c_str(), errno,
            strerror(errno));
        exit(-1);
    }

    int toFile = open(toPath.c_str(), O_WRONLY);
    if (toFile < 0) {
        LOG(ERROR, "Unable to open %s; errno %d: %s", toPath.c_str(), errno,
            strerror(errno));
        exit(-1);
    }

    std::vector<int> fromPids = PerfUtils::Util::readIntegers(fromFile, '\n');

    for (pid_t processId : fromPids) {
        char processIdStr[MAX_PID_LENGTH];
        snprintf(processIdStr, MAX_PID_LENGTH, "%d\n", processId);
        ssize_t bytesWritten =
            write(toFile, processIdStr, strlen(processIdStr));
        if (bytesWritten < 0) {
            // Writing fails if we try to move a kernel process. This is normal
            // behavior, and so we can ignore it.
            LOG(DEBUG, "Unable to write %d to %s; errno %d: %s", processId,
                toPath.c_str(), errno, strerror(errno));
        }
    }

    close(fromFile);
    close(toFile);
}

/**
 * See documentation for CoreSegregator::removeThreadFromCore.
 */
bool
CpusetCoreSegregator::removeThreadFromCore(int coreId) {
    // Figure out which thread it is, and clean up the core.
    int threadId = coreToThread[coreId];

    // Violate pre-condition.
    if (threadId <= 0) {
        LOG(ERROR, "No thread found on core %d", coreId);
        exit(-1);
    }

    char threadIdStr[MAX_PID_LENGTH];
    snprintf(threadIdStr, MAX_PID_LENGTH, "%d\n", threadId);
    ssize_t bytesWritten =
        write(unmanagedCpusetTasks, threadIdStr, strlen(threadIdStr));
    if (bytesWritten < 0) {
        // This error is likely because the thread has exited.
        // Sleeping helps keep the kernel from giving more errors
        // the next time we try to move a legitimate thread.
        LOG(ERROR, "Unable to write %d to unmanaged cpuset file; errno %d: %s",
            threadId, errno, strerror(errno));
        return false;
    }

    coreToThread[coreId] = UNASSIGNED;
    return true;
}

/**
 * Expand the unmanaged cores if necessary; remove non-managed threads off of
 * managed cores.
 */
void
CpusetCoreSegregator::garbageCollect() {
    setUnmanagedCores();
    removeExtraneousThreads();
}
}  // namespace CoreArbiter
