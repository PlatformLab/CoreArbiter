#include "CpusetCoreSegregator.h"

#include <dirent.h>
#include <stdio.h>
#include <iterator>
#include <sstream>
#include <thread>

#include "Logger.h"

namespace CoreArbiter {

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
    unmanagedCpusetCpus.open(unmanagedCpusPath);
    if (!unmanagedCpusetCpus.is_open()) {
        LOG(ERROR, "Unable to open %s", unmanagedCpusPath.c_str());
        exit(-1);
    }

    // Set up the file we will use to control which threads are in the
    // unmanaged cpuset.
    std::string unmanagedTasksPath = unmanagedCpusetPath + "/tasks";
    unmanagedCpusetTasks.open(unmanagedTasksPath);
    if (!unmanagedCpusetTasks.is_open()) {
        LOG(ERROR, "Unable to open %s", unmanagedTasksPath.c_str());
        exit(-1);
    }

    // Create separate cpuset files for every core's tasks
    for (int coreId : managedCoreIds) {
        std::string managedTasksPath =
            arbiterCpusetPath + "/Managed" + std::to_string(coreId) + "/tasks";
        coreToCpusetFile[coreId].open(managedTasksPath);
        if (!coreToCpusetFile[coreId].is_open()) {
            LOG(ERROR, "Unable to open %s", managedTasksPath.c_str());
            exit(-1);
        }
    }
}

// Destructor
CpusetCoreSegregator::~CpusetCoreSegregator() {
    for (auto& it : coreToCpusetFile) {
        it.second.close();
    }
    removeOldCpusets();
}

bool
CpusetCoreSegregator::setThreadForCore(int coreId, int threadId) {
    coreToThread[coreId] = threadId;
    // If there is a special state, it will get picked up by garbage
    // collection.
    if (threadId > 0) {
        std::fstream& cpusetFile = coreToCpusetFile[coreId];
        cpusetFile << threadId;
        cpusetFile.flush();
        if (cpusetFile.bad()) {
            // This error is likely because the thread has exited. We need to
            // close and reopen the file to prevent future errors.
            LOG(ERROR, "Unable to write %d to cpuset file for core %d",
                threadId, coreId);
            cpusetFile.clear();
            cpusetFile.seekg(0);
            return false;
        }
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
              std::ostream_iterator<int>(unmanagedCores, " "));
    std::string unmanagedCoresString = unmanagedCores.str();
    LOG(DEBUG, "Changing unmanaged cpuset to %s", unmanagedCoresString.c_str());

    unmanagedCpusetCpus << unmanagedCoresString << std::endl;

    if (unmanagedCpusetCpus.bad()) {
        LOG(ERROR, "Failed to write to unmanagedCpusetPus");
        abort();
    }
    unmanagedCoresNeedUpdate = false;
}

//// See documentation for CoreSegregator::moveThreadToManagedCore.
// bool
// CpusetCoreSegregator::moveThreadToManagedCore(int threadId, int coreId) {
//
//    return true;
//}

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

        int threadId = coreToThread[coreId];
        if (threadId > 0 || threadId == COERCE_IDLE) {
            std::fstream& fromFile = coreToCpusetFile[coreId];
            fromFile.clear();
            fromFile.seekg(0);

            int threadId;
            while (fromFile >> threadId) {
                // The managed thread should stay put.
                if (threadId == coreToThread[coreId])
                    continue;

                // Every other thread should be moved to the
                // unmanagedCpusetTasks.
                unmanagedCpusetTasks << threadId;
                unmanagedCpusetTasks.flush();
                if (unmanagedCpusetTasks.bad()) {
                    // This error is likely because the thread has exited.
                    // Sleeping helps keep the kernel from giving more errors
                    // the next time we try to move a legitimate thread.
                    LOG(ERROR, "Unable to write %d to unmanaged cpuset file",
                        threadId);
                    usleep(750);
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
    std::ofstream memsFile(memsPath);
    if (!memsFile.is_open()) {
        LOG(ERROR, "Unable to open %s", memsPath.c_str());
        exit(-1);
    }
    memsFile << mems;
    memsFile.close();

    std::string cpusPath = dirName + "/cpuset.cpus";
    std::ofstream cpusFile(cpusPath);
    if (!cpusFile.is_open()) {
        LOG(ERROR, "Unable to open %s", cpusPath.c_str());
        exit(-1);
    }
    cpusFile << cores;
    cpusFile.close();
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

    std::ifstream fromFile(fromPath);
    if (!fromFile.is_open()) {
        LOG(ERROR, "Unable to open %s", fromPath.c_str());
        exit(-1);
    }

    std::ofstream toFile(toPath);
    if (!toFile.is_open()) {
        LOG(ERROR, "Unable to open %s", toPath.c_str());
        exit(-1);
    }

    pid_t processId;
    while (fromFile >> processId) {
        toFile << processId;
        toFile << std::endl;
        if (toFile.bad()) {
            // The ofstream errors out if we try to move a kernel process. This
            // is normal behavior, but it means we need to reopen the file.
            toFile.close();
            toFile.open(toPath, std::fstream::app);
            if (!toFile.is_open()) {
                LOG(ERROR, "Unable top open %s", toPath.c_str());
                exit(-1);
            }
        }
    }

    fromFile.close();
    toFile.close();
}

/**
 * Move the managed thread on the given core off of that core.
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
    unmanagedCpusetTasks << threadId;
    unmanagedCpusetTasks.flush();
    if (unmanagedCpusetTasks.bad()) {
        // This error is likely because the thread has exited. Sleeping
        // helps keep the kernel from giving more errors the next time we
        // try to move a legitimate thread.
        LOG(ERROR, "Unable to write %d to unmanaged cpuset file", threadId);
        usleep(750);
        return false;
    }
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
