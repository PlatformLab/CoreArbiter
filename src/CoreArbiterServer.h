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

#ifndef CORE_ARBITER_SERVER_H_
#define CORE_ARBITER_SERVER_H_

#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <atomic>
#include <deque>
#include <fstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "CoreArbiterCommon.h"
#include "Logger.h"
#include "PerfUtils/Cycles.h"
#include "Syscall.h"

#define MAX_EPOLL_EVENTS 1000

using PerfUtils::Cycles;

namespace CoreArbiter {

/**
 * This class implements a service that arbitrates core allocations amongst
 * application. It handles a set of "managed" cores, on which only a single
 * thread can run, and "unmanaged" cores, which obey the kernel's thread
 * scheduling as usual. It is meant to be run as a daemon on a system. A typical
 * use would construct a server object and call startArbitration(), which does
 * not exit. There should be only one instance of the CoreArbiterServer on a
 * machine at any given time.
 *
 * This class is tightly connected to CoreArbiterClient. Users should not
 * attempt to connect to the server directly, but rather go through the client's
 * API.
 */
class CoreArbiterServer {
  public:
    CoreArbiterServer(std::string socketPath, std::string sharedMemPathPrefix,
                      std::vector<int> managedCores = {},
                      bool arbitrateImmediately = true);
    ~CoreArbiterServer();
    void startArbitration();
    void endArbitration();

    // Point at the most recently constructed instance of the
    // CoreArbiterServer.
    static CoreArbiterServer* volatile mostRecentInstance;

  private:
    struct ThreadInfo;
    struct ProcessInfo;
    struct CoreInfo;

    /**
     * Used to keep track of all the information for a core. There is a separate
     * CoreInfo instance for every core that the server has control over (both
     * managed and unmanaged). These structs are constructed when the server
     * starts up and exist for the server's entire lifetime.
     */
    struct CoreInfo {
        // The ID of this core. This ID matches what would be returned by a
        // thread on this core that ran sched_getcpu().
        int id;

        // A pointer to the thread running on this core if the core is managed.
        // NULL otherwise.
        struct ThreadInfo* managedThread;

        // The name of this core's managed cpuset tasks file.
        std::string cpusetFilename;

        // A stream pointing to the tasks file of this core's managed cpuset.
        std::ofstream cpusetFile;

        // The last time (in cycles) that this core had a thread removed from
        // it. If there is no thread running on this core, this value tells us
        // how long the core has been unoccupied.
        uint64_t threadRemovalTime;

        CoreInfo() : managedThread(NULL) {}

        CoreInfo(int id, std::string managedTasksPath)
            : id(id),
              managedThread(NULL),
              cpusetFilename(managedTasksPath),
              threadRemovalTime(0) {
            if (!testingSkipCpusetAllocation) {
                cpusetFile.open(cpusetFilename);
                if (!cpusetFile.is_open()) {
                    LOG(ERROR, "Unable to open %s", cpusetFilename.c_str());
                    exit(-1);
                }
            }
        }
    };

    /**
     * Used by ThreadInfo to keep track of a thread's state.
     */
    enum ThreadState {
        // Running on a managed core
        RUNNING_MANAGED,

        // Voluntarily running on the unmanaged core (this only happens before
        // the first call to blockUntilCoreAvailable())
        RUNNING_UNMANAGED,

        // Running on the unmanaged core because it was forceably preempted from
        // its managed core
        RUNNING_PREEMPTED,

        // Not running, waiting to be put on core
        BLOCKED
    };

    /**
     * Keeps track of all the information for a thread registered with this
     * server. A ThreadInfo instance exists from the time that a new thread
     * first connects with a server until that connection closes.
     */
    struct ThreadInfo {
        // The ID of this thread (self-reported when the thread first
        // establishes a connection). All threads within a process are expected
        // to have unique IDs.
        pid_t id;

        // A pointer to the process that this thread belongs to.
        struct ProcessInfo* process;

        // The file descriptor for the socket used to communicate with this
        // thread.
        int socket;

        // A pointer to the managed core this thread is running on. NULL if this
        // thread is not running on a managed core.
        struct CoreInfo* core;

        // A pointer to the managed core this thread was running before it was
        // preempted. If this thread becomes unpreempted before it blocks, it
        // must return to this core.
        struct CoreInfo* corePreemptedFrom;

        // The current state of this thread. When a thread first registers it
        // is assumed to be RUNNING_UNMANAGED.
        ThreadState state;

        ThreadInfo() {}

        ThreadInfo(pid_t threadId, struct ProcessInfo* process, int socket)
            : id(threadId),
              process(process),
              socket(socket),
              core(NULL),
              corePreemptedFrom(NULL),
              state(RUNNING_UNMANAGED) {}
    };

    /**
     * Keeps track of all the information for a process, including which threads
     * belong to this process. ProcessInfo instances are generated as needed,
     * when a thread registers with a proces that we have not seen before. A
     * process is not deleted from memory until all of its threads' connections
     * have closed.
     */
    struct ProcessInfo {
        // The ID of this process (self-reported when a thread first establishes
        // a connection). All processes on this machine are expected to have
        // unique IDs.
        pid_t id;

        // The file descriptor that is mmapped into memory for communication
        // between the process and server (see the stats struct below).
        int sharedMemFd;

        // A pointer to shared memory that is used to communicate information
        // to this process.
        struct ProcessStats* stats;

        // The set of cores that threads belonging to this process have been
        // timeout-preempted from. We must ensure that no threads from this
        // process are scheduled onto this core until the preempted thread
        // blocks and can be assigned a new core.
        std::unordered_set<CoreInfo*> coresPreemptedFrom;

        // How many cores this process desires at each priority level. Smaller
        // indexes mean higher priority.
        std::vector<uint32_t> desiredCorePriorities;

        // A map of ThreadState to the threads this process owns in that state.
        std::unordered_map<ThreadState, std::unordered_set<struct ThreadInfo*>,
                           std::hash<int>>
            threadStateToSet;

        ProcessInfo() : desiredCorePriorities(NUM_PRIORITIES) {}

        ProcessInfo(pid_t id, int sharedMemFd, struct ProcessStats* stats)
            : id(id),
              sharedMemFd(sharedMemFd),
              stats(stats),
              desiredCorePriorities(NUM_PRIORITIES) {}
    };

    /**
     * Data structure that stores a process and the core it was asked to
     * relinquish. This prevents the server from preempting a thread that has
     * already yielded.
     */
    struct TimerInfo {
        pid_t processId;
        CoreInfo* coreInfo;
    };

    bool handleEvents();
    void acceptConnection(int listenSocket);
    void threadBlocking(int socket);
    void coresRequested(int socket);
    void timeoutThreadPreemption(int timerFd);
    void cleanupConnection(int socket);
    CoreInfo* findGoodCoreForProcess(ProcessInfo* process,
                                     std::deque<struct CoreInfo*>& candidates);
    void wakeupThread(ThreadInfo* thread, CoreInfo* core);
    void distributeCores();
    void requestCoreRelease(struct CoreInfo* core);

    bool readData(int socket, void* buf, size_t numBytes, std::string err);
    bool sendData(int socket, void* buf, size_t numBytes, std::string err);

    void createCpuset(std::string dirName, std::string cores, std::string mems);
    void moveProcsToCpuset(std::string fromPath, std::string toPath);
    void removeUnmanagedThreadsFromCore(struct CoreInfo* core);
    void removeOldCpusets(std::string arbiterCpusetPath);
    bool moveThreadToManagedCore(struct ThreadInfo* thread,
                                 struct CoreInfo* core);
    void removeThreadFromManagedCore(struct ThreadInfo* thread,
                                     bool changeCpuset = true);
    void updateUnmanagedCpuset();
    void changeThreadState(struct ThreadInfo* thread, ThreadState state);

    void installSignalHandler();

    // The path to the socket that the server is listening for new connections
    // on.
    std::string socketPath;

    // The file descriptor for the socket that the server is listening for new
    // connections on.
    int listenSocket;

    // The prefix that will be used to generate shared memory file paths for
    // each process. This can be either a file or directory.
    std::string sharedMemPathPrefix;

    // The path to the shared memory file with global server information (see
    // the GlobalStats struct below).
    std::string globalSharedMemPath;

    // The file descriptor for the shared memory file with global server
    // information (see the GlobalStats struct below).
    int globalSharedMemFd;

    // The path to the advisory lock file, preventing multi
    // coreArbiterServer instances
    std::string advisoryLockPath;

    // The file descriptor for the advisory lock file
    int advisoryLockFd;

    // Pointer to a struct in shared memory that contains global information
    // about the state of all processes connected to this server.
    struct GlobalStats* stats;

    // The file descriptor used to block on client requests.
    int epollFd;

    // A map of core preemption timers to their related information.
    std::unordered_map<int, struct TimerInfo> timerFdToInfo;

    // The amount of time in milliseconds to wait before forceably preempting
    // a thread from its managed core to the unmanaged core.
    uint64_t preemptionTimeout;

    // Maps thread socket file desriptors to their associated threads.
    std::unordered_map<int, struct ThreadInfo*> threadSocketToInfo;

    // Maps process IDs to their associated processes.
    std::unordered_map<pid_t, struct ProcessInfo*> processIdToInfo;

    // Contains the information about cores that are not currently in the
    // unmanaged cpuset. This vector grows with cores from unmanagedCores when
    // the arbiter is loaded and shrinks when there are fewer cores being used.
    std::vector<struct CoreInfo*> managedCores;

    // Contains the information about cores that are currently in the unmanaged
    // cpuset. At startup, this vector contains all cores controlled by the
    // arbiter. It shrinks as cores are requested and grows when cores are
    // unused for an extended period.
    std::deque<struct CoreInfo*> unmanagedCores;

    // The file used to change which cores belong to the unmanaged cpuset.
    std::ofstream unmanagedCpusetCpus;

    // The file used to change which threads are running on the unmanaged
    // cpuset.
    std::ofstream unmanagedCpusetTasks;

    // A comma-delimited string of CPU IDs for cores not under the arbiter's
    // control.
    std::string alwaysUnmanagedString;

    // The last time (in cycles) that the unmanaged cpuset's set of cores was
    // updated.
    uint64_t unmanagedCpusetLastUpdate;

    // The minimum amount of time (in milliseconds) to wait before adding an
    // unoccupied core to the unmanaged cpuset. Also the minimum amount of time
    // to wait before updating the unmanaged cpuset's cores. This timeout is
    // necessary to make sure we don't change the unmanaged cpuset too often, as
    // doing so will cause the kernel to throw errors.
    uint64_t cpusetUpdateTimeout;

    // The set of the threads currently running on cores in managedCores.
    std::vector<struct ThreadInfo*> managedThreads;

    // The smallest index in the vector is the highest priority and the first
    // entry in the deque is the next process that should receive a core at
    // that priority.
    std::vector<std::deque<struct ProcessInfo*>> corePriorityQueues;

    // When this file descriptor is written, the core arbiter will return from
    // startArbitration.
    volatile int terminationFd;

    // The path to the root cpuset directory.
    static std::string cpusetPath;

    // Wrap all system calls for easier testing.
    static Syscall* sys;

    // Used for testing to avoid unnecessary setup and code execution.
    static bool testingSkipCpusetAllocation;
    static bool testingSkipCoreDistribution;
    static bool testingSkipSocketCommunication;
    static bool testingSkipMemoryDeallocation;
    static bool testingDoNotChangeManagedCores;
};

}  // namespace CoreArbiter

int ensureParents(const char* path, mode_t mode = S_IRWXU);

#endif  // CORE_ARBITER_SERVER_H_
