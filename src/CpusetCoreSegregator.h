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
#ifndef CPUSET_CORE_SEGREGATOR_H_
#define CPUSET_CORE_SEGREGATOR_H_

#include "CoreSegregator.h"
#include "Syscall.h"

#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>

namespace CoreArbiter {

/**
 * Objects of this class use Linux cpusets to segregate cores into different
 * states. See CoreSegregator documentation for details.
 */
class CpusetCoreSegregator : public CoreSegregator {
  public:
    CpusetCoreSegregator();
    ~CpusetCoreSegregator();
    bool setThreadForCore(int coreId, int threadId);
    bool removeThreadFromCore(int coreId);
    void garbageCollect();

  private:
    void removeOldCpusets();
    void removeExtraneousThreads();
    void createCpuset(std::string dirName, std::string cores, std::string mems);
    void moveProcsToCpuset(std::string fromPath, std::string toPath);
    void setUnmanagedCores();

    // The path to the root cpuset directory.
    static std::string cpusetPath;

    // The path to the CpusetCoreSegregator's cpuset directory.
    static std::string arbiterCpusetPath;

    // The path to the file where unmanaged tasks are written.
    std::string unmanagedTasksPath;

    // The files used to manage which thread lives on each core.
    std::unordered_map<int, std::fstream> coreToCpusetFile;

    // The paths to the files in coreToCpusetFile. Used for reopening when a
    // cpuset write fails, which is not uncommon.
    std::unordered_map<int, std::string> coreToCpusetPath;

    // The mapping of cores to threadIds. Values above 0 are actual thread ids;
    // values below zero are special states a core may be in.
    std::unordered_map<int, int> coreToThread;

    // The file used to change which cores belong to the unmanaged cpuset.
    std::ofstream unmanagedCpusetCpus;

    // The file used to change which threads are running on the unmanaged
    // cpuset.
    std::ofstream unmanagedCpusetTasks;

    // True means that the next iteration of garbageCollect should write to the
    // unmanaged cpuset.
    bool unmanagedCoresNeedUpdate;

    // Used for all syscalls for easier unit testing.
    static Syscall* sys;
};
}  // namespace CoreArbiter
#endif  // CPUSET_CORE_SEGREGATOR_H_
