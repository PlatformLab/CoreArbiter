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

    // The files used to manage which thread lives on each core.
    std::unordered_map<int, std::fstream> coreToCpusetFile;

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
    // TODO: Actually use this and write the code to refresh unmanaged and
    // garbage collect, invoke code in the Server and then fix unit tests.
    bool unmanagedCoresNeedUpdate;

    // Used for all syscalls for easier unit testing.
    static Syscall* sys;
};
}  // namespace CoreArbiter
#endif  // CPUSET_CORE_SEGREGATOR_H_