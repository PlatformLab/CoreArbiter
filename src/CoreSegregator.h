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
#ifndef CORE_SEGREGATOR_H_
#define CORE_SEGREGATOR_H_

#include <vector>

namespace CoreArbiter {
/**
 * An interface implemented by different mechanisms for moving kernel threads
 * between cores. Each core can be in one of four states.
 *
 * 1. Managed and has a thread assigned to it.
 * 2. Managed and intentionally idled.
 * 3. Managed and doesn't have a thread assigned to it.
 *    These threads are destined to eventually move into state 4 unless another
 *    thread is assigned to them.
 * 4. Unmanaged
 */
class CoreSegregator {
  public:
    /**
     * Place the thread with the given kernel thread identifier on the core
     * with the given kernel identifier. Positive values of threadId represent
     * actual threads, while negative values represent special states that a
     * core can be in.
     *
     * \param coreId
     *     The core to move to the given thread onto.
     * \param threadId
     *     The thread to live on the given core, or the state to put the core
     *     into.
     * \return
     *     True means the operation completed successfully.
     */
    virtual bool setThreadForCore(int coreId, int threadId) = 0;

    /**
     * Make the thread currently officially residing on the given core
     * unmanaged, freeing the core for use by other managed threads.
     *
     * NB: This method only removes the most recent thread passed to
     * setThreadForCore; if there were other threads resident on the given
     * core for other reasons, they should be cleaned up in garbageCollect().
     * NB: This method has different semantics from calling
     * setThreadForCore(coreId, UNASSIGNED); it ensures that the active thread
     * on the core is removed upon returning, rather than deferring this
     * operation until garbage collection. Thus, this method should only be
     * used to remove an uncooperative thread from a core.
     *
     * \param coreId
     *    The core to remove the currently active thread from.
     */
    virtual bool removeThreadFromCore(int coreId) = 0;

    /**
     * Perform periodic cleanup operations, typically deferred from the hot
     * path. Example operations include removing extraneous threads from a
     * given core, and allowing unmanaged kernel threads to run on an updated
     * set of unmanaged cores.
     */
    virtual void garbageCollect() = 0;

    // Virtual destructor to ensure proper destruction
    virtual ~CoreSegregator() {}

    enum CORE_STATUS {
        // A core with this status is logically unmanaged (no managed thread is
        // running on it) as well as physically unmanaged (unmanaged threads
        // can run on it).
        UNMANAGED = -1,
        // A core with this status is logically unmanaged but physically
        // managed (unmanaged threads cannot run on it).
        UNASSIGNED = -2,
        // A core with this thread is logically unmanaged but unmanaged threads
        // should not be allowed to run on it.
        COERCE_IDLE = -3,
    };
};
}  // namespace CoreArbiter

#endif  // CORE_SEGREGATOR_H_
