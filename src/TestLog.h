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
#ifndef TEST_LOG_H
#define TEST_LOG_H

#include <string>

namespace CoreArbiter {
    // Simple class for test-only logs in memory for facilitating unit tests.
    // This class is not thread-safe.
class TestLog {
 public:
   static const char* get();
   static void clear();
   static void log(const char* format, ...)
                __attribute__((format(gnu_printf, 1, 2)));
 private:
   static std::string logContents;
};

#if TESTING
/**
 * Log an entry in the test log for use in unit tests.
 *
 * See RAMCloud::TestLog for examples on how to use this for testing.
 *
 * \param[in] format
 *      A printf-style format string for the message. It should not have a line
 *      break at the end.
 * \param[in] ...
 *      The arguments to the format string.
 */
#define TEST_LOG(format, ...) \
    TestLog::log(format, ##__VA_ARGS__)
#else
#define TEST_LOG(format, ...)
#endif

}  // namespace CoreArbiter
#endif  // TEST_LOG_H
