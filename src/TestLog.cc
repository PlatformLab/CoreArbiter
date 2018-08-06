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

#include "TestLog.h"

#include <stdarg.h>
#include "PerfUtils/Util.h"


namespace CoreArbiter {

using PerfUtils::Util::vformat;

std::string TestLog::logContents;

/**
 * Read the concatenated output of all TEST_LOG statements since the last call
 * to TestLog::clear().
 */
const char*
TestLog::get() {
    return logContents.c_str();
}

/**
 * Remove all previous messages logged.
 */
void
TestLog::clear() {
    logContents.clear();
}

/**
 * Don't call this directly, see TEST_LOG instead.
 *
 * Log a message to the test log for unit testing.
 *
 * \param[in] format
 *      A printf-style format string for the message. It should not have a line
 *      break at the end.
 * \param[in] ...
 *      The arguments to the format string.
 */
void
TestLog::log(const char* format, ...) {
    if (logContents.length())
        logContents += " | ";
    va_list ap;
    va_start(ap, format);
    logContents += vformat(format, ap);
    va_end(ap);
}

}  // namespace CoreArbiter
