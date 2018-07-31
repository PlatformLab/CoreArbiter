#include "TestLog.h"
#include "PerfUtils/Util.h"

#include <stdarg.h>

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