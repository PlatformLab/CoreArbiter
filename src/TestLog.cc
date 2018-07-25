#include "TestLog.h"
#include "PerfUtils/Util.h"

#include <stdarg.h>

namespace CoreArbiter {

using PerfUtils::Util::vformat;

std::string TestLog::logContents;

const char* 
TestLog::get() {
    return logContents.c_str();
}

void
TestLog::clear() {
    logContents.clear();
}

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
