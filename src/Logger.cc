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

#include "Logger.h"

#include <string.h>
#include "PerfUtils/Cycles.h"

namespace CoreArbiter {

using PerfUtils::Cycles;

FILE* Logger::errorStream = stderr;
LogLevel Logger::displayMinLevel = WARNING;
std::mutex Logger::mutex;

/**
 * Friendly names for each #LogLevel value.
 * Keep this in sync with the LogLevel enum.
 */
static const char* logLevelNames[] = {"DEBUG", "NOTICE", "WARNING", "ERROR",
                                      "SILENT"};

void
Logger::log(const CodeLocation& where, LogLevel level, const char* fmt, ...) {
    if (level < displayMinLevel) {
        return;
    }

#define MAX_MESSAGE_CHARS 2000
    // Construct a message on the stack and then print it out with the lock
    char buffer[MAX_MESSAGE_CHARS];
    int spaceLeft = MAX_MESSAGE_CHARS;
    int charsWritten = 0;
    int actual;
    uint64_t time = Cycles::rdtsc();

    // Add a header including rdtsc time and location in the file.
    actual = snprintf(buffer + charsWritten, spaceLeft,
                      "%.10lu %s:%d in %s %s: ", time, where.baseFileName(),
                      where.line, where.function, logLevelNames[level]);
    charsWritten += actual;
    spaceLeft -= actual;

    // Add the actual message
    va_list args;
    va_start(args, fmt);
    actual = vsnprintf(buffer + charsWritten, spaceLeft, fmt, args);
    va_end(args);

    Lock lock(mutex);
    fprintf(errorStream, "%s\n", buffer);
    fflush(errorStream);
}

void
Logger::setLogLevel(const char* level) {
    if (strcmp(level, "DEBUG") == 0) {
        displayMinLevel = DEBUG;
    } else if (strcmp(level, "NOTICE") == 0) {
        displayMinLevel = NOTICE;
    } else if (strcmp(level, "WARNING") == 0) {
        displayMinLevel = WARNING;
    } else if (strcmp(level, "ERROR") == 0) {
        displayMinLevel = ERROR;
    } else if (strcmp(level, "SILENT") == 0) {
        displayMinLevel = SILENT;
    }
}

}  // namespace CoreArbiter
