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

#ifndef CORE_ARBITER_LOGGER_H
#define CORE_ARBITER_LOGGER_H

#include <stdarg.h>
#include <stdint.h>
#include <mutex>

#include "CodeLocation.h"

#define LOG(level, format, ...)                          \
    do {                                                 \
        Logger::log(HERE, level, format, ##__VA_ARGS__); \
    } while (0)

namespace CoreArbiter {

/**
 * Log levels from most to least inclusive.
 */
enum LogLevel { DEBUG, NOTICE, WARNING, ERROR, SILENT };

class Logger {
  public:
    /**
     * Set the minimum severity to print out.
     */
    static void setLogLevel(LogLevel level) { displayMinLevel = level; }

    /**
     * Set the minimum severity to print out, using a string.
     */
    static void setLogLevel(const char* level);

    /**
     * Change the target of the error stream, allowing redirection to an
     * application's log.
     */
    static void setErrorStream(FILE* stream) { errorStream = stream; }

    /**
     * Print a message to the console at a given severity level. Accepts
     * printf-style format strings.
     *
     * \param level
     *     The severity level of this message.
     * \param fmt
     *     A format string, followed by its arguments.
     */
    static void log(const CodeLocation& where, LogLevel level, const char* fmt,
                    ...) __attribute__((format(printf, 3, 4)));

  private:
    // The minimum severity level to print.
    static LogLevel displayMinLevel;

    // Lock around printing since CoreArbiterClient has threads.
    typedef std::unique_lock<std::mutex> Lock;
    static std::mutex mutex;

    // Used to allow redirection of error messages.
    static FILE* errorStream;
};

}  // namespace CoreArbiter

#endif
