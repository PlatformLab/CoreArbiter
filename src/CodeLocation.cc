/* Copyright (c) 2017 Stanford University
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

#include "CodeLocation.h"
#include <pcrecpp.h>
#include <cassert>

namespace CoreArbiter {

namespace {

/**
 * Return the number of characters of __FILE__ that make up the path prefix.
 * That is, __FILE__ plus this value will be the relative path from the top
 * directory of the RAMCloud repo.
 */
int
length__FILE__Prefix() {
    const char* start = __FILE__;
    const char* match = strstr(__FILE__, "src/CodeLocation.cc");
    assert(match != NULL);
    return downCast<int>(match - start);
}

}  // anonymous namespace

/**
 * Return the base name of the file (i.e., only the last component of the
 * file name, omitting any preceding directories).
 */
const char*
CodeLocation::baseFileName() const {
    const char* lastSlash = strrchr(file, '/');
    if (lastSlash == NULL) {
        return file;
    }
    return lastSlash + 1;
}

std::string
CodeLocation::relativeFile() const {
    static int lengthFilePrefix = length__FILE__Prefix();
    // Remove the prefix only if it matches that of __FILE__. This check is
    // needed in case someone compiles different files using different paths.
    if (strncmp(file, __FILE__, lengthFilePrefix) == 0)
        return std::string(file + lengthFilePrefix);
    else
        return std::string(file);
}

/**
 * Return the name of the function, qualified by its surrounding classes and
 * namespaces. Note that this strips off the RAMCloud namespace to produce
 * shorter strings.
 *
 * Beware: this method is really really slow (10-20 microseconds); we no
 * longer use it in log messages because it wastes so much time.
 */
std::string
CodeLocation::qualifiedFunction() const {
    std::string ret;
    const std::string pattern(
        format("\\s(?:RAMCloud::)?(\\S*\\b%s)\\(", function));
    if (pcrecpp::RE(pattern).PartialMatch(prettyFunction, &ret))
        return ret;
    else  // shouldn't happen
        return function;
}

// Utility functions used for formatting.

/// A safe version of sprintf.
std::string
format(const char* format, ...) {
    va_list ap;
    va_start(ap, format);
    std::string s = vformat(format, ap);
    va_end(ap);
    return s;
}

/// A safe version of vprintf.
std::string
vformat(const char* format, va_list ap) {
    std::string s;

    // We're not really sure how big of a buffer will be necessary.
    // Try 1K, if not the return value will tell us how much is necessary.
    int bufSize = 1024;
    while (true) {
        char buf[bufSize];
        // vsnprintf trashes the va_list, so copy it first
        va_list aq;
        __va_copy(aq, ap);
        int r = vsnprintf(buf, bufSize, format, aq);
        assert(r >= 0);  // old glibc versions returned -1
        if (r < bufSize) {
            s = buf;
            break;
        }
        bufSize = r + 1;
    }

    return s;
}

}  // namespace CoreArbiter
