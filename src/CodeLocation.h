/* Copyright (c) 2011-2017 Stanford University
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

#ifndef CORE_ARBITER_CODELOCATION_H
#define CORE_ARBITER_CODELOCATION_H

#include <assert.h>
#include <stdarg.h>
#include <string>

namespace CoreArbiter {

// Utility functions used.
std::string format(const char* format, ...);

/**
 * Describes the location of a line of code.
 * You can get one of these with #HERE.
 */
struct CodeLocation {
    /// Called by #HERE only.
    CodeLocation(const char* file, const uint32_t line, const char* function,
                 const char* prettyFunction)
        : file(file),
          line(line),
          function(function),
          prettyFunction(prettyFunction) {}
    std::string str() const {
        return format("%s at %s:%d", qualifiedFunction().c_str(),
                      relativeFile().c_str(), line);
    }
    const char* baseFileName() const;
    std::string relativeFile() const;
    std::string qualifiedFunction() const;

    /// __FILE__
    const char* file;
    /// __LINE__
    uint32_t line;
    /// __func__
    const char* function;
    /// __PRETTY_FUNCTION__
    const char* prettyFunction;
};

/**
 * Constructs a #CodeLocation describing the line from where it is used.
 */
#define HERE \
    CoreArbiter::CodeLocation(__FILE__, __LINE__, __func__, __PRETTY_FUNCTION__)

/**
 * Cast one size of int down to another one.
 * Asserts that no precision is lost at runtime.
 */
template <typename Small, typename Large>
Small
downCast(const Large& large) {
    Small small = static_cast<Small>(large);
    // The following comparison (rather than "large==small") allows
    // this method to convert between signed and unsigned values.
    assert(large - small == 0);
    return small;
}

std::string format(const char* format, ...)
    __attribute__((format(printf, 1, 2)));
std::string vformat(const char* format, va_list ap)
    __attribute__((format(printf, 1, 0)));

}  // namespace CoreArbiter

#endif  // RAMCLOUD_CODELOCATION_H
