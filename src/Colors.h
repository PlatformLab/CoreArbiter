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

#ifndef COLORS_H
#define COLORS_H
#define BLACK(X)             "\033[30m"  X "\033[0m"
#define RED(X)               "\033[31m"  X "\033[0m"
#define GREEN(X)             "\033[32m"  X "\033[0m"
#define YELLOW(X)            "\033[33m"  X "\033[0m"
#define BLUE(X)              "\033[34m"  X "\033[0m"
#define MAGENTA(X)           "\033[35m"  X "\033[0m"
#define CYAN(X)              "\033[36m"  X "\033[0m"
#define WHITE(X)             "\033[37m"  X "\033[0m"
#define BRIGHT_BLACK(X)      "\033[90m"  X "\033[0m"
#define BRIGHT_RED(X)        "\033[91m"  X "\033[0m"
#define BRIGHT_GREEN(X)      "\033[92m"  X "\033[0m"
#define BRIGHT_YELLOW(X)     "\033[93m"  X "\033[0m"
#define BRIGHT_BLUE(X)       "\033[94m"  X "\033[0m"
#define BRIGHT_MAGENTA(X)    "\033[95m"  X "\033[0m"
#define BRIGHT_CYAN(X)       "\033[96m"  X "\033[0m"
#define BRIGHT_WHITE(X)      "\033[97m"  X "\033[0m"
#define BG_BLACK(X)          "\033[40m"  X "\033[0m"
#define BG_RED(X)            "\033[41m"  X "\033[0m"
#define BG_GREEN(X)          "\033[42m"  X "\033[0m"
#define BG_YELLOW(X)         "\033[43m"  X "\033[0m"
#define BG_BLUE(X)           "\033[44m"  X "\033[0m"
#define BG_MAGENTA(X)        "\033[45m"  X "\033[0m"
#define BG_CYAN(X)           "\033[46m"  X "\033[0m"
#define BG_WHITE(X)          "\033[47m"  X "\033[0m"
#define BG_BRIGHT_BLACK(X)   "\033[100m" X "\033[0m"
#define BG_BRIGHT_RED(X)     "\033[101m" X "\033[0m"
#define BG_BRIGHT_GREEN(X)   "\033[102m" X "\033[0m"
#define BG_BRIGHT_YELLOW(X)  "\033[103m" X "\033[0m"
#define BG_BRIGHT_BLUE(X)    "\033[104m" X "\033[0m"
#define BG_BRIGHT_MAGENTA(X) "\033[105m" X "\033[0m"
#define BG_BRIGHT_CYAN(X)    "\033[106m" X "\033[0m"
#define BG_BRIGHT_WHITE(X)   "\033[107m" X "\033[0m"
#endif
