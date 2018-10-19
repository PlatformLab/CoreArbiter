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

#include <string.h>
#include "CoreArbiterServer.h"
#include "Logger.h"
#include "PerfUtils/Util.h"

using CoreArbiter::CoreArbiterServer;
using CoreArbiter::Logger;

std::string socketPath = "/tmp/CoreArbiter/socket";
std::string sharedMemoryPath = "/tmp/CoreArbiter/sharedmemory";
std::vector<int> coresUsed = std::vector<int>();

const char usage[] =
"Usage: ./coreArbiterServer [-h] [--coresUsed <comma_separated_range_list>]"
" [--socketPath <path_to_serving_socket>] [--sharedMemoryPath <path_to_shared memory>]"
" [--logLevel DEBUG|NOTICE|WARNING|ERROR|SILENT]";

/**
 * This function currently supports only long options.
 */
void
parseOptions(int* argcp, const char** argv) {
    if (argcp == NULL)
        return;

    int argc = *argcp;

    struct OptionSpecifier {
        // The string that the user uses after `--`.
        const char* optionName;
        // The id for the option that is returned when it is recognized.
        int id;
        // Does the option take an argument?
        bool takesArgument;
    } optionSpecifiers[] = {{"help", 'h', false},
                            {"socketPath", 'p', true},
                            {"sharedMemoryPath", 'm', true},
                            {"coresUsed", 's', true},
                            {"logLevel", 'l', true}};
    const int UNRECOGNIZED = ~0;

    int i = 1;
    while (i < argc) {
        if (argv[i][0] != '-' || argv[i][1] != '-') {
            i++;
            continue;
        }
        const char* optionName = argv[i] + 2;
        int optionId = UNRECOGNIZED;
        const char* optionArgument = NULL;

        for (size_t k = 0;
             k < sizeof(optionSpecifiers) / sizeof(OptionSpecifier); k++) {
            const char* candidateName = optionSpecifiers[k].optionName;
            bool needsArg = optionSpecifiers[k].takesArgument;
            if (strncmp(candidateName, optionName, strlen(candidateName)) ==
                0) {
                if (needsArg) {
                    if (i + 1 >= argc) {
                        LOG(CoreArbiter::ERROR,
                            "Missing argument to option %s!\n", candidateName);
                        break;
                    }
                    optionArgument = argv[i + 1];
                    optionId = optionSpecifiers[k].id;
                    argc -= 2;
                    memmove(argv + i, argv + i + 2, (argc - i) * sizeof(char*));
                } else {
                    optionId = optionSpecifiers[k].id;
                    argc -= 1;
                    memmove(argv + i, argv + i + 1, (argc - i) * sizeof(char*));
                }
                break;
            }
        }
        switch (optionId) {
            case 'h':
                puts(usage);
                exit(0);
            case 'p':
                socketPath = optionArgument;
                break;
            case 'm':
                sharedMemoryPath = optionArgument;
                break;
            case 's':
                if (memcmp(optionArgument, "ALL", sizeof("ALL")) == 0)
                    coresUsed = std::vector<int>();
                else
                    coresUsed = PerfUtils::Util::parseRanges(optionArgument);
                break;
            case 'l':
                Logger::setLogLevel(optionArgument);
                break;
            case UNRECOGNIZED:
                LOG(CoreArbiter::ERROR, "Unrecognized option %s given.",
                    optionName);
                abort();
        }
    }
    *argcp = argc;
}

int
main(int argc, const char** argv) {
    Logger::setLogLevel(CoreArbiter::ERROR);
    parseOptions(&argc, argv);
    printf("socketPath:       %s\n", socketPath.c_str());
    printf("sharedMemoryPath: %s\n", sharedMemoryPath.c_str());
    printf("coresUsed:       ");
    if (coresUsed.empty()) {
        printf(" ALL\n");
    } else {
        for (size_t i = 0; i < coresUsed.size(); i++)
            printf(" %d", coresUsed[i]);
        putchar('\n');
    }
    fflush(stdout);

    CoreArbiterServer server(socketPath, sharedMemoryPath, coresUsed);
    return 0;
}
