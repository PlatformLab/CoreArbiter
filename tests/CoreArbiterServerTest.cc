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

#define private public
#define VIRTUAL_FOR_TESTING virtual
// #define TESTING 1


#include "gtest/gtest.h"
#include "MockSyscall.h"
#include "CoreArbiterServer.h"

namespace CoreArbiter {

class CoreArbiterServerTest : public ::testing::Test {
  public:

    MockSyscall* sys;
    std::string socketPath;
    std::string memPath;

    CoreArbiterServerTest()
        : socketPath("testsocket")
        , memPath("testmem")
    {
        sys = new MockSyscall();
        CoreArbiterServer::sys = sys;
    }

    ~CoreArbiterServerTest()
    {
        delete sys;
    }
};

TEST_F(CoreArbiterServerTest, constructor_notRoot) {
    sys->callGeteuid = false;
    sys->geteuidResult = 1;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<uint32_t>()),
        "The core arbiter server must be run as root");
    sys->callGeteuid = true;    
}

TEST_F(CoreArbiterServerTest, constructor_socketError) {
    sys->socketErrno = EAFNOSUPPORT;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<uint32_t>()),
        "Error creating listen socket:.*");
    sys->socketErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_bindError) {
    sys->bindErrno = EINVAL;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<uint32_t>()),
        "Error binding listen socket:.*");
    sys->bindErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_listenError) {
    sys->listenErrno = EBADF;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<uint32_t>()),
        "Error listening:.*");
    sys->listenErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_chmodError) {
    sys->chmodErrno = EACCES;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<uint32_t>()),
        "Error on chmod for.*");
    sys->chmodErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_epollCreateError) {
    sys->epollCreateErrno = EINVAL;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<uint32_t>()),
        "Error on epoll_create:.*");
    sys->epollCreateErrno = 0;
}

TEST_F(CoreArbiterServerTest, constructor_epollCtlError) {
    sys->epollCtlErrno = EBADF;
    ASSERT_DEATH(
        CoreArbiterServer(socketPath, memPath, std::vector<uint32_t>()),
        "Error adding listenFd .* to epoll:.*");
    sys->epollCtlErrno = 0;
}

}