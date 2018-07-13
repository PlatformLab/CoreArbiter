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

#define private public
#define protected public

#include "ArbiterClientShim.h"
#include "CoreArbiterClient.h"
#include "Logger.h"
#include "MockSyscall.h"

#undef private
#undef protected
#include "gtest/gtest.h"

namespace CoreArbiter {

class CoreArbiterClientTest : public ::testing::Test {
  public:
    MockSyscall* sys;
    std::string socketPath;
    std::string memPath;
    int clientSocket;
    int serverSocket;
    ProcessStats processStats;
    GlobalStats globalStats;

    CoreArbiterClient client;
    Arachne::ArbiterClientShim shim_client;

    CoreArbiterClientTest()
        : socketPath("/tmp/CoreArbiter/testsocket"),
          memPath("/tmp/CoreArbiter/testsocket"),
          processStats(),
          globalStats(),
          client("") {
        Logger::setLogLevel(ERROR);

        sys = new MockSyscall();
        CoreArbiterClient::sys = sys;

        int fd[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
        clientSocket = fd[0];
        serverSocket = fd[1];
    }

    ~CoreArbiterClientTest() { delete sys; }

    void connectClient() {
        client.serverSocket = clientSocket;
        client.processStats = &processStats;
        client.globalStats = &globalStats;
    }

    void disconnectClient() {
        client.serverSocket = -1;
        client.processStats = NULL;
        client.globalStats = NULL;
    }
};

TEST_F(CoreArbiterClientTest, setRequestedCores_invalidRequest) {
    CoreArbiterClient::testingSkipConnectionSetup = true;
    disconnectClient();

    // Core request vector too small
    ASSERT_THROW(client.setRequestedCores({0}),
                 CoreArbiterClient::ClientException);

    // Core request vector too large
    ASSERT_THROW(client.setRequestedCores({0, 0, 0, 0, 0, 0, 0, 0, 0}),
                 CoreArbiterClient::ClientException);
}

TEST_F(CoreArbiterClientTest, setRequestedCores_establishConnection) {
    CoreArbiterClient::testingSkipConnectionSetup = true;
    disconnectClient();

    ASSERT_EQ(client.serverSocket, -1);
    // This isn't going to work because the client's socket is set to an
    // invalid file descriptor for testing
    ASSERT_THROW(client.setRequestedCores({0, 0, 0, 0, 0, 0, 0, 0}),
                 CoreArbiterClient::ClientException);
    ASSERT_EQ(client.serverSocket, 999);
}

TEST_F(CoreArbiterClientTest, setRequestedCores) {
    connectClient();
    client.setRequestedCores({0, 1, 2, 3, 4, 5, 6, 7});
    client.serverSocket = -1;

    uint8_t msgType;
    recv(serverSocket, &msgType, sizeof(msgType), 0);
    ASSERT_EQ(msgType, CORE_REQUEST);

    uint32_t requestArr[NUM_PRIORITIES];
    recv(serverSocket, requestArr, sizeof(requestArr), 0);

    for (uint32_t i = 0; i < NUM_PRIORITIES; i++) {
        ASSERT_EQ(requestArr[i], i);
    }
}

TEST_F(CoreArbiterClientTest, mustReleaseCore) {
    connectClient();
    ASSERT_FALSE(client.mustReleaseCore());
    int coreId = 0;

    client.coreId = coreId;
    processStats.threadCommunicationBlocks[coreId].coreReleaseRequested = true;
    ASSERT_TRUE(client.mustReleaseCore());

    // Simulate a blockUntilCoreAvailable() call
    processStats.threadCommunicationBlocks[coreId].coreReleaseRequested = false;

    ASSERT_FALSE(client.mustReleaseCore());
}

TEST_F(CoreArbiterClientTest, blockUntilCoreAvailable_establishConnection) {
    CoreArbiterClient::testingSkipConnectionSetup = true;
    disconnectClient();

    ASSERT_EQ(client.serverSocket, -1);
    // This isn't going to work because the client's socket is set to an
    // invalid file descriptor for testing
    ASSERT_THROW(client.blockUntilCoreAvailable(),
                 CoreArbiterClient::ClientException);
    ASSERT_EQ(client.serverSocket, 999);
}

TEST_F(CoreArbiterClientTest, blockUntilCoreAvailable_alreadyExclusive) {
    connectClient();
    client.coreId = 1;
    client.processStats->numOwnedCores = 1;

    // Thread should not be allowed to block
    EXPECT_EQ(client.blockUntilCoreAvailable(), 1);
    EXPECT_EQ(client.processStats->numOwnedCores, 1u);

    // This time thread should block because it owes the server a core
    processStats.threadCommunicationBlocks[client.coreId].coreReleaseRequested =
        true;
    int coreId = 2;
    send(serverSocket, &coreId, sizeof(int), 0);
    EXPECT_EQ(client.blockUntilCoreAvailable(), 2);
    EXPECT_EQ(client.processStats->numOwnedCores, 1u);

    // Same test, but this time with a pending release
    send(serverSocket, &coreId, sizeof(int), 0);
    EXPECT_EQ(client.blockUntilCoreAvailable(), 2);
    EXPECT_EQ(client.processStats->numOwnedCores, 1u);

    uint8_t blockMsg;
    recv(serverSocket, &blockMsg, sizeof(uint8_t), 0);
    EXPECT_EQ(blockMsg, THREAD_BLOCK);
}

TEST_F(CoreArbiterClientTest, getNumOwnedCores) {
    client.numOwnedCores = 99;
    EXPECT_EQ(client.getNumOwnedCores(), 99u);
}

TEST_F(CoreArbiterClientTest, setRequestedCores_shim) {
    shim_client.setRequestedCores({0, 1, 2, 3, 4, 5, 6, 7});
    ASSERT_EQ(shim_client.currentRequestedCores, (unsigned)28);
}

TEST_F(CoreArbiterClientTest, mustReleaseCore_shim) {
    shim_client.currentCores = 26;
    ASSERT_EQ(shim_client.mustReleaseCore(), true);
}

}  // namespace CoreArbiter
