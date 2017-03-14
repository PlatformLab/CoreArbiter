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

#include "gtest/gtest.h"
#include "MockSyscall.h"
#include "CoreArbiterClient.h"
#include "Logger.h"

namespace CoreArbiter {

class CoreArbiterClientTest : public ::testing::Test {
  public:

    MockSyscall* sys;
    std::string socketPath;
    std::string memPath;
    int clientSocket;
    int serverSocket;
    std::atomic<uint64_t> coreReleaseRequestCount;

    CoreArbiterClient client;

    CoreArbiterClientTest()
        : socketPath("/tmp/CoreArbiter/testsocket")
        , memPath("/tmp/CoreArbiter/testsocket")
        , coreReleaseRequestCount(0)
        , client("")
    {
        Logger::setLogLevel(ERROR);

        sys = new MockSyscall();
        CoreArbiterClient::sys = sys;

        int fd[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
        clientSocket = fd[0];
        serverSocket = fd[1];
    }

    ~CoreArbiterClientTest()
    {
        delete sys;
    }

    void connectClient() {
        client.serverSocket = clientSocket;
        client.coreReleaseRequestCount = &coreReleaseRequestCount;
        coreReleaseRequestCount = 0;
        client.coreReleaseCount = 0;

    }

    void disconnectClient() {
        client.serverSocket = -1;
        client.coreReleaseRequestCount = NULL;
    }
};

TEST_F(CoreArbiterClientTest, setNumCores_invalidRequest) {
    // Core request vector too small
    std::vector<uint32_t> coreRequestTooFew(NUM_PRIORITIES - 1);
    ASSERT_THROW(client.setNumCores(coreRequestTooFew),
                 CoreArbiterClient::ClientException);

    // Core request vector too large
    std::vector<uint32_t> coreRequestTooMany(NUM_PRIORITIES + 1);
    ASSERT_THROW(client.setNumCores(coreRequestTooMany),
                 CoreArbiterClient::ClientException);
}

TEST_F(CoreArbiterClientTest, setNumCores_establishConnection) {
    CoreArbiterClient::testingSkipConnectionSetup = true;
    disconnectClient();

    ASSERT_EQ(client.serverSocket, -1);
    std::vector<uint32_t> coreRequest(NUM_PRIORITIES);
    // This isn't going to work because the client's socket is set to an
    // invalid file descriptor for testing
    ASSERT_THROW(client.setNumCores(coreRequest),
                 CoreArbiterClient::ClientException);
    ASSERT_EQ(client.serverSocket, 999);

    CoreArbiterClient::testingSkipConnectionSetup = false;
}

TEST_F(CoreArbiterClientTest, setNumCores) {
    std::vector<uint32_t> coreRequest(NUM_PRIORITIES);
    for (uint32_t i = 0; i < NUM_PRIORITIES; i++) {
        coreRequest[i] = i;
    }

    connectClient();
    client.setNumCores(coreRequest);
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
    disconnectClient();
    ASSERT_FALSE(client.mustReleaseCore());

    connectClient();
    coreReleaseRequestCount = 0;

    ASSERT_FALSE(client.mustReleaseCore());

    coreReleaseRequestCount++;
    ASSERT_TRUE(client.mustReleaseCore());
    ASSERT_EQ(client.coreReleasePendingCount, 1u);
    
    // Simulate a blockUntilCoreAvailable() call
    client.coreReleaseCount++;
    client.coreReleasePendingCount--;

    client.coreReleaseCount++;
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

    CoreArbiterClient::testingSkipConnectionSetup = false;
}

TEST_F(CoreArbiterClientTest, blockUntilCoreAvailable_alreadyExclusive) {
    connectClient();
    coreReleaseRequestCount = 0;
    client.coreId = 1;
    client.ownedCoreCount = 1;
    client.coreReleasePendingCount = 0;

    // Thread should not be allowed to block
    EXPECT_EQ(client.blockUntilCoreAvailable(), 1);
    EXPECT_EQ(client.ownedCoreCount, 1u);

    // This time thread should block because it owes the server a core
    coreReleaseRequestCount = 1;
    core_t coreId = 2;
    send(serverSocket, &coreId, sizeof(core_t), 0);
    EXPECT_EQ(client.blockUntilCoreAvailable(), 2);
    EXPECT_EQ(client.coreReleaseCount, 1u);
    EXPECT_EQ(client.coreReleasePendingCount, 0u);
    EXPECT_EQ(client.ownedCoreCount, 1u);

    // Same test, but this time with a pending release
    coreReleaseRequestCount = 1;
    send(serverSocket, &coreId, sizeof(core_t), 0);
    EXPECT_EQ(client.blockUntilCoreAvailable(), 2);
    EXPECT_EQ(client.coreReleaseCount, 1u);
    EXPECT_EQ(client.coreReleasePendingCount, 0u);
    EXPECT_EQ(client.ownedCoreCount, 1u);

    uint8_t blockMsg;
    recv(serverSocket, &blockMsg, sizeof(uint8_t), 0);
    EXPECT_EQ(blockMsg, THREAD_BLOCK);
}

TEST_F(CoreArbiterClientTest, getOwnedCoreCount) {
    client.ownedCoreCount = 99;
    EXPECT_EQ(client.getOwnedCoreCount(), 99u);
}

}