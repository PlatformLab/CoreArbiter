CC=g++
CCFLAGS=-g -Wall -Werror -Wformat=2 -Wextra -Wwrite-strings \
-Wno-unused-parameter -Wmissing-format-attribute -Wno-non-template-friend \
-Woverloaded-virtual -Wcast-qual -Wcast-align -Wconversion -fomit-frame-pointer \
-std=c++11 -fPIC -O3

# Output directories
OBJECT_DIR = obj
SRC_DIR = src
INCLUDE_DIR = include
LIB_DIR = lib
BIN_DIR = bin

# Depenencies
PERFUTILS=../PerfUtils
INCLUDE=-I$(PERFUTILS)/include
LIBS=$(PERFUTILS)/lib/libPerfUtils.a -pthread


OBJECT_NAMES := CoreArbiterServer.o  CoreArbiterClient.o mkdir_p.o Logger.o
HEADER_NAMES =  CoreArbiterClient.h CoreArbiterServer.h

OBJECTS = $(patsubst %,$(OBJECT_DIR)/%,$(OBJECT_NAMES))
HEADERS= $(patsubst %,$(SRC_DIR)/%,$(HEADER_NAMES))

SERVER_BIN = $(OBJECT_DIR)/server
CLIENT_BIN =  $(OBJECT_DIR)/client

install: $(SERVER_BIN) $(CLIENT_BIN)
	mkdir -p $(BIN_DIR) $(LIB_DIR) $(INCLUDE_DIR)/CoreArbiter
	cp $(HEADERS) $(INCLUDE_DIR)/CoreArbiter
	cp $(SERVER_BIN) $(CLIENT_BIN) bin
	cp $(OBJECT_DIR)/libCoreArbiter.a lib

$(SERVER_BIN): $(OBJECT_DIR)/CoreArbiterServerMain.o $(OBJECT_DIR)/libCoreArbiter.a
	$(CC) $(LDFLAGS) $(CCFLAGS) -o $@ $^ $(LIBS)

$(CLIENT_BIN): $(OBJECT_DIR)/CoreArbiterClientMain.o $(OBJECT_DIR)/libCoreArbiter.a
	$(CC) $(LDFLAGS) $(CCFLAGS) -o $@ $^ $(LIBS)

$(OBJECT_DIR)/libCoreArbiter.a: $(OBJECTS)
	ar rcs $@ $^	

$(OBJECT_DIR)/%.o: $(SRC_DIR)/%.cc $(HEADERS) | $(OBJECT_DIR)
	$(CC) $(INCLUDE) $(CCFLAGS) -c $< -o $@

$(OBJECT_DIR):
	mkdir -p $(OBJECT_DIR)

################################################################################
# Test Targets

GTEST_DIR=../googletest/googletest
TEST_LIBS=-Lobj/ -lCoreArbiter $(OBJECT_DIR)/libgtest.a
INCLUDE+=-I${GTEST_DIR}/include

test: $(OBJECT_DIR)/CoreArbiterServerTest $(OBJECT_DIR)/CoreArbiterClientTest
	sudo $(OBJECT_DIR)/CoreArbiterServerTest
	$(OBJECT_DIR)/CoreArbiterClientTest

$(OBJECT_DIR)/CoreArbiterServerTest: $(OBJECT_DIR)/CoreArbiterServerTest.o $(OBJECT_DIR)/libgtest.a $(OBJECT_DIR)/libCoreArbiter.a
	$(CC) $(INCLUDE) $(CCFLAGS) $< $(GTEST_DIR)/src/gtest_main.cc $(TEST_LIBS) $(LIBS)  -o $@

$(OBJECT_DIR)/CoreArbiterClientTest: $(OBJECT_DIR)/CoreArbiterClientTest.o $(OBJECT_DIR)/libgtest.a $(OBJECT_DIR)/libCoreArbiter.a
	$(CC) $(INCLUDE) $(CCFLAGS) $< $(GTEST_DIR)/src/gtest_main.cc $(TEST_LIBS) $(LIBS)  -o $@

$(OBJECT_DIR)/libgtest.a:
	g++ -I${GTEST_DIR}/include -I${GTEST_DIR} \
		-pthread -c ${GTEST_DIR}/src/gtest-all.cc \
		-o $(OBJECT_DIR)/gtest-all.o
	ar -rv $(OBJECT_DIR)/libgtest.a $(OBJECT_DIR)/gtest-all.o
################################################################################

clean:
	rm -rf obj bin lib

.PHONY: install clean
