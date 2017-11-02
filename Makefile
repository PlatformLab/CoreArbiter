CC=g++
CCFLAGS=-g -Wall -Wformat=2 -Wextra -Wwrite-strings \
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
LIBS=$(PERFUTILS)/lib/libPerfUtils.a -lpcrecpp -pthread

# Stuff needed for make check
TOP := $(shell echo $${PWD-`pwd`})
ifndef CHECK_TARGET
CHECK_TARGET=$$(find $(SRC_DIR) '(' -name '*.h' -or -name '*.cc' ')' -not -path '$(TOP)/googletest/*' )
endif

OBJECT_NAMES := CoreArbiterServer.o  CoreArbiterClient.o mkdir_p.o Logger.o CodeLocation.o ArbiterClientShim.o

OBJECTS = $(patsubst %,$(OBJECT_DIR)/%,$(OBJECT_NAMES))
HEADERS= $(shell find src -name '*.h')
DEP=$(OBJECTS:.o=.d)

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

-include $(DEP)

$(OBJECT_DIR)/%.d: $(SRC_DIR)/%.cc | $(OBJECT_DIR)
	$(CC) $(INCLUDE) $(CCFLAGS) $< -MM -MT $(@:.d=.o) > $@

$(OBJECT_DIR)/%.o: $(SRC_DIR)/%.cc $(HEADERS) | $(OBJECT_DIR)
	$(CC) $(INCLUDE) $(CCFLAGS) -c $< -o $@

$(OBJECT_DIR):
	mkdir -p $(OBJECT_DIR)

check:
	scripts/cpplint.py --filter=-runtime/threadsafe_fn,-readability/streams,-whitespace/blank_line,-whitespace/braces,-whitespace/comments,-runtime/arrays,-build/include_what_you_use,-whitespace/semicolon $(CHECK_TARGET)
	! grep '.\{81\}' $(SRC_DIR)/*.h $(SRC_DIR)/*.cc

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
	rm -rf $(OBJECT_DIR) $(BIN_DIR) $(INCLUDE_DIR) $(LIB_DIR)

.PHONY: install clean
