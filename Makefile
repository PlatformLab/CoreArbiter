CCFLAGS=-Wall -Werror -Wformat=2 -Wextra -Wwrite-strings -Wno-unused-parameter -Wmissing-format-attribute -Wno-non-template-friend -Woverloaded-virtual -Wcast-qual -Wcast-align -Wconversion -fomit-frame-pointer
CC = g++

all: server client

server: CoreArbiterServer.o CoreArbiterServerMain.o
	$(CC) $(LDFLAGS) -o $@ $^

client: CoreArbiterClient.o CoreArbiterClientMain.o
	$(CC) $(LDFLAGS) -pthread -o $@ $^

test: CoreArbiterServer.o
	make -C tests

CoreArbiterServerMain.o: CoreArbiterServerMain.cc
	$(CC) $(CCFLAGS) -O3 -std=c++11 -c CoreArbiterServerMain.cc

CoreArbiterServer.o: CoreArbiterServer.h CoreArbiterServer.cc CoreArbiterCommon.h
	$(CC) $(CCFLAGS) -O3 -std=c++11 -c CoreArbiterServer.cc

CoreArbiterClientMain.o: CoreArbiterClientMain.cc
	$(CC) $(CCFLAGS) -O3 -std=c++11 -c CoreArbiterClientMain.cc

CoreArbiterClient.o: CoreArbiterClient.h CoreArbiterClient.cc CoreArbiterCommon.h
	$(CC) $(CCFLAGS) -O3 -std=c++11 -c CoreArbiterClient.cc

clean:
	rm -f *.o *.a server client