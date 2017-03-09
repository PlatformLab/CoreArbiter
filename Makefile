CCFLAGS=-Wall -Werror -Wformat=2 -Wextra -Wwrite-strings -Wno-unused-parameter -Wmissing-format-attribute -Wno-non-template-friend -Woverloaded-virtual -Wcast-qual -Wcast-align -Wconversion -fomit-frame-pointer -std=c++11
CC = g++

all: server client

server: CoreArbiterServer.o CoreArbiterServerMain.o mkdir_p.o Logger.o
	$(CC) $(LDFLAGS) -o $@ $^

client:  CoreArbiterClientMain.o libCoreArbiter.a
	$(CC) $(LDFLAGS) -pthread -o $@ $^

libCoreArbiter.a: CoreArbiterClient.o Logger.o
	ar rcs $@ $^	

test: CoreArbiterServer.o
	make -C tests

CoreArbiterServerMain.o: CoreArbiterServerMain.cc
	$(CC) $(CCFLAGS) -O3 -c CoreArbiterServerMain.cc

CoreArbiterServer.o: CoreArbiterServer.h CoreArbiterServer.cc CoreArbiterCommon.h
	$(CC) $(CCFLAGS) -O3 -c CoreArbiterServer.cc

CoreArbiterClientMain.o: CoreArbiterClientMain.cc
	$(CC) $(CCFLAGS) -O3 -c CoreArbiterClientMain.cc

CoreArbiterClient.o: CoreArbiterClient.h CoreArbiterClient.cc CoreArbiterCommon.h
	$(CC) $(CCFLAGS) -fPIC  -O3 -c CoreArbiterClient.cc

Logger.o: Logger.h Logger.cc
	$(CC) $(CCFLAGS) -O3 -c Logger.cc

%.o: %.cc
	g++ $(CCFLAGS) -O3  $(LIBS) -fPIC -c -std=c++11 -o $@ $<

clean:
	rm -f *.o *.a server client
