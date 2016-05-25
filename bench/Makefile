ifeq ($(shell uname -s),Cygwin)
	CXX= x86_64-w64-mingw32-g++
endif

# Set compiler to g++
CXX=g++
CFLAGS= -g -O2 -m64 -std=c++11 -stdlib=libc++
LDFLAGS= -lm -lzm -lgmp -lgmpxx -L../../ate-pairing/lib -L../lib
INCLUDES= -I../include -I../../xbyak -I../../ate-pairing/include
DEPS= ../src/sha256.o ../src/bls.o

all: ./bin/bench
	make clean # force recompile TODO: change this it's really ineffecient
	make ./bin/bench
	make ./bin/test

./bin/bench: bench.o
	$(CXX) $(CFLAGS) $(DEPS) bench.o -o $@ $(LDFLAGS)

./bin/test: test.o
	$(CXX) $(CFLAGS) $(DEPS) test.o -o $@ $(LDFLAGS)

bench.o: bench.cpp
	$(CXX) $(CFLAGS) -c bench.cpp $(INCLUDES)

test.o: test.cpp
	$(CXX) $(CFLAGS) -c test.cpp $(INCLUDES)

clean:
	rm *.o bin/bench
