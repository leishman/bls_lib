ifeq ($(shell uname -s),Cygwin)
	CXX= x86_64-w64-mingw32-g++
endif

# Set compiler to g++
CXX=g++
CFLAGS= -g -O1 -m64
LDFLAGS= -lm -lzm -lgmp -lgmpxx -L../../ate-pairing/lib -L../lib
INCLUDES= -I../include -I../../xbyak -I../../ate-pairing/include
DEPS= ../src/sha256.o ../src/bls.o bench.o

all: ./bin/bench
	make clean # force recompile
	make ./bin/bench

./bin/bench: bench.o
	$(CXX) $(CFLAGS) $(DEPS) -o $@ $(LDFLAGS)

bench.o: bench.cpp
	$(CXX) -c -g bench.cpp $(INCLUDES)

clean:
	rm *.o bin/bench
