ifeq ($(shell uname -s),Cygwin)
	CXX= x86_64-w64-mingw32-g++
endif

# Set compiler to g++
CXX=g++
LDFLAGS = -lm -lzm -lgmp -lgmpxx -L../../ate-pairing/lib
CFLAGS= -g -O2 -m64

all: bls

bls: sha256.o bls.o ../../ate-pairing/lib/libzm.a
	$(CXX) bls.o sha256.o -o bls $(CFLAGS) $(LDFLAGS)

sha256.o: sha256.cpp
	$(CXX) -c sha256.cpp -I../include/

bls.o: bls.cpp
	$(CXX) -c bls.cpp -I../include -I../../xbyak -I../../ate-pairing/include

clean:
	rm *o bls

