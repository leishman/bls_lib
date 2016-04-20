ifeq ($(shell uname -s),Cygwin)
	CXX= x86_64-w64-mingw32-g++
endif

# Set compiler to g++
CXX=g++
LDFLAGS = -lm -lzm -lgmp -lgmpxx -L../../ate-pairing/lib
CFLAGS= -g -O2 -m64 -std=c++11 -stdlib=libc++
TARGET= ../lib/libbls.a

all: $(TARGET)
	# make clean # force recompile
	make ../lib/libbls.a

# TODO: This archive not currently used
../lib/libbls.a: sha256.o bls.o
	# rm -f $@
	ar -r $@ $^

sha256.o: sha256.cpp
	$(CXX) $(CFLAGS) -c sha256.cpp -I../include/

bls.o: bls.cpp
	$(CXX) $(CFLAGS) -c bls.cpp -I../include -I../../xbyak -I../../ate-pairing/include

clean:
	rm *.o
	rm -f $(TARGET)
