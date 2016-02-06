
ifeq ($(shell uname -s),Cygwin)
	CXX= x86_64-w64-mingw32-g++
endif

CXX=g++

CFLAGS= -g -O2
HEADER= ../../ate-pairing/include/zm.h ../../ate-pairing/include/bn.h ../../ate-pairing/include/zm2.h ../include/bls.h 
INC_DIR+= -I../include -I../../xbyak -I../../ate-pairing/include

LDFLAGS = -lm -lzm $(LIB_DIR) -lgmp -lgmpxx
LIB_DIR+= -L../../ate-pairing/lib
BIT=-m64

ifeq ($(BIT),-m64)
	TARGET += bls
endif

# all:$(TARGET)
.SUFFIXES: .cpp
.cpp.o:
	$(CXX) -c $< -o $@ $(CFLAGS) $(CFLAGS_WARN) $(CFLAGS_ALWAYS) $(INC_DIR) $(BIT)

.c.o:
	$(CC) -c $< -o $@ $(CFLAGS) $(CFLAGS_WARN) $(CFLAGS_ALWAYS) $(INC_DIR) $(BIT)

bls: bls.o ../../ate-pairing/lib/libzm.a
	$(CXX) -o $@ $< $(LDFLAGS) $(BIT)

clean:
	$(RM) *.o $(TARGET)

bls.o: bls.cpp $(HEADER)
