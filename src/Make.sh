#temporary replacement of makefile
g++ -c sha256.cpp -o sha256.o -g -O2 -I../include -m64
g++ -c bls.cpp -o bls.o -g -O2   -I../include -I../../xbyak -I../../ate-pairing/include -I../src/ -m64
g++ -o bls bls.o sha256.o -lm -lzm -L../../ate-pairing/lib -lgmp -lgmpxx -m64