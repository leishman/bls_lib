# BLS Signature Library
### Authors: PengHui How, Alexander Leishman

## TODO
- Distributed Key Generation
- Again look at data types here
- Threshold Signatures
- Blind Signatures
- Aggregate signatures
- Signing Function

## Build
- This project must sit in the same directory as both [ate-pairing](https://github.com/herumi/ate-pairing) and [xbyak](https://github.com/herumi/xbyak). Build both of these projects following the given instructions in the respective repo.
- Run `make` in `/src` to compile the object files
- To run the benchmark run `make` in `/bench` which will compile, build and save the executable in `/bench/bin`