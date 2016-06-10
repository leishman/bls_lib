# Stanford BLS Signature Library

# WARNING: IN DEVELOPMENT! DO NOT USE IN PRODUCTION!!!!!

## Features
- Invididual BLS signature generation and validation
- Aggregate BLS signature generation and validation
- Threshold BLS signature API (stil in progress)

## Usage
### Individual Signatures
```c++

  // create instance of Bls class
  Bls my_bls = Bls();

  // define message
  const char *msg = "That's how the cookie crumbles";

  // generate public key from seed
  const char *seed = "19283492834298123123";
  PubKey pubkey = my_bls.genPubKey(seed);

  // create signature
  Sig sig = my_bls.signMsg(msg, seed, pubkey);
  
  // validate signature
  my_bls.verifySig(pubkey, msg, sig);
```

### Aggregate Signatures
```c++

  // create instance of Bls class
  Bls my_bls = Bls();

  // generate two seeds (NOTE: seeds should actually be random)
  const char *seed_1 = "11111111111";
  const char *seed_2 = "22222222222";

  // generate both pubkeys
  PubKey pubkey_1 = my_bls.genPubKey(seed_1);
  PubKey pubkey_2 = my_bls.genPubKey(seed_2);

  std::vector<PubKey> pubkeys;
  pubkeys.push_back(pubkey_1);
  pubkeys.push_back(pubkey_2);

  const char *msg_1 = "message 1";
  const char *msg_2 = "message 2";

  std::vector<const char *> msgs;
  msgs.push_back(msg_1);
  msgs.push_back(msg_2);

  // sign both messages
  Sig sig_1 = my_bls.signMsg(msg_1, seed_1, pubkey_1);
  Sig sig_2 = my_bls.signMsg(msg_2, seed_2, pubkey_2);

  // add signatures to vector
  std::vector<Sig> sigs;
  sigs.push_back(sig_1);
  sigs.push_back(sig_2);

  // generate the aggregate signature of all signatures in the vector
  Sig agg_sig = my_bls.aggregateSigs(sigs);

  // Check that the signature is valid
  bool agg_sig_valid = my_bls.verifyAggSig(msgs, pubkeys, agg_sig);
```



## TODO
- Distributed Key Generation
- Threshold Signatures
- Blind Signatures

## Build
- This project must sit in the same directory as both [ate-pairing](https://github.com/herumi/ate-pairing) and [xbyak](https://github.com/herumi/xbyak). Build both of these projects following the given instructions in the respective repo.
- Run `make` in `/src` to compile the object files
- To run the benchmark run `make` in `/bench` which will compile, build and save the executable in `/bench/bin`


## Classes
- Bls - Create instance of this class to perform BLS sign/verify functions
- Sig - Signature (point in Ec1)
- PubKey - Public Key (generated from seed)

### Author: Alexander Leishman

### Contributors:
- PengHui How

