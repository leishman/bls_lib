
/*
 * Dependencies: https://github.com/herumi/ate-pairing
 */

/*
 * Function: bls_keygen
 * Generate a random public/private keypair
 */

#include <iostream>
#include <cmath>
#include <typeinfo>
#include "bn.h"
#include "sha256.h"
#include <vector>
#include <map>
#include "../src/test_point.hpp"

using namespace std;
using namespace bn;

class Bls {
  private:
  Ec1 g1;
  Ec2 g2;

  public:
  Bls();

  /*
  * @param {char* } rand_seed, string representation of 256 bit int
  * @return {Ec2}  public key point
  * public_key = g2 ^ secret_key
  */
  Ec2 gen_key(const char *rand_seed);


  /* Function: aggregate_sigs()
  * Multiply signatures together to create aggregate signature
  * @param {std::vector<Ec1>*} sigs
  * @returns {Ec1} aggregate signature
  */
  Ec1 aggregate_sigs(const std::vector<Ec1> &sigs);

  /* Function: verify_sig
  * @param {Ec2} pubkey  point in G2 representing the pubkey
  * @param {char*} msg  the message that was signed
  * @param {Ec1} sig  the point in G1 representing the signature
  */
  bool verify_sig(Ec2 const &pubkey, const char* msg, Ec1 const &sig);

  /* Function: sign_msg
  * Sign message with secret key
  * @param {char*} msg  message to be signed
  * @param {char*} secret_key  integer string represenation of secret key
  */
  Ec1 sign_msg(const char *msg, const char* secret_key);

  /* Function: verify_agg_sig()
  * Verify aggregate signature for n pubkey, msg pairs
  * Each message must be distinct
  * @param {vector<char*>*} Vector containing pubkeys used in aggregate signature
  * @param {vector<char*>*} Vector containing messages used in aggregate signature
  * @param {Ec1 sig} Point in G1 representing aggregate signature
  */
  bool verify_agg_sig(std::vector<const char*> &messages, std::vector<Ec2> &pubkeys, Ec1 sig);

  /* Function: verify_threshold_sig
  * @param {char*} msg
  * @param {char*} sig
  * @return {bool} check that threshold signature is valid
  */
  bool verify_threshold_sig(const char* msg);

};

