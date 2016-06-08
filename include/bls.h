/*
 * Dependencies: https://github.com/herumi/ate-pairing
 */

#include <iostream>
#include <cmath>
#include <typeinfo>
#include "bn.h"
#include "sha256.h"
#include <vector>
#include <string>
#include <map>
#include <openssl/rand.h>
#include "../src/test_point.hpp"


using namespace std;
using namespace bn;

namespace bls {
  // y^2 = x^3 + b
  const int CURVE_B = 2;
  const mie::Vuint CURVE_P = mie::Vuint("16798108731015832284940804142231733909889187121439069848933715426072753864723");

  /*
   * Container for managing PubKey format and serialization
   */
  class PubKey {
    public:
    PubKey(const char* serializedPubKey);
    PubKey(std::string serializedPubKey);
    PubKey(Ec2 pk);

    // pubkey point (in Ec2 - defined in ate-pairing lib)
    Ec2 ec2;

    Ec2 toEc2();
    std::string toString();
  };


  /*
   * Container for managing Signature format and serialization
   */
  class Sig {
    public:
    Sig(Ec1 sig);

    // signature point (in Ec1 - defined in ate-pairing lib)
    Ec1 ec1;


    Sig addSig(Ec1 sig);
    Sig(const char* serializedSig);
    Sig(string serializedSig);
    std::string toString();
    Ec1 toEc1();
  };

  /*
   * Structure to threshold secret point
   */
  typedef struct thresholdPoint {
    Fp x;
    Fp y;
  } thresholdPoint;

  /*
   * Structure to threshold signature share
   */
  typedef struct thresholdSigPoint {
    Fp x;
    Sig y;
  } thresholdSigPoint;


  /*
   * Structure to hold point for testing
   */
  typedef struct shamirPoint {
    Fp x;
    Fp y;
  } shamirPoint;


  class Bls {

    public:

    Ec1 g1;
    Ec2 g2;
    bn::CurveParam cp;
    
    /*
     * Constructor for the Bls class
     */
    Bls();

    /*
     * Function genPubKey: generate a public key from a random seed
     * @param {const string&} rand_seed, string representation of 256 bit int
     * @return {PubKey}  public key point
     * public_key = g2 ^ secret_key
     */
    PubKey genPubKey(mie::Vuint secret_key);
    PubKey genPubKey(const char *rand_seed);
    PubKey genPubKey(const string& seed);

    /*
     * Placeholder for testing during Threshold development
     */
    Fp recoverSecret(const std::vector<shamirPoint>& points, size_t t);


    /* 
     * Function: aggregateSigs()
     * Multiply signatures together to create aggregate signature
     * @param {std::vector<Sig>&} sigs, vector of signatures
     * @returns {Sig} aggregate signature
     */
    Sig aggregateSigs(const std::vector<Sig> &sigs);


    /* 
     * Function: verifySig, verify a signature
     * @param {const Pubkey} pubkey  point in G2 representing the pubkey
     * @param {const char*} msg  the message that was signed
     * @param {const Sig} sig  the point in G1 representing the signature
     */
    bool verifySig(PubKey const &pubkey, const char* msg, Sig const &sig);

    /* 
     * Function: signMsg
     * Sign message with secret key
     * @param {const char*} msg  message to be signed
     * @param {const char*} secret_key  integer string represenation of secret key
     * @param {const PubKey} pubkey  integer string represenation of secret key
     */
    Sig signMsg(const char *msg, const char* secret_key, const PubKey &pubkey);
    Sig signMsg(const char *msg, const mie::Vuint secret_key, const PubKey &pubkey);
    Sig signMsg(std::string& msg, const mie::Vuint secret_key, const PubKey &pubkey);


    /* 
     * Function: verifyAggSig()
     * Verify aggregate signature for n pubkey, msg pairs
     * Each message/pubkey need not be be distinct:
     * Unrestricted Aggregate Signatures, Bellare, et. al (http://link.springer.com/chapter/10.1007%2F978-3-540-73420-8_37)
     * @param {vector<char*>*} Vector containing pubkeys used in aggregate signature
     * @param {vector<char*>*} Vector containing messages used in aggregate signature
     * @param {Ec1 sig} Point in G1 representing aggregate signature
     */
    bool verifyAggSig(const std::vector<const char*> &messages, const std::vector<PubKey> &pubkeys, const Sig &sig, bool delay_exp=true);

    /* Function: verify_threshold_sig
    * @param {char*} msg
    * @param {char*} sig
    * @return {bool} check that threshold signature is valid
    */
    bool verifyThreshSig(const char* msg);

    /* Function: hash_msg
     * hash message onto curve: h = H(M) \in G_1
     * @param {char*} msg
     * @return {Ec1} point in G_1
     */
    Ec1 hashMsgWithPubkey(const char *msg, const Ec2 &pubkey);

    /*
     * Function: genThreshKeys, centralized generation of collection of threshold keyshares
     * @param {char*} secret, secret key to split amongst shares
     * @param {size_t} t, threshold required
     * @param {size_t} n, number of shares to generate n >= t
     * @param {vector<thresholdPoint>&} pair_vec, vector to be populated with shares
     * @return void
     */
    // TODO: maybe have this explicitly return the new vector
    void genThreshKeys(const char* secret, size_t t, size_t n, std::vector<thresholdPoint>& pair_vec);

    /*
     * Function: combineThresholdSigs, calculate single signature from collection of shares
     * @param {vector<thresholdSigPoint>&} vector of shares, each containing signature and x-coord
     * @param {size_t} threshold required
     * @returns {Sig} final threshold signature
     */
    Sig combineThresholdSigs(const std::vector<thresholdSigPoint>& sigs, size_t t);

    Ec1 mapHashOntoCurve(const char* hashed_message);

    private:

    /* Function: nbits
     * @param {mie::Vuint} (val)
     * @return {mie::Vuint} (number of bits of the input integer)
     */
    const mie::Vuint nbits(const mie::Vuint val);

    /* Function: ord2
     * val = 2^r * s where s is odd
     * @param {mie::Vuint} (val)
     * @param {mie::Vuint *} (s)
     * @return {mie::Vuint} (r)
     */
    const mie::Vuint ord2(const mie::Vuint val, mie::Vuint *s);

    /* Function: prepend_p
     * @param {mie::Vuint} val
     * @param {mie::Vuint} num_digits (binary length val)
     * @param {unsigned long} pre (to be prepended)
     * @return {Fp} the prepended value (1|val) % p, in Fp
     */
    Fp prependP(const mie::Vuint val, const mie::Vuint num_digits, unsigned long pre);

    /* 
     * Function: mapHashOntoCurve
     * hash message digest onto curve: h = H(M) \in G_1
     * @param {char*} msg_digest should take the form of 0x.....
     * @return {Ec1} point in G_1
     */

    /*
     * Function: calcPolynomial, Calculate y value of given x value and set of polynomial coefficients
     * y = secret + r_0*x + r_1 * x^2 + r_2 * x^3 ... r_n * x^n
     * @param {vector<mie::Vuint>& r_vals} reference to vector containing r vals
     * @param {mie::Vuint} secret
     * @param {int} x, x value
     * @return y {mie::Vuint}, value of evaluation of polynomial at x
     */
    mie::Vuint calcPolynomial(std::vector<mie::Vuint>& r_vals, mie::Vuint secret, int x);
  };
}
