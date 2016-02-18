#include "bls.h"
#include "test_point.hpp"


using namespace std;
using namespace bn;

/* Function: Bls Class constructor
 *
 */
Bls::Bls() {
  bn::CurveParam cp = bn::CurveFp254BNb;
  Param::init(cp);

  const Point& pt = selectPoint(cp);

  Ec1 g1p(pt.g1.a, pt.g1.b);

  Ec2 g2p(
    Fp2(Fp(pt.g2.aa), Fp(pt.g2.ab)),
    Fp2(Fp(pt.g2.ba), Fp(pt.g2.bb))
  );

  g1 = g1p;
  g2 = g2p;
}

/* Function: nbits
 * @param {mie::Vuint} (val)
 * @return {mie::Vuint} (number of bits of the input integer)
 */
static const mie::Vuint nbits(const mie::Vuint val){
  if(val <= 1) return 1;
  return nbits(val / 2) + 1;
}

/* Function: ord2
 * val = 2^r * s where s is odd
 * @param {mie::Vuint} (val)
 * @param {mie::Vuint *} (s)
 * @return {mie::Vuint} (r)
 */
static const mie::Vuint ord2(const mie::Vuint val, mie::Vuint *s){
  if((val % 2 == 1) || (val == 0)) {
    *s = val;
    return 0;
  }
  return ord2(val / 2, s) + 1;
}

/* Function: pow_p
 * power mod p
 * @param {Fp} val
 * @param {mie::Vuint} power
 * @return {Fp} a value in Fp
 */
static const Fp pow_p(Fp val, const mie::Vuint power){
  if(power == 0) return 1;
  if(power == 1) return val;
  Fp result_sqrt_floor = pow_p(val, power/2);
  return (result_sqrt_floor * result_sqrt_floor) * pow_p(val, power % 2);
}

/* Function: sqrt_p
 * returns a possible sqrt mod p, implements the Tonelli-Shanks algorithm (https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm)
 * @param {Fp} val
 * @param {bool *} valid
 * @param {Fp} n (a pre-computed non-quadratic reside mod p) //need to find a better way to pass in this info
 * @return {Fp} a value in Fp
 * TODO: simplify (reorganize) function
 */
static Fp sqrt_p(Fp val, bool *valid, Fp n){
  if(val == 0 || Param::p == 2) {
    *valid = true;
    return val;
  }
  if(pow_p(val, (Param::p - 1)/2) == -1) { //val is a quadratic nonresidue mod p
    *valid = false;
    return -1;
  }
  *valid = true;
  mie::Vuint s;
  const mie::Vuint r = ord2(Param::p - 1, &s);
  Fp y = pow_p(val, (s+1)/2);
  if(r == 1) return y; //p % 4 = 3
  Fp m = pow_p(n, s); //n^s (generater of the 2-sylow subgroup of Z_p)
  Fp b = pow_p(val, s);
  mie::Vuint twopowr = 1;
  for(mie::Vuint i = 0; i < r; i += 1) twopowr = twopowr * 2;
  mie::Vuint count = 1;
  Fp z = m;
  while(count < twopowr){
    if(z * z == b) return y/z;
    z *= m;
    count += 1;
  }
  *valid = false;
  cerr << "Some error occured." << endl;
  return -1;
}

/* Function: randNonQR_p
 * @return {Fp} a random nonquadratic residue of p
 * (actually this is not random, perhaps the name should be changed)
 */
static Fp randNonQR_p(){
  if(Param::p == 2 || Param::p % 4 == 3) return 0; //always have QR here (this result won't be used anyway)
  if(Param::p % 8 == 5) return Fp(2);
  Fp result = 0;
  const mie::Vuint e((Param::p - 1)/2);
  for(int i = 0; i < Param::p; ++i){ //change the upper bound to sqrt(p)
    result += 1;
    if(pow_p(result, e) != 1) return result;
  }
  return 0;
}

/* Function: prepend_p
 * @param {mie::Vuint} val
 * @param {mie::Vuint} numDigits (binary length val)
 * @param {unsigned long} pre (to be prepended)
 * @return {Fp} the prepended value (1|val) % p, in Fp
 */
static Fp prepend_p(const mie::Vuint val, const mie::Vuint numDigits, unsigned long pre){
  Fp result(val % Param::p);
  return result += Fp(pre % Param::p) * pow_p(2, numDigits);
}

/* Function: hash_msg
 * hash message onto curve: h = H(M) \in G_1
 * @param {char*} msg
 * @return {Ec1} point in G_1
 */
Ec1 hash_msg(const char *msg) {
  bn::CurveParam cp = bn::CurveFp254BNb;
  Param::init(cp);
  Fp nonQR_p = randNonQR_p();
  Ec1 hashed_msg_point;
  unsigned long count = 0; //32-bit field
  bool squareRootExists = false;
  while(!squareRootExists){
    string xString = "0x" + sha256(msg);
    const mie::Vuint xVuintSHA256(xString);
    const mie::Vuint xVuint = xVuintSHA256 >> 1;
    const mie::Vuint numDigits = nbits(xVuint); //TODO: optimize it, don't have to find this each time
    Fp x = prepend_p(xVuint, numDigits, count); //what to do if doesn't work for any count?
    Fp x3plusb = x * x * x + cp.b;
    Fp y = sqrt_p(x3plusb, &squareRootExists, nonQR_p);
    if(xVuintSHA256 % 2 != 0) y = -y; //first bit as sign
    if(squareRootExists){
      const Ec1 result(x, y);
      return result;
    } else {
      ++count;
      if(count == ULONG_MAX) break;
    }
  }
  cerr << "This point should not have been reached \n";
}


/*
 * @param {char* } rand_seed, string representation of 256 bit int
 * @return {Ec2}  public key point
 * public_key = g2 ^ secret_key
 */
Ec2 Bls::gen_key(const char *rand_seed) {
  // convert seed into Variable sized uint
  // TODO, test that this conversion works properly
  const mie::Vuint secret_key(rand_seed);

  // Multiply generator by pk
  Ec2 public_key_point = g2 * secret_key;

  // TODO, determine data structure to return
  // Should probably return struct or array
  // Perhaps this method should just return the
  // pubkey and should take as input the private key
  // so that can be generated by whatever means possible
  return public_key_point;
}


/* Function: aggregate_sigs()
 * Multiply signatures together to create aggregate signature
 * @param {std::vector<Ec1>*} sigs
 * @returns {Ec1} aggregate signature
 */
Ec1 Bls::aggregate_sigs(const std::vector<Ec1>& sigs) {
  // multiply all signatures together
  Ec1 sig_product = sigs[0];

  for(size_t i=1; i < sigs.size(); i++) {
    // TODO, should this be addition here? Ask Dan
    sig_product = sig_product + sigs[i];
  }
  return sig_product;
}

/* Function: verify_sig
 * @param {Ec2} pubkey  point in G2 representing the pubkey
 * @param {char*} msg  the message that was signed
 * @param {Ec1} sig  the point in G1 representing the signature
 */
bool Bls::verify_sig(Ec2 const &pubkey, const char* msg, Ec1 const &sig) {
  Fp12 pairing_1; // e(g, H(m)^pk)
  Fp12 pairing_2; // e(g^pk, H(m))

  // ~760 us
  Ec1 hashed_msg_point = hash_msg(msg);

  // check pairing equality
  // e(g, H(m)^alpha) == e(g^alpha (pubkey), H(m)) 

  // ~510 us
  opt_atePairing(pairing_1, g2, sig);

  // ~530 us
  opt_atePairing(pairing_2, pubkey, g1);

  // return pairing_1 == pairing_2;
  return true;
}

/* Function: sign_msg
 * Sign message with secret key
 * @param {char*} msg  message to be signed
 * @param {char*} secret_key  integer string represenation of secret key
 */
Ec1 Bls::sign_msg(const char *msg, const char *secret_key_str) {
  const mie::Vuint secret_key(secret_key_str);

  Ec1 hashed_msg_point = hash_msg(msg);

  return hashed_msg_point * secret_key;
}

/* Function: verify_agg_sig()
 * Verify aggregate signature for n pubkey, msg pairs
 * Each message must be distinct
 * @param {vector<char*>*} Vector containing pubkeys used in aggregate signature
 * @param {vector<char*>*} Vector containing messages used in aggregate signature
 * @param {Ec1 sig} Point in G1 representing aggregate signature
 */
bool Bls::verify_agg_sig(std::vector<char*>& messages, std::vector<Ec2>& pubkeys, Ec1 sig) {

  Fp12 pairing_agg;

  // check that same number of messages and pubkeys
  if(messages.size() != pubkeys.size()) {
    return false;
  }

  // calculate initial pairing
  Fp12 pairing_sum;
  Ec1 hashed_msg_point = hash_msg(messages[0]);
  opt_atePairing(pairing_sum, pubkeys[0], hashed_msg_point);

  // Set for checking that all messages are unique
  std::vector<Ec1> hashed_msgs;

  for(size_t i=1; i < messages.size(); i++) {
    Fp12 pairing_i;
    char *msg = messages[i];
    Ec2 pubkey = pubkeys[i];
    Ec1 hashed_msg_point = hash_msg(msg);

    // verify all messages are distinct
    if(std::find(hashed_msgs.begin(), hashed_msgs.end(), hashed_msg_point) != hashed_msgs.end()) {
      cout << "Duplicate messages given!\n";
      return false;
    }

    hashed_msgs.push_back(hashed_msg_point);
    opt_atePairing(pairing_i, pubkey, hashed_msg_point);
    pairing_sum += pairing_i;
  }

  return pairing_agg == pairing_sum;
}

/* Function: verify_threshold_sig
 * @param {char*} msg
 * @param {char*} sig
 * @return {bool} check that threshold signature is valid
 */
bool Bls::verify_threshold_sig(const char* msg) {
  // TODO, implement
  return true;
}