#include "bls.h"
#include "test_point.hpp"

using namespace std;
using namespace bn;

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
 * @return {Fp} a value in Fp
 */
static Fp sqrt_p(Fp val, bool *valid){
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
  if(r == 1) return pow_p(val, (s+1)/2); //p % 4 = 3
  Fp n = (Param::p % 8 == 5) ? 2 : 2; //quadratic nonresidue (TODO: handle else case)
  Fp m = pow_p(n, s); //generator of the 2-sylow subgroup of Z_p^*
  Fp b = pow_p(2, s); //ordp_b < ordp_m
  mie::Vuint ordp_m = mie::power(2, r);
  mie::Vuint ordp_b = mie::power(2, r-1);
  while(pow_p(b, ordp_b) == 1) ordp_b /= 2;
  ordp_b *= 2;
  Fp result = 1;
  while(b != 1){
    //find lowest i such that pow_p(b, 2^i) = 1
  //result
  }
  return m;
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
  Ec1 hashed_msg_point;
  unsigned long count = 0; //32-bit field
  bool squareRootExists = false;
  while(!squareRootExists){
    string xString = "0x" + sha256(msg);
    const mie::Vuint xVuintSHA256(xString);
    const mie::Vuint xVuint = xVuintSHA256 >> 1;
    Fp sign(2 *(xVuintSHA256 % 2) - 1); //first bit as sign
    const mie::Vuint numDigits = nbits(xVuint); //TODO: optimize it, don't have to find this each time
    Fp x = prepend_p(xVuint, numDigits, count); //what to do if doesn't work for any count?
    Fp x3plusb = x * x * x + cp.b;
    Fp y = sqrt_p(x3plusb, &squareRootExists);
    if(xVuintSHA256 % 2 != 0) y = -y;
    if(squareRootExists){
      const Ec1 result(x, y);
      return result;
    } else {
      ++count;
      if(count == ULONG_MAX){
        cerr << "Not-hashable, 32-bit unsigned count overflowed" << endl;
      }
    }
  }
  /*Dummy code just to complete the function*/
  const Point& pt = selectPoint(cp);
  const Ec1 g1(pt.g1.a, pt.g1.b); // get g1
  const mie::Vuint rand_msg_mult(rand());
  hashed_msg_point = g1 * rand_msg_mult;
  cerr << "Invalid hash" << endl;
  return hashed_msg_point;
}


/*
 * @param {char* } rand_seed, string representation of 256 bit int
 * @return {Ec2}  public key point
 * public_key = g2 ^ secret_key
 */
Ec2 gen_key(char *rand_seed) {

  bn::CurveParam cp = bn::CurveFp254BNb;
  Param::init(cp);

  const Point& pt = selectPoint(cp);

  // get g2
  const Ec2 g2(
    Fp2(Fp(pt.g2.aa), Fp(pt.g2.ab)),
    Fp2(Fp(pt.g2.ba), Fp(pt.g2.bb))
  );

  // get g1
  const Ec1 g1(pt.g1.a, pt.g1.b);

  // convert seed into Variable sized uint
  // TODO, test that this conversion works properly
  const mie::Vuint secret_key(rand_seed);

  // Multiply generator by pk
  Ec2 public_key_point = g2 * secret_key;

  const char* msg = "my msg";
  Ec1 hashed_msg_point = hash_msg(msg);
  Ec1 signed_msg = hashed_msg_point * secret_key;

  // TEST VALIDATION
  Fp12 pairing_1; // e(g, H(m)^pk)
  Fp12 pairing_2; // e(g^pk, H(m))

  opt_atePairing(pairing_1, g2, signed_msg);
  opt_atePairing(pairing_2, public_key_point, hashed_msg_point);

  if(pairing_1 == pairing_2) {
    printf("It's working");
  } else {
    printf("NOT working");
  }

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
Ec1 aggregate_sigs(const std::vector<Ec1>& sigs) {
  // multiply all signatures together
  Ec1 sig_product = sigs[0];

  for(size_t i=1; i < sigs.size(); i++) {
    // TODO, should this be addition here? Ask Dan
    sig_product = sig_product + sigs[i];
  }
  return sig_product;
}

// TODO: requires hash function

bool verify_sig(char* pubkey, char* msg, Ec1 sig) {
  Fp12 e;

  // hash msg
  bool sig_valid;

  // check pairing equality
  // does equality check need to be special?
  // e(g, H(m)^alpha) == e(g^alpha (pubkey), H(m))


  return sig_valid;
}

/* Function: verify_agg_sig()
 * Verify aggregate signature for n pubkey, msg pairs
 * Each message must be distinct
 *
 */
// bool verify_agg_sig(char* pubkeys[], vector<char*>* msgs, Ec1 sig) {

// }



int main() {

    // Get random number x in Zp
    // Exponentiate g2 by x
    // Return keypair
    // Generate random 256 bit string
    char *seed = "15267802884793550383558706039165621050290089775961208824303765753922461897946";
    gen_key(seed);
    return 0;
}

// TODO

// -Distributed Key Generation
// -Simple BLS Sig
// -Again look at data types here
// -Threshold Signatures
// -Blind Signatures
// - Aggregate signatures
// -Signing Function