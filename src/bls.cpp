#ifndef BLS_LIB
#define BLS_LIB

#include "bls.h"
#include "test_point.hpp"

using namespace std;
using namespace bn;

namespace bls {
  /* 
   * Function: Bls Class constructor
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

  PubKey Bls::genPubKey(const char *seed) {
    // convert seed into Variable sized uint
    mie::Vsint s_secret_key(seed);
    
    // test that rand_seed is within proper limits
    if(s_secret_key <= 0) {
      throw std::invalid_argument("Cannot have zero or negative secret key");
    } else if (s_secret_key >= Param::p) {
      throw std::invalid_argument("Secret key too large");
    }

    mie::Vuint secret_key(s_secret_key.toString());
    return genPubKey(secret_key);
  }

  PubKey Bls::genPubKey(const std::string& seed) {
    return genPubKey(seed.c_str());
  }

  PubKey Bls::genPubKey(mie::Vuint secret_key) {
    // Multiply generator by pk
    Ec2 public_key_point = g2 * secret_key;
    return PubKey(public_key_point);
  }

  Sig Bls::aggregateSigs(const std::vector<Sig>& sigs) {
    Ec1 sig_product = sigs[0].ec1;

    for(size_t i=1; i < sigs.size(); i++) {
      sig_product = sig_product + sigs[i].ec1;
    }

    return Sig(sig_product);
  }

  bool Bls::verifySig(PubKey const &pubkey, const char* msg, Sig const &sig) {
    Fp12 pairing_1; // e(g, H(m)^sk)
    Fp12 pairing_2; // e(g^sk, H(m))

    // ~100 us
    Ec1 hashed_msg_point = hashMsgWithPubkey(msg, pubkey.ec2);

    // check pairing equality
    // e(g, H(m)^alpha) == e(g^alpha (pubkey), H(m)) 

    // ~500 us
    opt_atePairing(pairing_1, g2, sig.ec1);

    // ~500 us
    opt_atePairing(pairing_2, pubkey.ec2, hashed_msg_point);

    return pairing_1 == pairing_2;
  }

  Sig Bls::signMsg(const char *msg, const char *secret_key_str, const PubKey &pubkey) {
    const mie::Vuint secret_key(secret_key_str);
    return signMsg(msg, secret_key, pubkey);
  }

  Sig Bls::signMsg(const char *msg, const mie::Vuint secret_key, const PubKey &pubkey) {
    Ec1 hashed_msg_point = hashMsgWithPubkey(msg, pubkey.ec2);
    return Sig(hashed_msg_point * secret_key);
  }

  Sig Bls::signMsg(std::string& msg, const mie::Vuint secret_key, const PubKey &pubkey) {
    return signMsg(msg.c_str(), secret_key, pubkey);
  }

  bool Bls::verifyAggSig(const std::vector<const char*> &messages, const std::vector<PubKey> &pubkeys, const Sig &sig, bool delay_exp) {
    // check that same number of messages and pubkeys
    if(messages.size() != pubkeys.size()) {
      cerr << "SIZES NOT EQUAL" << endl;
      return false;
    }

    // calculate initial pairing
    Fp12 pairing_prod;
    Ec1 hashed_msg_point = hashMsgWithPubkey(messages[0], pubkeys[0].ec2);
    opt_atePairing(pairing_prod, pubkeys[0].ec2, hashed_msg_point, !delay_exp);

    // Set for checking that all messages are unique
    std::vector<Ec1> hashed_msgs;
    hashed_msgs.push_back(hashed_msg_point);

    for(size_t i=1; i < messages.size(); i++) {
      Fp12 pairing_i;
      Ec1 hashed_msg_point = hashMsgWithPubkey(messages[i], pubkeys[i].ec2);
      Ec2 pubkey = pubkeys[i].ec2;
      hashed_msgs.push_back(hashed_msg_point);
      opt_atePairing(pairing_i, pubkey, hashed_msg_point, !delay_exp);
      pairing_prod *= pairing_i;
    }

    if(delay_exp) {
      pairing_prod.final_exp();
    }

    // calculate pairing with agg signature
    Fp12 pairing_agg;
    opt_atePairing(pairing_agg, g2, sig.ec1);

    return pairing_agg == pairing_prod;
  }

  Ec1 Bls::hashMsgWithPubkey(const char *msg, const Ec2 &pk) {
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest,0,SHA256::DIGEST_SIZE);

    SHA256 ctx = SHA256();
    ctx.init();

    // update with pubkey
    std::string pkstr = pk.p[0].toString();
    ctx.update( (unsigned char*)pkstr.c_str(), pkstr.length() );

    // update with msg
    ctx.update( (unsigned char*)msg, strlen(msg) );

    // calculate final digest
    ctx.final(digest);

    char buf[2*SHA256::DIGEST_SIZE+3];
    // add null terminator to end
    buf[2*SHA256::DIGEST_SIZE] = 0;

    // prepend with 0x
    buf[0] = '0';
    buf[1] = 'x';

    // fill buf with digest
    for (int i = 0; i < SHA256::DIGEST_SIZE; i++) {
      sprintf(buf+(i*2)+2, "%02x", digest[i]);
    }

    //cout << buf << endl;
    // map hash onto curve
    return mapHashOntoCurve(buf);
  } 

  void Bls::genThreshKeys(const char* secret, size_t t, size_t n, std::vector<thresholdPoint>& pair_vec) {
    // generate t-1 random numbers (TODO: do these need to be mod p?)

    // TODO: add error checks
    // vector of random coefficients
    std::vector<mie::Vuint> r_vec(t-1);

    for(uint i=0; i < t-1; i++) {
      // generate random number in Fp
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      // TODO: REMOVE RAND() FROM THIS CODE.
      // THIS IS A PLACEHOLDER ONLY AND IS NOT SECURE and is ONLY A PLACEHOLDER!!!!!!!!!!!
      r_vec[i] = mie::Vuint(random() % 100);
    }

    mie::Vuint s(secret);
    assert(s > 0);

    // calculate n points on curve (x values need not be random) 
    for(uint i=1; i <= n; i++) {
      mie::Vuint res = calcPolynomial(r_vec, s, i);
      pair_vec.push_back({i, Fp(res)});
    }
  }

  Sig Bls::combineThresholdSigs(const std::vector<thresholdSigPoint>& sigs, size_t t) {
    // calculate lambdas
    std::vector<Fp> lambdas;

    // calculate each lambda
    for(size_t j=0; j < t; j++) {
      Fp l_j(1);

      // calculate lambda
      for(size_t m=0; m < t; m++) {
        if(m == j) continue;
        l_j *= (Fp(0) - sigs[m].x) / (sigs[j].x - sigs[m].x);
      }

      // cout << "labmbda: " << l_j << endl;
      lambdas.push_back(l_j);
    }

    Ec1 sig = sigs[0].y.ec1 * lambdas[0].get();
    // cout << "temp sig: " << sig << endl;

    for(size_t i=1; i < lambdas.size(); i++) {
      sig += sigs[i].y.ec1 * lambdas[i].get();
      // cout << "temp sig: " << sig << endl;
    }

    return Sig(sig);
  }

  // Test to see that math checks out
  Fp Bls::recoverSecret(const std::vector<shamirPoint>& points, size_t t) {
    // calculate lambdas
    std::vector<Fp> lambdas;

    // calculate each lambda
    for(size_t j=0; j < t; j++) {
      Fp l_j(1);
      // calculate lambda
      for(size_t m=0; m < t; m++) {
        if(m == j) continue;
        l_j *= (Fp(0) - points[m].x) / (points[j].x - points[m].x);
      }

      lambdas.push_back(l_j);
    }

    Fp sig = points[0].y * lambdas[0];

    for(size_t i=1; i < lambdas.size(); i++) {
      sig += points[i].y * lambdas[i];
    }

    return sig;
  }

  /**********************************************************************
   * Helper Functions for Signature creation and Verification
   **********************************************************************/
  
  const mie::Vuint Bls::nbits(const mie::Vuint val){
    if(val <= 1) return 1;
    return nbits(val / 2) + 1;
  }

  Fp Bls::prependP(const mie::Vuint val, const mie::Vuint num_digits, unsigned long pre){
    Fp result(val % Param::p);
    return result += Fp(pre % Param::p) * mie::power(Fp(2), num_digits);
  }

  Ec1 Bls::mapHashOntoCurve(const char* msg_digest) {
    Ec1 hashed_msg_point;
    unsigned long count = 0; //32-bit field
    bool squareRootExists = false;
    const mie::Vuint xVuintSHA256(msg_digest);
    const mie::Vuint xVuint = xVuintSHA256 >> 1;
    const mie::Vuint numDigits = nbits(xVuint); 
    Fp y;

    while(!squareRootExists) {
      Fp x = prependP(xVuint, numDigits, count); //what to do if doesn't work for any count?
      Fp x3plusb = x * x * x + CURVE_B;
      squareRootExists = Fp::squareRoot(y, x3plusb);
      if(xVuintSHA256 % 2 != 0) y = -y; //first bit as sign
      if(squareRootExists){
        const Ec1 result(x, y);
        return result;
      } else {
        ++count;
        if(count == ULONG_MAX) break;
      }
    }

    // throw error if map fails
    throw("This point should not have been reached \n");
  }

  // y = secret + r_0*x + r_1 * x^2 + r_2 * x^3 ... r_n * x^n
  mie::Vuint Bls::calcPolynomial(std::vector<mie::Vuint>& r_vals, mie::Vuint secret, int x) {
    Fp y(secret);
    for(size_t i=1; i <= r_vals.size(); i++) {
      Fp r_p = Fp(r_vals[i-1]);
      Fp x_p = Fp(x);
      y += r_p * mie::power(x_p, i);
    }
    return y.get();
  }

  /*******************************************
   * Public Containers for Sig and PubKey
   *******************************************/

  Sig::Sig(const char* serializedSig) {
    mie::Vuint xCoord(serializedSig);
    bool y_neg = (xCoord % 2) == 1;

    xCoord >>= 1;

    Fp x = Fp(xCoord);
    Fp y2 = x * x * x + CURVE_B;
    Fp y;

    Fp::squareRoot(y, y2);

    if(y_neg && y.get() % 2 != 1) {
      y = -y;
    }

    ec1 = Ec1(x, y);

    // check that normalization is the right approach here
    ec1.normalize();
  }

  Sig::Sig(string serializedSig) : Sig::Sig(serializedSig.c_str()) {};

  Sig::Sig(Ec1 sig) {
    ec1 = sig;

    //TODO: check that normalization is the right approach here
    ec1.normalize();
  }

  string Sig::toString() {
    mie::Vuint y_coord(ec1.p[1].toString(10));
    mie::Vuint x_coord(ec1.p[0].toString(10));

    x_coord <<= 1;

    if(y_coord % 2 == 1) {
      x_coord += 1; // add flag to indicate negative
    }

    return x_coord.toString(10);
  }

  PubKey::PubKey(const char* serializedPubKey) {
    char* newStr = strdup(serializedPubKey);
    char* token = std::strtok(newStr, "_");

    vector<string> components;
    cout << token << endl;
    while (token != NULL) {
      components.push_back(string(token));
      token = std::strtok(NULL, "_");
    }

    assert(components.size() == 4);
    

    Fp x1 = Fp(components[0]);
    Fp y1 = Fp(components[1]);
    Fp2 x = Fp2(x1, y1);

    Fp x2 = Fp(components[2]);
    Fp y2 = Fp(components[3]);
    Fp2 y = Fp2(x2, y2);
    ec2 = Ec2(x, y);
  }

  PubKey::PubKey(Ec2 pk) {
    pk.normalize();
    ec2 = pk;
  }

  string PubKey::toString() {
    Fp2 x = ec2.p[0];
    Fp2 y = ec2.p[1];
    Fp2 z = ec2.p[2];
    cout << "projective z: " << z << endl;
    std::stringstream s;
    s << x.get()[0] << "_" << x.get()[1] << "_" << y.get()[0] << "_" << y.get()[1];
    return s.str();
  }

  Ec2 PubKey::toEc2() {
    return ec2;
  }
}

#endif
