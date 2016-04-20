#include "bls.h"
#include <sys/time.h>

// Use Catch for the testing framework
// https://github.com/philsquared/Catch/blob/master/docs/tutorial.md
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

using namespace bls;

TEST_CASE("Message hashes onto curve", "[bls]") {

}

TEST_CASE("Key generation works properly", "[bls]") {
  // pd is 0

  // pk is 1
  Bls my_bls = Bls();
  const char *seed = "1";
  Ec2 pubkey = my_bls.genPubKey(seed).ec2;

  CHECK(pubkey == my_bls.g2);

  // pk is 2
  // pubkey should be g2 * 2 = g2 + g2
  seed = "2";
  pubkey = my_bls.genPubKey(seed).ec2;
  CHECK(pubkey == (my_bls.g2 + my_bls.g2));
  CHECK(pubkey == my_bls.g2 * 2);


  seed = "3";
  pubkey = my_bls.genPubKey(seed).ec2;
  CHECK(pubkey == (my_bls.g2 + my_bls.g2 + my_bls.g2));


  seed = "-234234234234234434";
  CHECK_THROWS(my_bls.genPubKey(seed));

  // seed equal to p
  seed = "16798108731015832284940804142231733909889187121439069848933715426072753864723"; // Param::p
  CHECK_THROWS(my_bls.genPubKey(seed));


  // seed equal to p-1
  seed = "16798108731015832284940804142231733909889187121439069848933715426072753864722";
  pubkey = my_bls.genPubKey(seed).ec2;
  CHECK(pubkey.isValid());
  // pk is just right
}


// Empty String?, null, invalid types, ... think about this one
// TEST_CASE("Refuses to sign invalid messages") {

// }


TEST_CASE("Valid individual signatures are created", "[bls]") {
  // Bls my_bls = Bls();



}

TEST_CASE("Valid aggregate signatures are created", "[bls]") {
  Bls my_bls = Bls();

  const char *seed_1 = "1";
  const char *seed_2 = "2";

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


  Sig sig_1 = my_bls.signMsg(msg_1, seed_1, pubkey_1);
  Sig sig_2 = my_bls.signMsg(msg_2, seed_2, pubkey_2);


  std::vector<Sig> sigs;
  sigs.push_back(sig_1);
  sigs.push_back(sig_2);

  Sig agg_sig = my_bls.aggregateSigs(sigs);

  bool agg_sig_valid = my_bls.verifyAggSig(msgs, pubkeys, agg_sig);
  CHECK(agg_sig_valid);
}

TEST_CASE("Verification does not succeed with corrupted message or key", "[bls]") {
  Bls my_bls = Bls();

  const char *valid_msg = "That's how the cookie crumbles";
  // change one letter
  const char *invalid_msg = "That't how the cookie crumbles";

  // gen keys
  const char *seed = "19283492834298123123";
  PubKey pubkey = my_bls.genPubKey(seed);


  // create sigs
  Sig sig_with_valid_msg = my_bls.signMsg(valid_msg, seed, pubkey);
  Sig sig_with_invalid_msg = my_bls.signMsg(invalid_msg, seed, pubkey);


  bool valid_verify_bool = my_bls.verifySig(pubkey, valid_msg, sig_with_valid_msg);

  // validating msg with signature of "corrupted msg" should not work
  bool invalid_verify_bool = my_bls.verifySig(pubkey, valid_msg, sig_with_invalid_msg);

  CHECK(valid_verify_bool == true);
  CHECK(invalid_verify_bool == false);

  // change one num in seed (corrupt the private key)
  // TODO: change to flip bit instead
  const char *invalid_seed = "19283492834298123124";
  PubKey invalid_pubkey = my_bls.genPubKey(invalid_seed);
  // Sig sig_with_invalid_key = my_bls.signMsg(valid_msg, invalid_seed);

  bool invalid_verify_bool_2 = my_bls.verifySig(invalid_pubkey, valid_msg, sig_with_valid_msg);
  CHECK(invalid_verify_bool == false);
}

TEST_CASE("Verify algebraic properties of signature", "[bls]") {
  Bls my_bls = Bls();

  const char *msg = "That's how the cookie crumbles";
  // change one letter

  // gen keys
  const char *seed = "19283492834298123123";
  PubKey pubkey = my_bls.genPubKey(seed);


  // create sigs
  Sig sig = my_bls.signMsg(msg, seed, pubkey);


  // test that  SIGN(-sk, m) = \sigma^{-1}
  // order of Ec1 = 16798108731015832284940804142231733909759579603404752749028378864165570215949
  mie::Vuint ord("16798108731015832284940804142231733909759579603404752749028378864165570215949");
  Ec1 inv = sig.ec1 * (ord - 1); // sig ^ (ord(Ec1) - 1)
  CHECK(sig.ec1 + inv == sig.ec1 * ord);

  const char *neg_seed ="16798108731015832284940804142231733909759579603404752749009095371331272092826";// "-19283492834298123123" % ord(Ec1) // calculate modular inv

  Ec1 sig_with_neg_key = my_bls.signMsg(msg, neg_seed, pubkey).ec1;
  CHECK(sig_with_neg_key == inv);


  // test that SIGN(sk + 1, m) = H(m) * \sigma
  // TODO: remove hard coded vals
  const char *seed_plus1 = "19283492834298123124"; // "19283492834298123123" + 1
  Ec1 hashed_msg = my_bls.hashMsgWithPubkey(msg, pubkey.ec2);
  Ec1 sig_with_plus1_key = my_bls.signMsg(msg, seed_plus1, pubkey).ec1;
  
  CHECK(sig_with_plus1_key == (hashed_msg + sig.ec1));


  // signing message with SK of 1 should return the original hashed msg
  const char *seed_of_1 = "1";
  const char *msg_of_1 = "That's how the cookie crumbles";
  PubKey pubkey_of_1 = my_bls.genPubKey(seed_of_1);


  Ec1 hashed_msg_of_1 = my_bls.hashMsgWithPubkey(msg_of_1, pubkey_of_1.ec2);
  Ec1 my_sig_of_1 = my_bls.signMsg(msg_of_1, seed_of_1, pubkey_of_1).ec1;
  CHECK(hashed_msg_of_1 == my_sig_of_1);


  // signing message with SK of 2 should NOT return 2*hashed_msg because of pubkey concatenation
  const char *seed_2 = "2";
  PubKey pubkey_of_2 = my_bls.genPubKey(seed_2);
  Sig my_sig_of_2 = my_bls.signMsg(msg_of_1, seed_2, pubkey_of_2);

  // property should not hold
  CHECK_FALSE(hashed_msg_of_1 + hashed_msg_of_1 == my_sig_of_2.ec1);


  // signature should still verify
  CHECK(my_bls.verifySig(pubkey_of_2, msg_of_1, my_sig_of_2));

}

TEST_CASE("Runs benchmarks", "[bench]") {
  // number of iterations to 
  int its = 1000;

  Bls my_bls = Bls();
  const char *seed = "15267802884793550383558706039165621050290089775961208824303765753922461897946";

  // const char *seed = "2342342342";
  PubKey pubkey = my_bls.genPubKey(seed);
  const char *msg = "That's how the cookie crumbles";

  struct timeval timeStart,
                timeEnd;

  Sig my_sig = my_bls.signMsg(msg, seed, pubkey);

  gettimeofday(&timeStart, NULL);

  // Test validation speed
  bool sigValid = true;
  for(int i=0; i<its; i++) {
    sigValid = my_bls.verifySig(pubkey, msg, my_sig);
  }

  gettimeofday(&timeEnd, NULL);

  std::cout << "Average Bls::verifySig Execution Time (microseconds): ";
  std::cout << ((timeEnd.tv_sec - timeStart.tv_sec) * 1000000 + timeEnd.tv_usec - timeStart.tv_usec) / its;
  std::cout << std::endl;
}

TEST_CASE("Serializes and Deserializes Signature Properly", "[bls]") {
  Bls my_bls = Bls();

  std::string seeds[5];
  seeds[0] = "15267802884793550383558706039165621050290089775961208824303765753922461897946";
  seeds[1] = "15267802884793550383558706039165621050290089775961208824303765753922461897945";
  seeds[2] = "9999";
  seeds[3] = "1";
  seeds[4] = "36";

  for(auto seed: seeds) {
    PubKey pubkey = my_bls.genPubKey(seed);

    const char *msg = "That's how the cookie crumbles";

    Sig my_sig = my_bls.signMsg(msg, seed.c_str(), pubkey);

    // Test serialized sig
    Ec1 my_sig_ec1 = my_sig.ec1;

    // CHECK(my_sig.toString() == my_sig_ec1.p[0].toString(10));

    Sig my_deserialized_sig = Sig(my_sig.toString());

    CHECK(my_deserialized_sig.ec1 == my_sig_ec1);
  }
}

// TODO: get serialization for pubkey working properly
TEST_CASE("Serializes and Deserializes PubKey Properly", "[bls]") {
  Bls my_bls = Bls();
  const char *seed = "15267802884793550383558706039165621050290089775961208824303765753922461897946";

  PubKey pubkey = my_bls.genPubKey(seed);
  string strpk = pubkey.toString();
  PubKey newpk = PubKey(strpk.c_str());
  CHECK(false);
}

// TODO: get threshold properly working
TEST_CASE("Threshold KeyGen", "[bls]") {
  Bls my_bls = Bls();
  const char* secret = "12345";
  std::vector<thresholdPoint> points;

  const char* msg = "this is a test message";

  PubKey pubkey = my_bls.genPubKey(secret);

  size_t t = 2;
  my_bls.genThreshKeys(secret, t, 7, points);

  std::vector<thresholdSigPoint> sig_points;
  std::vector<shamirPoint> shamir_points;

  for(uint i=0; i < t; i++) {
    Sig s = my_bls.signMsg(msg, points[i].y.get(), pubkey);
    Fp x = points[i].x;
    sig_points.push_back({x, s});

    shamir_points.push_back({x, points[i].y});
  }

  const char* secret_1 = "4";
  PubKey pubkey_1 = my_bls.genPubKey(secret_1);

  Sig sig_1 = my_bls.signMsg(msg, secret_1, pubkey);

  const char* secret_2 = "5";
  PubKey pubkey_2 = my_bls.genPubKey(secret_2);

  Sig sig_2 = my_bls.signMsg(msg, secret_2, pubkey);

  Sig sig_c = Sig(sig_1.ec1 + sig_2.ec1 * 2);

  const char* secret_3 = "14";
  PubKey pubkey_3 = my_bls.genPubKey(secret_3);

  Sig sig_3 = my_bls.signMsg(msg, secret_3, pubkey);


  // for(uint i=0; i < t; i++) {
  //   Sig s = my_bls.signMsg(msg, points[i].y.get(), pubkey);
  //   Fp x = points[i].x;
  //   cout << "x " << x << endl;
  //   sig_points.push_back({x, s});
  // }

  // cout << "recovered key: " << my_bls.recoverSecret(shamir_points, t) << endl;
  Sig combined_sig = my_bls.combineThresholdSigs(sig_points, t);
  // cout << combined_sig.ec1 << endl;
  // cout << my_bls.signMsg(msg, secret, pubkey).ec1 << endl;
  CHECK(my_bls.verifySig(pubkey, msg, combined_sig));
}

