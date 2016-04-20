#include "bls.h"
#include <sys/time.h>
using namespace bls;


int its = 1000;

void run_bench() {
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
  // for(int i=0; i<its; i++) {
    sigValid = my_bls.verifySig(pubkey, msg, my_sig);
  // }
  printf(sigValid ? "Success\n" : "Failure\n");

  gettimeofday(&timeEnd, NULL);

  std::cout << "Execution Time (microseconds)";
  std::cout << ((timeEnd.tv_sec - timeStart.tv_sec) * 1000000 + timeEnd.tv_usec - timeStart.tv_usec) / its;
  std::cout << std::endl;
  // printf(sigValid ? "true\n" : "false\n");
}

void run_bench_agg() {
  Bls my_bls = Bls();

  std::vector<const char*> seeds;

  seeds.push_back("1232334");
  seeds.push_back("456237");
  seeds.push_back("8010121");

  PubKey pk_1 = my_bls.genPubKey(seeds[0]);
  PubKey pk_2 = my_bls.genPubKey(seeds[1]);
  PubKey pk_3 = my_bls.genPubKey(seeds[2]);

  std::string m1 = "That's how the cookie crumbles";
  std::string m2 = "This is a new message";
  std::string m3 = "This is another new message";

  std::vector<const char*> msgs;
  msgs.push_back(m1.c_str());
  msgs.push_back(m2.c_str());
  msgs.push_back(m3.c_str());

  std::vector<PubKey> pubkeys;

  pubkeys.push_back(pk_1);
  pubkeys.push_back(pk_2);
  pubkeys.push_back(pk_3);

  std::vector<Sig> sigs;

  // Sign each message and store signature in array
  for(int i=0; i < msgs.size(); i++) {
    const char* m = msgs[i];
    Sig sig = my_bls.signMsg(m, seeds[i], pubkeys[i]);
    sigs.push_back(sig);
  }

  Sig agg_sig = my_bls.aggregateSigs(sigs);

  bool result = my_bls.verifyAggSig(msgs, pubkeys, agg_sig);
  printf(result ? "Success\n" : "Failure\n");
}

void run_test() {
  // Test suite outline
  //   Test individual signatures ()

  Bls my_bls = Bls();

  std::vector<const char*> seeds;

  seeds.push_back("123233232234234334");
  seeds.push_back("4562124122342343137");
  seeds.push_back("80101211231231231234135");

  PubKey pk_1 = my_bls.genPubKey(seeds[0]);
  PubKey pk_2 = my_bls.genPubKey(seeds[1]);
  PubKey pk_3 = my_bls.genPubKey(seeds[2]);

  std::string m1 = "That's how the cookie crumbles";
  std::string m2 = "That's how the cookie crumblesapa";
  std::string m3 = "That's how the cookie crumbles";

  std::vector<const char*> msgs;
  msgs.push_back(m1.c_str());
  msgs.push_back(m2.c_str());
  msgs.push_back(m3.c_str());

  std::vector<PubKey> pubkeys;

  pubkeys.push_back(pk_1);
  pubkeys.push_back(pk_2);
  pubkeys.push_back(pk_3);

  std::vector<Sig> sigs;

  // Sign each message and store signature in array
  for(int i=0; i < msgs.size(); i++) {
    const char* m = msgs[i];
    Sig sig = my_bls.signMsg(m, seeds[i], pubkeys[i]);
    sigs.push_back(sig);
  }

  Sig agg_sig = my_bls.aggregateSigs(sigs);

  bool result = my_bls.verifyAggSig(msgs, pubkeys, agg_sig);
  printf(result ? "Success\n" : "Failure\n");
}

int main() {
  run_bench();
  // run_bench_agg();
  run_test();
  return 0;
}