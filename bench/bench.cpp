#include "bls.h"
#include <sys/time.h>

int its = 1000;

void run_bench() {
  Bls my_bls = Bls();
  const char *seed = "15267802884793550383558706039165621050290089775961208824303765753922461897946";

  // const char *seed = "2342342342";
  Ec2 pubkey = my_bls.gen_key(seed);
  const char *msg = "That's how the cookie crumbles";

  struct timeval timeStart,
                timeEnd;


  Ec1 my_sig = my_bls.sign_msg(msg, seed);

  gettimeofday(&timeStart, NULL);

  // Test validation speed
  bool sigValid = true;
  // for(int i=0; i<its; i++) {
    sigValid = my_bls.verify_sig(pubkey, msg, my_sig);
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

  Ec2 pk_1 = my_bls.gen_key(seeds[0]);
  Ec2 pk_2 = my_bls.gen_key(seeds[1]);
  Ec2 pk_3 = my_bls.gen_key(seeds[2]);

  std::string m1 = "That's how the cookie crumbles";
  std::string m2 = "This is a new message";
  std::string m3 = "This is another new message";

  std::vector<const char*> msgs;
  msgs.push_back(m1.c_str());
  msgs.push_back(m2.c_str());
  msgs.push_back(m3.c_str());

  std::vector<Ec2> pubkeys;

  pubkeys.push_back(pk_1);
  pubkeys.push_back(pk_2);
  pubkeys.push_back(pk_3);

  std::vector<Ec1> sigs;

  // Sign each message and store signature in array
  for(int i=0; i < msgs.size(); i++) {
    const char* m = msgs[i];
    Ec1 sig = my_bls.sign_msg(m, seeds[i]);
    sigs.push_back(sig);
  }

  Ec1 agg_sig = my_bls.aggregate_sigs(sigs);

  bool result = my_bls.verify_agg_sig(msgs, pubkeys, agg_sig);
  printf(result ? "Success\n" : "Failure\n");
}

int main() {
  // run_bench();
  run_bench_agg();
  return 0;
}