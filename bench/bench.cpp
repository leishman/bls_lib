#include "bls.h"
#include <sys/time.h>

int its = 1000;

void run_bench() {
  Bls my_bls = Bls();
  const char *seed = "15267802884793550383558706039165621050290089775961208824303765753922461897946";
  Ec2 pubkey = my_bls.gen_key(seed);
  const char *msg = "That's how the cookie crumbles";

  struct timeval timeStart,
                timeEnd;


  Ec1 my_sig = my_bls.sign_msg(msg, seed);

  gettimeofday(&timeStart, NULL);

  // Test validation speed
  bool sigValid = true;
  for(int i=0; i<its; i++) {
    my_bls.verify_sig(pubkey, msg, my_sig);
  }

  gettimeofday(&timeEnd, NULL);

  std::cout << "Execution Time (microseconds)";
  std::cout << ((timeEnd.tv_sec - timeStart.tv_sec) * 1000000 + timeEnd.tv_usec - timeStart.tv_usec) / its;
  std::cout << std::endl;
  // printf(sigValid ? "true\n" : "false\n");
}

int main() {
  run_bench();
  return 0;
}