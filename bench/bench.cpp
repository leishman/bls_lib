#include "bls.h"

int main() {
  struct timeval timeStart,
                timeEnd;

  gettimeofday(&timeStart, NULL);

  // code to benchmark

  gettimeofday(&timeEnd, NULL);

  std::cout << "Execution Time (microseconds)"
            << ((timeEnd.tv_sec - timeStart.tv_sec) * 1000000 + timeEnd.tv_usec - timeStart.tv_usec))
            << std::endl;
}