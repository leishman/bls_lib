#pragma once
#include "bn.h"

const struct Point {
  struct G2 {
    const char *aa;
    const char *ab;
    const char *ba;
    const char *bb;
  } g2;
  struct G1 {
    int a;
    int b;
  } g1;
} g_pointTbl[] = {
  // Aranha
  {
    {
      "12723517038133731887338407189719511622662176727675373276651903807414909099441",
      "4168783608814932154536427934509895782246573715297911553964171371032945126671",
      "13891744915211034074451795021214165905772212241412891944830863846330766296736",
      "7937318970632701341203597196594272556916396164729705624521405069090520231616",
    },
    {
      -1, 1
    },
  },
};

inline const Point& selectPoint(const bn::CurveParam& cp)
{
  if (cp != bn::CurveFp254BNb) {
    printf("Only CurveFp254BNb supported");
    exit(1);
  }
  return g_pointTbl[0];
}
