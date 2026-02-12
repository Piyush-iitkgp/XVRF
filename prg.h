// prg.h - Pseudorandom Generator
#ifndef XVRF_PRG_H
#define XVRF_PRG_H

#include "params.h"

class PRG {
private:
    Bytes state;
public:
    PRG(const Bytes& seed);
    Bytes next();
};

#endif
