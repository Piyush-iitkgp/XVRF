// prg.cpp - PRG implementation using hash-based construction
#include "prg.h"
#include "hash_utils.h"

PRG::PRG(const Bytes& seed) : state(seed) {}

Bytes PRG::next() {
    Bytes input_s = state, input_r = state;
    input_s.push_back(0x00);
    input_r.push_back(0x01);
    state = HashUtils::hash(input_s);
    return HashUtils::hash(input_r);
}