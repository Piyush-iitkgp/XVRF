// hash_utils.h - Hash functions for X-VRF
#ifndef XVRF_HASH_UTILS_H
#define XVRF_HASH_UTILS_H

#include "params.h"
#include <string>

class HashUtils {
public:
    // Tree hash: H(left || right) XOR bitmask
    static HashVal H(const HashVal& left, const HashVal& right, const HashVal& bitmask);

    // Keyed hash: F_k(input) = SHA256(key || input)
    static HashVal F(const Bytes& key, const HashVal& input);

    // General hash
    static HashVal hash(const Bytes& data);

    // XOR two byte vectors
    static HashVal xor_bytes(const HashVal& a, const HashVal& b);

    // Hex conversions
    static std::string to_hex(const Bytes& data);
    static Bytes from_hex(const std::string& hex);
};

#endif