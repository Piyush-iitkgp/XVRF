// params.h - X-VRF Parameters
#ifndef XVRF_PARAMS_H
#define XVRF_PARAMS_H

#include <vector>
#include <cstdint>

// Security parameter (32 bytes = 256 bits)
constexpr size_t LAMBDA = 32;

// Winternitz parameter (w=16 is standard)
constexpr int W = 16;
constexpr int W_LOG = 4;

// Message length (SHA256 output size)
constexpr size_t M_LEN = 32;

// WOTS+ chain counts: l1 = ceil(256/4) = 64, l2 = 3
constexpr int L1 = 64;
constexpr int L2 = 3;
constexpr int L_WOTS = L1 + L2;

// Type aliases
using byte = uint8_t;
using Bytes = std::vector<byte>;
using HashVal = std::vector<byte>;

#endif