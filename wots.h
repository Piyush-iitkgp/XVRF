// wots.h - WOTS+ One-Time Signature
#ifndef XVRF_WOTS_H
#define XVRF_WOTS_H

#include "params.h"
#include <vector>

class WOTS {
public:
    // Convert message to base-w chain lengths (with checksum)
    static std::vector<int> chain_lengths(const Bytes& msg);

    // Chain function: apply F_k 'steps' times with randomization
    static Bytes chain(const Bytes& input, int start, int steps,
                       const std::vector<Bytes>& r, const Bytes& key);

    // Generate public key from secret seed
    static std::vector<Bytes> gen_pk(const Bytes& sk_seed,
                                     const std::vector<Bytes>& r,
                                     const Bytes& key);

    // Sign message
    static std::vector<Bytes> sign(const Bytes& msg, const Bytes& sk_seed,
                                   const std::vector<Bytes>& r,
                                   const Bytes& key);

    // Reconstruct public key from signature
    static std::vector<Bytes> pk_from_sig(const Bytes& msg,
                                          const std::vector<Bytes>& sig,
                                          const std::vector<Bytes>& r,
                                          const Bytes& key);
};

#endif