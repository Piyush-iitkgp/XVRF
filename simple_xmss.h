// simple_xmss.h - X-VRF (XMSS-based VRF without layers)
#ifndef XVRF_SIMPLE_XMSS_H
#define XVRF_SIMPLE_XMSS_H

#include "params.h"
#include "wots.h"
#include "xmss_core.h"
#include <vector>

struct VRFProof {
    uint32_t index;
    std::vector<Bytes> wots_sig;
    std::vector<HashVal> auth_path;
};

class XVRF {
private:
    Bytes sk_seed;
    uint32_t height;
    uint32_t idx;
    HashVal root;
    std::vector<HashVal> bitmasks;
    std::vector<HashVal> leaves;

    Bytes derive_leaf_seed(uint32_t i) const;

public:
    XVRF(uint32_t h, const Bytes& seed);

    // Key generation
    void keygen();

    // Evaluate VRF (outputs y and proof)
    bool eval(const Bytes& msg, HashVal& y, VRFProof& proof);

    // Verify VRF output
    static bool verify(const HashVal& pk, const Bytes& msg, const HashVal& y,
                       const VRFProof& proof, const std::vector<HashVal>& bitmasks,
                       const std::vector<Bytes>& r, const Bytes& key);

    // Accessors
    HashVal get_pk() const { return root; }
    std::vector<HashVal> get_bitmasks() const { return bitmasks; }
    uint32_t get_idx() const { return idx; }
    uint32_t get_height() const { return height; }
};

#endif