// simple_xmss.h - XM-VRF Core Implementation (Paper Section 3: Construction of XM-VRF from XMSS)
// Implements the multi-layer Verifiable Random Function as described in:
// "XM-VRF: Forward Secure, Fast and Key Updatable Hash Based Verifiable Random Function"
// by Suman Ghosh, Ratna Dutta, and Sourav Mukhopadhyay (IIT Kharagpur)
// Supports d layers of XMSS trees, each of height h' = h/d (Paper Section 1.2)

#ifndef XVRF_SIMPLE_XMSS_H
#define XVRF_SIMPLE_XMSS_H

#include "params.h"
#include "wots.h"
#include "xmss_core.h"
#include <vector>

// VRFProof: Proof structure πXM-VRF (defined in Paper Section 3.1, Algorithm Verify)
// Contains cryptographic proof that VRF output is correctly computed for all d layers
// - indices: Leaf index for each layer (used to identify which WOTS+ key was used)
// - wots_sigs: WOTS+ signature at each layer (σ0, σ1, ..., σd−1 in paper)
// - auth_paths: Authentication path from leaf to root for each layer (Auth0, Auth1, ..., Authd−1)
// Multi-layer structure: Layer 0 proves input was signed, Layer i>0 proves layer i−1 root was signed
struct VRFProof {
    std::vector<uint32_t> indices;                 // indices[i] = index in layer i
    std::vector<std::vector<Bytes>> wots_sigs;     // wots_sigs[i] = signature σi
    std::vector<std::vector<HashVal>> auth_paths;  // auth_paths[i] = authentication path Authi
};

// XVRF: XM-VRF implementation from Paper Section 3 (ParamGen, KeyGen, Eval, Verify algorithms)
// Unified class implementing both X-VRF (d=1, single layer) and X-MVRF (d>1, multiple layers)
// Architecture (Paper Section 1.2, 3):
//   - d independent XMSS trees of height h' = h/d each
//   - Layer 0 (bottom): Signs the input message with WOTS+
//   - Layer i>0: Signs the root of Layer i−1 with WOTS+
//   - Top layer root is stored in verification key vkXM-VRF
// Message chaining: Each layer passes its signature as input to the next layer (Paper Section 1.2)
class XVRF {
private:
    // Key material and configuration
    Bytes sk_seed;                           // Master secret seed (32 bytes)
    uint32_t d;                              // Number of layers
    std::vector<uint32_t> heights;           // Height of each Merkle tree layer
    uint32_t idx;                            // Current evaluation counter
    
    // Core structures
    HashVal root;                            // Public key (root of top layer)
    std::vector<HashVal> bitmasks;           // Bitmasks for all layers (XOR randomization)
    std::vector<std::vector<HashVal>> layer_leaves;  // Leaf nodes for each layer

    // Helper function: Derive deterministic seed for (layer, position)
    // Paper Section 1.2: Uses stateful forward-secure PRG to generate WOTS+ key pairs sequentially
    // Formula: seed(layer, position) = H(sk_seed || layer_id || position_id)
    Bytes derive_seed(uint32_t layer, uint32_t i) const;

public:
    // Constructor: Initialize XVRF (part of ParamGen and KeyGen setup)
    // Builds the internal structures for d layers with given heights
    // Paper Section 3.1 KeyGen (step i): Initializes random seeds Scur,i for current trees
    XVRF(const std::vector<uint32_t>& h, const Bytes& seed);

    // Key generation: XM-VRF.KeyGen algorithm from Paper Section 3.1
    // Builds d independent XMSS trees using TreeHash (Algorithm 3)
    // For each layer: generates 2^(h/d) WOTS+ keys, applies L-tree, builds tree
    // Output: vkXM-VRF (root of top tree), skXM-VRF (seeds and signatures)
    void keygen();

    // Evaluation: XM-VRF.Eval algorithm from Paper Section 3.1
    // Step ii: Signs input message with WOTS+ at Layer 0
    // Step iii: For each layer i>0, signs root of layer i−1 with WOTS+
    // Output: yXM-VRF = H1(Σ, x), proof πXM-VRF = (σ0, Auth0, σ1, Auth1, ..., σd−1, Authd−1)
    // Returns false if tree exhausted (after 2^h evaluations)
    bool eval(const Bytes& msg, HashVal& y, VRFProof& proof);

    // Verification: XM-VRF.Verify algorithm from Paper Section 3.1
    // Step i: Parses proof πXM-VRF = (σ0, Auth0, σ1, Auth1, ..., σd−1, Authd−1)
    // Step ii-iii: Reconstructs WOTS+ public key pk(j) from σj using Algorithm 6 (WOTS+PKfromSign)
    //              Computes root xj+1 using L-tree and Auth2Root (Algorithm 5)
    // Step iv: Verifies xd == vkXM-VRF (top layer root matches)
    // Step v: Verifies yXM-VRF == H1(πXM-VRF, x)
    static bool verify(const HashVal& pk, const Bytes& msg, const HashVal& y,
                       const VRFProof& proof, uint32_t d,
                       const std::vector<HashVal>& bitmasks,
                       const std::vector<Bytes>& r, const Bytes& key);

    // Accessors: Get components of vkXM-VRF and internal state
    HashVal get_pk() const { return root; }  // Get verification key vkXM-VRF (root of top layer)
    std::vector<HashVal> get_bitmasks() const { return bitmasks; }  // Bitmasks used in Algorithm Verify Step i
    uint32_t get_idx() const { return idx; }  // Get current evaluation counter
    uint32_t get_height() const { return heights[0]; }  // Get height of one layer (h' = h/d)
};

// Type alias: XMVRF is equivalent to XVRF (same implementation)
typedef XVRF XMVRF;

#endif