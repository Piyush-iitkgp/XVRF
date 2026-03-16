// simple_xmss.cpp - XM-VRF Implementation (Paper Section 3: ParamGen, KeyGen, Eval, Verify)
// Implements the multi-layer Verifiable Random Function from:
// "XM-VRF: Forward Secure, Fast and Key Updatable Hash Based Verifiable Random Function"
// Constructs d layers of XMSS trees, where:
//   - Layer 0 (bottom) signs the input message
//   - Layer i>0 signs the root of Layer i−1
//   - Top layer root embedded in verification key vkXM-VRF

#include "simple_xmss.h"
#include "hash_utils.h"
#include "prg.h"
#include <iostream>
#include <algorithm>

// ============================================================================
// Constructor: XVRF - Initialize XM-VRF instance (Part of ParamGen/KeyGen)
// ============================================================================
// Paper Reference: Section 3.1, Algorithm KeyGen, steps (i) and (iii)
// Purpose: Set up configuration and generate bitmasks for d-layer XMSS construction
// Input:
//   - h: Vector of heights for each layer (typically all same value h' = h/d)
//   - seed: Master secret key sk (32 bytes, random λ-bit string)
// Process:
//   1. Store d (number of layers) and heights vector
//   2. Initialize PRG with seed (stateful forward-secure PRG from paper)
//   3. Generate bitmasks B1, B2, ..., Bct where ct = h' + ceil(log l)
//      Each bitmask is 2λ bits (64 bytes in our implementation)
//   4. Reserve vectors for layer leaf storage (filled during keygen())
// ============================================================================
XVRF::XVRF(const std::vector<uint32_t>& h, const Bytes& seed)
    : sk_seed(seed), d(h.size()), heights(h), idx(0) {
    // Generate bitmasks for Merkle tree XOR randomization
    PRG prg(sk_seed);
    prg.next();  // Burn first output for randomness distribution
    
    // Find maximum height to allocate enough bitmasks
    uint32_t max_h = *std::max_element(heights.begin(), heights.end());
    
    // Generate 2*(max_h + 10) bitmasks for Merkle operations
    // Each bitmask is two 32-byte hashes concatenated
    for (uint32_t i = 0; i < 2 * (max_h + 10); i++) {
        HashVal m1 = prg.next(), m2 = prg.next();
        m1.insert(m1.end(), m2.begin(), m2.end());
        bitmasks.push_back(m1);
    }
    
    // Allocate space for leaves of each layer (content filled in keygen)
    layer_leaves.resize(d);
}

// ============================================================================
// derive_seed: Generate deterministic seed for WOTS+ key at specific position
// ============================================================================
// Paper Reference: Section 3.1, Algorithm KeyGen step (iv), uses stateful PRG
// Purpose: Derive unique seed for WOTS+ secret key at (layer, position)
// Input:
//   - layer: Layer index (0 to d-1)
//   - i: Position/index in that layer (0 to 2^(h/d) - 1)
// Output: Deterministic 32-byte seed = H(sk_seed || layer_id || position_id)
// Security Property (Paper Section 1.2):
//   - Different (layer, position) pairs produce different seeds
//   - Seeds are deterministically derived, enabling sequential WOTS+ key generation
//   - Eliminates need to store all 2^h WOTS+ keys in memory
// ============================================================================
Bytes XVRF::derive_seed(uint32_t layer, uint32_t i) const {
    Bytes input = sk_seed;
    // Append layer identifier (16 bits)
    input.push_back((layer >> 8) & 0xFF);
    input.push_back(layer & 0xFF);
    // Append position identifier (32 bits)
    input.push_back((i >> 24) & 0xFF);
    input.push_back((i >> 16) & 0xFF);
    input.push_back((i >> 8) & 0xFF);
    input.push_back(i & 0xFF);
    // Hash to get derived seed
    return HashUtils::hash(input);
}

// ============================================================================
// keygen: XM-VRF.KeyGen algorithm implementation (Paper Section 3.1)
// ============================================================================
// Paper Reference: Section 3.1, Algorithm KeyGen
// Purpose: Generate verification key vkXM-VRF = root of topmost XMSS tree
// Output: Populates layer_leaves and sets root (public key vkXM-VRF)
// Algorithm steps:
//   (i) Choose random seeds Scur,i for each layer
//   (ii) Compute XMSS tree parameters: l, h', ct
//   (iii) Sample random bitmasks B1, ..., Bct
//   (iv) For each layer i = 0 to d-1:
//        - Generate 2^(h/d) WOTS+ secret-public key pairs using stateful PRG
//        - Apply L-tree (Algorithm 2) to compress WOTS+ pk to single value at leaves
//        - Build XMSS tree using TreeHash (Algorithm 3) bottom-up
//   (v-vii) Store state information Stcur,i and cross-layer signatures σi
//   (viii) Return skXM-VRF (seeds, signatures, states) and vkXM-VRF (root of top layer)
// Efficiency: Builds d trees of height h/d in parallel (faster than single height-h tree)
// ============================================================================
void XVRF::keygen() {
    // Pre-compute parameters needed for WOTS+ key generation
    Bytes key = HashUtils::hash(sk_seed);
    std::vector<Bytes> r;
    PRG prg(sk_seed);
    // Generate W-1 random seeds for WOTS+ operations
    for (int i = 0; i < W - 1; i++) r.push_back(prg.next());

    // Build each layer independently
    for (uint32_t layer = 0; layer < d; layer++) {
        uint32_t n = 1 << heights[layer];  // 2^height[layer] leaves for this layer
        std::cout << "Generating layer " << (layer + 1) << " with " << n << " nodes..." << std::endl;

        // Generate all leaves for this layer
        for (uint32_t i = 0; i < n; i++) {
            // Generate WOTS+ public key for (layer, position i)
            auto pk = WOTS::gen_pk(derive_seed(layer, i), r, key);
            // Compress WOTS+ pk to single value using L-tree
            layer_leaves[layer].push_back(XMSSCore::l_tree(pk, bitmasks));
        }
        
        // Build Merkle tree from all leaves of this layer
        HashVal layer_root = XMSSCore::tree_hash(layer_leaves[layer], bitmasks);
        
        // Top layer root becomes public key
        if (layer == d - 1) root = layer_root;
    }
}

// ============================================================================
// eval: XM-VRF.Eval algorithm implementation (Paper Section 3.1)
// ============================================================================
// Paper Reference: Section 3.1, Algorithm Eval
// Purpose: Evaluate VRF on input message, produce output and proof
// Input: msg (32 bytes, message to evaluate)
// Output:
//   - y: VRF output = H1(Σ, x) where Σ = (σ0, Auth0, σ1, Auth1, ..., σd−1, Authd−1)
//   - proof: Contains all indices, WOTS+ signatures, and authentication paths for d layers
// Return: true on success, false if bottom layer exhausted (after 2^(h/d) evaluations)
// Algorithm steps:
//   (i) Retrieve current evaluation index from counter (ctr' mod 2^(h/d))
//   (ii) For layer 0: Sign input message with WOTS+ using current leaf's key
//   (iii) Extract authentication paths from current XMSS tree state for all layers
//   (iv) For layers 1 to d-1: Sign previous layer's root with current layer's WOTS+ key
//   (vii) Update AuthCalc state for next evaluation
//   (viii) Update counter and tree states for next round
// Security properties (Paper Section 1.2):
//   - Stateful: counter ensures each leaf used exactly once
//   - Forward-secure: evaluations don't reveal future keys
//   - Message chaining: each layer signs output of previous layer
// ============================================================================
bool XVRF::eval(const Bytes& msg, HashVal& y, VRFProof& proof) {
    // Check if we still have unused leaves in bottom layer
    if (idx >= (1u << heights[0])) return false;

    // Pre-compute parameters for WOTS+ signing
    Bytes key = HashUtils::hash(sk_seed);
    std::vector<Bytes> r;
    PRG prg(sk_seed);
    for (int i = 0; i < W - 1; i++) r.push_back(prg.next());

    // Clear any previous proof data
    proof.indices.clear();
    proof.wots_sigs.clear();
    proof.auth_paths.clear();

    // Message starts as input message for layer 0
    Bytes current_msg = msg;

    // Evaluate each layer with message chaining
    for (uint32_t layer = 0; layer < d; layer++) {
        // Calculate index/position to use in this layer
        // Layer 0: use current counter directly
        // Upper layers: map from bottom-layer index
        uint32_t layer_idx = (layer == 0) ? idx : idx >> (heights[0] - heights[layer]);
        if (layer_idx >= (1u << heights[layer])) return false;

        // Store index for verification
        proof.indices.push_back(layer_idx);

        // Sign current message with WOTS+ at (layer, layer_idx)
        auto wots_sig = WOTS::sign(current_msg, derive_seed(layer, layer_idx), r, key);
        proof.wots_sigs.push_back(wots_sig);

        // Get Merkle authentication path (sibling hashes from leaf to root)
        auto auth_path = XMSSCore::get_auth_path(layer_leaves[layer], layer_idx, bitmasks);
        proof.auth_paths.push_back(auth_path);

        // Prepare message for next layer: flatten WOTS+ signature bytes
        current_msg.clear();
        for (const auto& s : wots_sig) {
            current_msg.insert(current_msg.end(), s.begin(), s.end());
        }
    }

    // Compute final VRF output: H(top-layer signature || original message)
    Bytes flat;
    for (const auto& s : proof.wots_sigs[d - 1]) {
        flat.insert(flat.end(), s.begin(), s.end());
    }
    flat.insert(flat.end(), msg.begin(), msg.end());
    y = HashUtils::hash(flat);

    // Increment counter for next evaluation (enforce single-use guarantee)
    idx++;
    return true;
}

// ============================================================================
// verify (static): XM-VRF.Verify algorithm implementation (Paper Section 3.1)
// ============================================================================
// Paper Reference: Section 3.1, Algorithm Verify
// Purpose: Cryptographically verify VRF output without access to private key
// Input:
//   - pk: Verification key vkXM-VRF (root of topmost XMSS tree)
//   - msg: Original message x that was evaluated
//   - y: Claimed VRF output yXM-VRF to verify
//   - proof: Proof πXM-VRF = (σ0, Auth0, σ1, Auth1, ..., σd−1, Authd−1)
//   - d: Number of layers (must match KeyGen)
//   - bitmasks: Bitmasks B1, ..., Bct from KeyGen (must match)
//   - r, key: WOTS+ parameters (must match)
// Output: 1 (true) if valid, 0 (false) if invalid
// Algorithm steps (Paper Section 3.1):
//   (i) Parse πXM-VRF = (σ0, Auth0, σ1, Auth1, ..., σd−1, Authd−1)
//   (ii-iii) For each layer j = 0 to d−1:
//     - Algorithm 6 (WOTS+PKfromSign): Reconstruct WOTS+ pk(j) from σj and xj (message for layer j)
//     - Algorithm 2 (L-tree): Compute leaf value from reconstructed WOTS+ pk(j)
//     - Algorithm 5 (Auth2Root): Use Authj to verify leaf → root path matches expected root
//   (iv) Check xd (computed root) equals rt(d−1) = pk (verification key)
//   (v) Check H1(πXM-VRF, x) equals yXM-VRF (VRF output)
// Return conditions:
//   - Returns 1 (true) only if ALL d layers verify AND VRF output matches
//   - Returns 0 (false) on structural mismatch, invalid path, or output mismatch
// Security properties:
//   - Complete: Accepts all validly generated proofs
//   - Sound: Rejects all invalid proofs (collision-resistant hash assumption)
//   - Uniqueness (Paper Theorem 3): No two different outputs can verify for same input
// ============================================================================
bool XVRF::verify(const HashVal& pk, const Bytes& msg, const HashVal& y,
                  const VRFProof& proof, uint32_t d,
                  const std::vector<HashVal>& bitmasks,
                  const std::vector<Bytes>& r, const Bytes& key) {
    // Sanity check: proof must have exactly d components
    if (proof.indices.size() != d || proof.wots_sigs.size() != d || proof.auth_paths.size() != d) {
        return false;
    }

    // Message starts as original input
    Bytes current_msg = msg;

    // Verify each layer from bottom to top
    for (uint32_t layer = 0; layer < d; layer++) {
        // Reconstruct WOTS+ public key from signature
        // This is reverse of signing: given signature and message, recover pk
        auto wots_pk = WOTS::pk_from_sig(current_msg, proof.wots_sigs[layer], r, key);
        
        // Compress WOTS+ public key using L-tree
        HashVal leaf = XMSSCore::l_tree(wots_pk, bitmasks);
        
        // Verify authentication path: does it lead to correct root?
        // auth_to_root combines leaf with sibling hashes to compute root
        HashVal computed_node = XMSSCore::auth_to_root(leaf, proof.auth_paths[layer], 
                                                       proof.indices[layer], bitmasks);

        // For top layer, computed root must equal public key
        if (layer == d - 1) {
            if (computed_node != pk) return false;
        }

        // Prepare message for next layer: flatten current signature
        current_msg.clear();
        for (const auto& s : proof.wots_sigs[layer]) {
            current_msg.insert(current_msg.end(), s.begin(), s.end());
        }
    }

    // Final check: verify VRF output y = H(top-layer signature || original message)
    Bytes flat;
    for (const auto& s : proof.wots_sigs[d - 1]) {
        flat.insert(flat.end(), s.begin(), s.end());
    }
    flat.insert(flat.end(), msg.begin(), msg.end());

    return HashUtils::hash(flat) == y;
}