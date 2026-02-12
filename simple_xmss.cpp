// simple_xmss.cpp - X-VRF implementation
#include "simple_xmss.h"
#include "hash_utils.h"
#include "prg.h"
#include <iostream>

XVRF::XVRF(uint32_t h, const Bytes& seed) : sk_seed(seed), height(h), idx(0) {
    // Generate bitmasks (tree height + L-tree height)
    PRG prg(sk_seed);
    prg.next(); // Burn first output
    for (uint32_t i = 0; i < 2 * (height + 10); i++) {
        HashVal m1 = prg.next(), m2 = prg.next();
        m1.insert(m1.end(), m2.begin(), m2.end());
        bitmasks.push_back(m1);
    }
}

Bytes XVRF::derive_leaf_seed(uint32_t i) const {
    Bytes input = sk_seed;
    input.push_back((i >> 24) & 0xFF);
    input.push_back((i >> 16) & 0xFF);
    input.push_back((i >> 8) & 0xFF);
    input.push_back(i & 0xFF);
    return HashUtils::hash(input);
}

void XVRF::keygen() {
    uint32_t n = 1 << height;
    leaves.clear();

    Bytes key = HashUtils::hash(sk_seed);
    std::vector<Bytes> r;
    PRG prg(sk_seed);
    for (int i = 0; i < W - 1; i++) r.push_back(prg.next());

    std::cout << "Generating " << n << " WOTS keys..." << std::endl;
    for (uint32_t i = 0; i < n; i++) {
        auto pk = WOTS::gen_pk(derive_leaf_seed(i), r, key);
        leaves.push_back(XMSSCore::l_tree(pk, bitmasks));
    }
    root = XMSSCore::tree_hash(leaves, bitmasks);
}

bool XVRF::eval(const Bytes& msg, HashVal& y, VRFProof& proof) {
    if (idx >= (1u << height)) return false;

    Bytes key = HashUtils::hash(sk_seed);
    std::vector<Bytes> r;
    PRG prg(sk_seed);
    for (int i = 0; i < W - 1; i++) r.push_back(prg.next());

    proof.index = idx;
    proof.wots_sig = WOTS::sign(msg, derive_leaf_seed(idx), r, key);
    proof.auth_path = XMSSCore::get_auth_path(leaves, idx, bitmasks);

    // VRF output: y = H(sigma || msg)
    Bytes flat;
    for (const auto& s : proof.wots_sig) flat.insert(flat.end(), s.begin(), s.end());
    flat.insert(flat.end(), msg.begin(), msg.end());
    y = HashUtils::hash(flat);

    idx++;
    return true;
}

bool XVRF::verify(const HashVal& pk, const Bytes& msg, const HashVal& y,
                  const VRFProof& proof, const std::vector<HashVal>& bitmasks,
                  const std::vector<Bytes>& r, const Bytes& key) {
    // Reconstruct WOTS public key from signature
    auto wots_pk = WOTS::pk_from_sig(msg, proof.wots_sig, r, key);
    HashVal leaf = XMSSCore::l_tree(wots_pk, bitmasks);
    HashVal computed_root = XMSSCore::auth_to_root(leaf, proof.auth_path, proof.index, bitmasks);

    if (computed_root != pk) {
        std::cerr << "Root mismatch" << std::endl;
        return false;
    }

    // Verify VRF output
    Bytes flat;
    for (const auto& s : proof.wots_sig) flat.insert(flat.end(), s.begin(), s.end());
    flat.insert(flat.end(), msg.begin(), msg.end());
    if (HashUtils::hash(flat) != y) {
        std::cerr << "VRF output mismatch" << std::endl;
        return false;
    }

    return true;
}