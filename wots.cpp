// wots.cpp - WOTS+ implementation
#include "wots.h"
#include "hash_utils.h"
#include "prg.h"

std::vector<int> WOTS::chain_lengths(const Bytes& msg) {
    std::vector<int> result;
    result.reserve(L_WOTS);

    // Convert message to base-w (nibbles for w=16)
    for (byte b : msg) {
        result.push_back((b >> 4) & 0x0F);
        result.push_back(b & 0x0F);
    }

    // Compute checksum
    uint32_t csum = 0;
    for (int v : result) csum += (W - 1 - v);

    // Append checksum in base-w (L2 digits)
    for (int i = 0; i < L2; i++) {
        result.push_back((csum >> ((L2 - 1 - i) * W_LOG)) & (W - 1));
    }

    return result;
}

Bytes WOTS::chain(const Bytes& input, int start, int steps,
                  const std::vector<Bytes>& r, const Bytes& key) {
    Bytes curr = input;
    for (int i = 0; i < steps; i++) {
        curr = HashUtils::F(key, HashUtils::xor_bytes(curr, r[start + i]));
    }
    return curr;
}

std::vector<Bytes> WOTS::gen_pk(const Bytes& sk_seed,
                                const std::vector<Bytes>& r,
                                const Bytes& key) {
    std::vector<Bytes> pk;
    pk.reserve(L_WOTS);
    PRG prg(sk_seed);
    for (int i = 0; i < L_WOTS; i++) {
        pk.push_back(chain(prg.next(), 0, W - 1, r, key));
    }
    return pk;
}

std::vector<Bytes> WOTS::sign(const Bytes& msg, const Bytes& sk_seed,
                              const std::vector<Bytes>& r, const Bytes& key) {
    std::vector<Bytes> sig;
    sig.reserve(L_WOTS);
    auto lengths = chain_lengths(msg);
    PRG prg(sk_seed);
    for (int i = 0; i < L_WOTS; i++) {
        sig.push_back(chain(prg.next(), 0, lengths[i], r, key));
    }
    return sig;
}

std::vector<Bytes> WOTS::pk_from_sig(const Bytes& msg,
                                     const std::vector<Bytes>& sig,
                                     const std::vector<Bytes>& r,
                                     const Bytes& key) {
    std::vector<Bytes> pk;
    pk.reserve(L_WOTS);
    auto lengths = chain_lengths(msg);
    for (int i = 0; i < L_WOTS; i++) {
        pk.push_back(chain(sig[i], lengths[i], W - 1 - lengths[i], r, key));
    }
    return pk;
}