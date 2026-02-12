// hash_utils.cpp - Hash function implementations
#include "hash_utils.h"
#include <openssl/evp.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

static Bytes sha256(const Bytes& input) {
    Bytes hash(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), &len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA256 failed");
    }
    
    EVP_MD_CTX_free(ctx);
    hash.resize(len);
    return hash;
}

HashVal HashUtils::H(const HashVal& left, const HashVal& right, const HashVal& bitmask) {
    Bytes concat = left;
    concat.insert(concat.end(), right.begin(), right.end());
    return sha256(xor_bytes(concat, bitmask));
}

HashVal HashUtils::F(const Bytes& key, const HashVal& input) {
    Bytes data = key;
    data.insert(data.end(), input.begin(), input.end());
    return sha256(data);
}

HashVal HashUtils::hash(const Bytes& data) {
    return sha256(data);
}

HashVal HashUtils::xor_bytes(const HashVal& a, const HashVal& b) {
    HashVal res(a.size());
    for (size_t i = 0; i < a.size(); ++i) res[i] = a[i] ^ b[i];
    return res;
}

std::string HashUtils::to_hex(const Bytes& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (byte b : data) ss << std::setw(2) << (int)b;
    return ss.str();
}

Bytes HashUtils::from_hex(const std::string& hex) {
    Bytes bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        bytes.push_back((byte)strtol(hex.substr(i, 2).c_str(), nullptr, 16));
    }
    return bytes;
}