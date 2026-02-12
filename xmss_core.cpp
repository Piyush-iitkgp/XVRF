// xmss_core.cpp - Merkle tree implementation
#include "xmss_core.h"
#include "hash_utils.h"
#include <stack>
#include <stdexcept>

HashVal XMSSCore::l_tree(const std::vector<HashVal>& wots_pk,
                         const std::vector<HashVal>& bitmasks) {
    std::vector<HashVal> layer = wots_pk;
    int h = 0;

    while (layer.size() > 1) {
        std::vector<HashVal> next;
        for (size_t i = 0; i < layer.size(); i += 2) {
            if (i + 1 < layer.size()) {
                next.push_back(HashUtils::H(layer[i], layer[i+1], bitmasks[h]));
            } else {
                next.push_back(layer[i]); // Odd node lifted
            }
        }
        layer = next;
        h++;
    }
    return layer[0];
}

HashVal XMSSCore::tree_hash(const std::vector<HashVal>& leaves,
                            const std::vector<HashVal>& bitmasks) {
    struct Node { HashVal hash; int height; };
    std::stack<Node> stk;

    for (const auto& leaf : leaves) {
        Node node = {leaf, 0};
        while (!stk.empty() && stk.top().height == node.height) {
            Node left = stk.top(); stk.pop();
            node = {HashUtils::H(left.hash, node.hash, bitmasks[node.height]), node.height + 1};
        }
        stk.push(node);
    }

    if (stk.size() != 1) throw std::runtime_error("Leaves must be power of 2");
    return stk.top().hash;
}

HashVal XMSSCore::auth_to_root(const HashVal& leaf,
                               const std::vector<HashVal>& auth_path,
                               uint32_t index,
                               const std::vector<HashVal>& bitmasks) {
    HashVal curr = leaf;
    for (size_t h = 0; h < auth_path.size(); h++) {
        if ((index >> h) % 2 == 0)
            curr = HashUtils::H(curr, auth_path[h], bitmasks[h]);
        else
            curr = HashUtils::H(auth_path[h], curr, bitmasks[h]);
    }
    return curr;
}

static void build_auth_path(const std::vector<HashVal>& layer, uint32_t idx, int h,
                            const std::vector<HashVal>& bm, std::vector<HashVal>& path) {
    if (layer.size() == 1) return;
    std::vector<HashVal> next;
    for (size_t i = 0; i < layer.size(); i += 2) {
        if (i == idx || i + 1 == idx)
            path.push_back((i == idx) ? layer[i+1] : layer[i]);
        next.push_back(HashUtils::H(layer[i], layer[i+1], bm[h]));
    }
    build_auth_path(next, idx / 2, h + 1, bm, path);
}

std::vector<HashVal> XMSSCore::get_auth_path(const std::vector<HashVal>& leaves,
                                             uint32_t index,
                                             const std::vector<HashVal>& bitmasks) {
    std::vector<HashVal> path;
    build_auth_path(leaves, index, 0, bitmasks, path);
    return path;
}