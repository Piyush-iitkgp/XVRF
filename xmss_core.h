// xmss_core.h - Merkle tree operations
#ifndef XVRF_XMSS_CORE_H
#define XVRF_XMSS_CORE_H

#include "params.h"
#include <vector>

class XMSSCore {
public:
    // Compress WOTS+ public key to single leaf using L-tree
    static HashVal l_tree(const std::vector<HashVal>& wots_pk,
                          const std::vector<HashVal>& bitmasks);

    // Build Merkle tree from leaves, return root
    static HashVal tree_hash(const std::vector<HashVal>& leaves,
                             const std::vector<HashVal>& bitmasks);

    // Compute root from leaf and authentication path
    static HashVal auth_to_root(const HashVal& leaf,
                                const std::vector<HashVal>& auth_path,
                                uint32_t index,
                                const std::vector<HashVal>& bitmasks);

    // Get authentication path for a leaf
    static std::vector<HashVal> get_auth_path(const std::vector<HashVal>& leaves,
                                              uint32_t index,
                                              const std::vector<HashVal>& bitmasks);
};

#endif