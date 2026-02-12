# X-VRF Implementation

XMSS-based Verifiable Random Function using WOTS+ signatures and Merkle trees.

## Build

```bash
make
```

## Run

```bash
./xvrf
```

## Usage

Interactive CLI with three operations:

```
1) KeyGen   - Generate key pair
2) Eval     - Compute VRF output
3) Verify   - Verify VRF output
4) Exit
```

### KeyGen

Generates a Merkle tree of WOTS+ key pairs.

- **Input:** Tree height h (1-20)
- **Output:** Public key (root), secret seed
- Supports 2^h evaluations (h=4 → 16, h=10 → 1024)

### Eval

Evaluates VRF on a message.

- **Input:** Message (hex or ASCII, any length)
- **Output:** VRF output y, proof (WOTS+ signature + auth path)
- Messages padded/truncated to 32 bytes
- Each eval uses one leaf (stateful)

### Verify

Verifies VRF output against public key.

- **Input:** Public key (64 hex), message, VRF output (64 hex)
- Reconstructs WOTS+ pk from signature
- Recomputes Merkle root via auth path
- Checks y = H(σ || msg)

## Parameters

| Param | Value | Description |
|-------|-------|-------------|
| LAMBDA | 32 | Security (256 bits) |
| W | 16 | Winternitz param |
| L_WOTS | 67 | WOTS+ chains (64+3) |

## Files

| File | Purpose |
|------|---------|
| params.h | Constants |
| hash_utils | SHA256 wrappers |
| prg | HMAC-based PRG |
| wots | WOTS+ signatures |
| xmss_core | Merkle tree ops |
| simple_xmss | X-VRF core |
| main.cpp | CLI |

## Clean

```bash
make clean
```
