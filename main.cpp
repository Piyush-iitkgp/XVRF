// main.cpp - XM-VRF Interactive CLI (Paper Application: Algorand Committee Selection)
// User-friendly command-line interface for XM-VRF cryptographic operations
// Paper: "XM-VRF: Forward Secure, Fast and Key Updatable Hash Based Verifiable Random Function"
// Implements XM-VRF.ParamGen, XM-VRF.KeyGen, XM-VRF.Eval, and XM-VRF.Verify algorithms
// Supports both X-VRF (d=1, single-layer) and X-MVRF (d>1, multi-layer) modes
// Application (Paper Section 4): Random committee selection in Algorand blockchain

#include <iostream>
#include <string>
#include <limits>
#include <algorithm>
#include <chrono>
#include "simple_xmss.h"
#include "hash_utils.h"
#include "prg.h"

using namespace std;
using namespace chrono;

// Global state variables
static XVRF* xvrf = nullptr;              // VRF object for current mode
static bool use_mvrf = false;             // true for multi-layer, false for single
static uint32_t num_layers = 0;           // Number of layers for MVRF
static vector<uint32_t> layer_heights;    // Height of each layer
static Bytes seed;                        // Master seed (kept for verification)
static VRFProof proof;                    // Last proof (for verify operation)

// ============================================================================
// hex2bytes: Convert hex string to bytes
// ============================================================================
// Purpose: Parse hex input (e.g., "48656c6c6f") to binary data
// Input: hex string (pairs of hex digits)
// Output: Bytes vector, empty if invalid
// Example: "aabbcc" → [0xAA, 0xBB, 0xCC]
static Bytes hex2bytes(const string& hex) {
    Bytes out;
    // Process two hex characters at a time
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        // Check if both characters are valid hex digits
        if (!isxdigit(hex[i]) || !isxdigit(hex[i+1])) return {};
        // Convert hex pair to byte
        out.push_back((uint8_t)strtol(hex.substr(i, 2).c_str(), nullptr, 16));
    }
    return out;
}

// ============================================================================
// format_capacity: Format capacity value, handling values > 2^63
// ============================================================================
// Purpose: Display capacity in "2^x (value)" format for all bit widths
// For bits <= 63: compute and display "2^x (actual_value)"
// For bits > 63: display as "2^x" only (cannot compute in 64-bit)
static string format_capacity(uint32_t bits) {
    if (bits > 63) {
        // Cannot represent in 64-bit integer
        return "2^" + to_string(bits);
    }
    if (bits == 63) {
        return "2^63 (" + to_string(1ULL << 63) + ")";
    }
    return "2^" + to_string(bits) + " (" + to_string(1ULL << bits) + ")";
}

// ============================================================================
// sep: Print visual separator line
// ============================================================================
// Purpose: Make CLI output more readable with separator lines
static void sep() { 
    cout << "────────────────────────────────────────────────────────\n"; 
}

// ============================================================================
// mode_selection: Interactive XM-VRF.ParamGen parameter setup (Paper Section 3.1)
// ============================================================================
// Paper Reference: Algorithm ParamGen - Configure public parameters ppXM-VRF
// Purpose: Let user select VRF mode and configure parameters
// Prompts for:
//   - Mode selection: 1=X-VRF (d=1) or 2=X-MVRF (d>1)
//   - For X-MVRF: number of layers d, tree height h for all layers
// Paper parameters set:
//   - m (message length): Fixed at 32 bytes (M_LEN)
//   - w (Winternitz param): Fixed at 16 (W)
//   - λ (security param): Fixed at 32 bytes (LAMBDA)
//   - d (number of layers): User-selectable 1-10
//   - h (total height): Computed as h' × d where h' = user height, d = layers
// Sets global variables: use_mvrf, num_layers, layer_heights
// ============================================================================
static void mode_selection() {
    sep();
    cout << "Select VRF Mode:\n";
    cout << "1) X-VRF (single layer)\n";
    cout << "2) X-MVRF (multi-layer)\n";
    cout << "Choice [1-2]: ";
    int opt; cin >> opt;
    
    if (opt == 1) {
        // X-VRF mode: single layer
        use_mvrf = false;
        num_layers = 1;
    } else if (opt == 2) {
        // X-MVRF mode: multiple layers
        use_mvrf = true;
        
        // Get number of layers
        cout << "Enter number of layers (1-10): ";
        cin >> num_layers;
        if (num_layers < 1 || num_layers > 10) { 
            cout << "Invalid. Setting to 3.\n"; 
            num_layers = 3;
        }
        
        // Get height (same for all layers)
        cout << "Enter height for all layers [1-10]: ";
        int h; cin >> h;
        if (h < 1 || h > 10) h = 4;
        
        // Create layer configuration
        layer_heights.clear();
        for (uint32_t i = 0; i < num_layers; i++) {
            layer_heights.push_back(h);
        }
    } else {
        // Invalid choice, default to X-VRF
        use_mvrf = false;
        num_layers = 1;
    }
}

// ============================================================================
// keygen: XM-VRF.KeyGen algorithm - Generate verification and signing keys
// ============================================================================
// Paper Reference: Algorithm KeyGen, Section 3.1
// Purpose: Execute XM-VRF.KeyGen to generate (skXM-VRF, vkXM-VRF) key pair
// Workflow:
//   1. Choose random master seed sk ∈ {0,1}^λ
//   2. Call XVRF constructor with layer heights and seed
//   3. Execute keygen() to build d XMSS trees of height h/d each
//   4. Output:
//      - vkXM-VRF (verification key): Root of topmost XMSS tree (public)
//      - skXM-VRF (signing key): Seeds and state info (secret)
// Configuration:
//   - For X-VRF mode: d=1, single tree of height h
//   - For X-MVRF mode: d>1, d trees each of height h/d (parallel computation)
// Sets global variables: xvrf (VRF object), seed (master key material)
// Output: Displays public key, seed, layer info, and timing
// ============================================================================
static void keygen() {
    sep();
    
    if (use_mvrf) {
        // X-MVRF key generation
        cout << "X-MVRF Key Generation (d=" << num_layers << " layers)\n";
        auto t0 = high_resolution_clock::now();
        
        // Generate random master seed
        seed.resize(LAMBDA);
        for (size_t i = 0; i < LAMBDA; i++) seed[i] = rand() % 256;
        
        // Create and run XVRF (which implements XMVRF)
        delete xvrf;
        xvrf = new XVRF(layer_heights, seed);
        xvrf->keygen();
        
        auto dt = duration_cast<microseconds>(high_resolution_clock::now() - t0);

        // Display results
        cout << "\n[KEYGEN SUCCESS]\n";
        cout << "Public Key (Root): " << HashUtils::to_hex(xvrf->get_pk()) << "\n";
        cout << "Secret Key (Seed): " << HashUtils::to_hex(seed) << "\n";
        cout << "Layers: " << num_layers << ", Height: " << layer_heights[0] << "\n";
        cout << "Capacity: " << format_capacity(layer_heights[0] * num_layers) << " evaluations\n";
        cout << "Time: " << dt.count() << " μs\n";
    } else {
        // X-VRF key generation (single layer)
        cout << "X-VRF Key Generation (single layer)\n";
        cout << "Enter tree height [1-20]: ";
        int h; cin >> h;
        if (h < 1 || h > 20) { cout << "Invalid height.\n"; return; }
        
        auto t0 = high_resolution_clock::now();
        
        // Generate random master seed
        seed.resize(LAMBDA);
        for (size_t i = 0; i < LAMBDA; i++) seed[i] = rand() % 256;
        
        // Create and run single-layer XVRF
        delete xvrf;
        layer_heights.clear();
        layer_heights.push_back(h);
        xvrf = new XVRF(layer_heights, seed);
        xvrf->keygen();
        
        auto dt = duration_cast<microseconds>(high_resolution_clock::now() - t0);

        // Display results
        cout << "\n[KEYGEN SUCCESS]\n";
        cout << "Public Key (Root): " << HashUtils::to_hex(xvrf->get_pk()) << "\n";
        cout << "Secret Key (Seed): " << HashUtils::to_hex(seed) << "\n";
        cout << "Capacity: " << format_capacity(h) << " evaluations\n";
        cout << "Time: " << dt.count() << " μs\n";
    }
}

// ============================================================================
// eval: XM-VRF.Eval algorithm - Evaluate VRF on input message
// ============================================================================
// Paper Reference: Algorithm Eval, Section 3.1
// Purpose: Execute XM-VRF.Eval to produce (yXM-VRF, πXM-VRF)
// Workflow:
//   1. Prompt user for input message x (max 32 bytes, hex or ASCII)
//   2. Call XVRF.eval(x) to generate:
//      - yXM-VRF: VRF output = H1(Σ, x) where Σ = proof data
//      - πXM-VRF: Multi-layer proof (σ0, Auth0, σ1, Auth1, ..., σd−1, Authd−1)
//   3. Display:
//      - VRF output (64 hex characters)
//      - Layer-wise proof components (indices, path depths)
//      - Evaluation timing
// Result:
//   - First call uses leaf 0, second uses leaf 1, etc. (stateful)
//   - Supports 2^(h/d) evaluations total before tree exhaustion
// Sets global variable: proof (stored for later verification)
// ============================================================================
static void eval() {
    sep();
    if (!xvrf) { cout << "Run KeyGen first.\n"; return; }
    
    // Get message from user
    cout << "Enter message (hex or ASCII, max 32 bytes): ";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    string s; getline(cin, s);
    
    // Convert hex or ASCII to bytes
    Bytes msg = hex2bytes(s);
    if (msg.empty()) msg = Bytes(s.begin(), s.end());
    // Pad/truncate to standard 32 bytes
    msg.resize(M_LEN, 0);

    auto t0 = high_resolution_clock::now();
    
    // Evaluate VRF
    HashVal y;
    if (!xvrf->eval(msg, y, proof)) { 
        cout << "[ERROR] Tree exhausted\n"; 
        return; 
    }
    
    auto dt = duration_cast<microseconds>(high_resolution_clock::now() - t0);

    // Display results
    cout << "\n[EVAL SUCCESS]\n";
    cout << "VRF Output (y): " << HashUtils::to_hex(y) << "\n";
    
    // Display proof components
    cout << "π (Proof): \n";
    
    if (use_mvrf) {
        // Multi-layer mode: show detailed per-layer proof
        cout << "Layers: " << num_layers << "\n";
        for (uint32_t i = 0; i < num_layers; i++) {
            cout << "\n  Layer " << (i + 1) << ":\n";
            cout << "    Index: " << proof.indices[i] << "\n";
            
            // Print WOTS+ signature
            cout << "    σ (WOTS+ Sig): ";
            for (const auto& sig_component : proof.wots_sigs[i]) {
                cout << HashUtils::to_hex(sig_component) << " ";
            }
            cout << "\n";
            
            // Print authentication path
            cout << "    Auth" << i << " (path): ";
            for (const auto& node : proof.auth_paths[i]) {
                cout << HashUtils::to_hex(node) << " ";
            }
            cout << "\n";
        }
    } else {
        // Single-layer mode: show detailed proof
        cout << "Index: " << proof.indices[0] << "\n";
        
        // Print WOTS+ signature
        cout << "σ (WOTS+ Sig): ";
        for (const auto& sig_component : proof.wots_sigs[0]) {
            cout << HashUtils::to_hex(sig_component) << " ";
        }
        cout << "\n";
        
        // Print authentication path
        cout << "Auth Path: ";
        for (const auto& node : proof.auth_paths[0]) {
            cout << HashUtils::to_hex(node) << " ";
        }
        cout << "\n";
        
        uint64_t total = (1ULL << layer_heights[0]);
        uint64_t remaining = total - proof.indices[0] - 1;
        cout << "Total Capacity: " << format_capacity(layer_heights[0]) << "\n";
        cout << "Remaining: " << remaining << " evaluations\n";
    }
    cout << "Time: " << dt.count() << " μs\n";
}

// ============================================================================
// verify: XM-VRF.Verify algorithm - Verify VRF output and proof
// ============================================================================
// Paper Reference: Algorithm Verify, Section 3.1
// Purpose: Execute XM-VRF.Verify to cryptographically authenticate (yXM-VRF, πXM-VRF)
// Workflow:
//   1. Prompt user for three inputs (all must match original eval):
//      - vkXM-VRF (verification key, public, from keygen)
//      - x (message, must be same as eval input)
//      - πXM-VRF (proof, from eval output)
//   2. Call XVRF.verify(vk, x, y, proof, d, ...) which:
//      (i) Parses πXM-VRF = (σ0, Auth0, σ1, Auth1, ..., σd−1, Authd−1)
//      (ii-iii) For each layer j: Reconstructs WOTS+ pk(j), verifies auth path
//      (iv) Checks computed root = verification key (vkXM-VRF)
//      (v) Checks H1(πXM-VRF, x) = yXM-VRF
//   3. Output: VERIFY SUCCESS (≡1) or VERIFY FAILED (≡0)
// Security (Paper Section 3.4):
//   - Uniqueness (Theorem 3): Only one valid output per input
//   - Pseudorandomness (Theorem 4): Output indistinguishable from random
//   - Forward security (Theorem 5): Uses stateful forward-secure PRG
// Note: Verification succeeds iff ALL d layers verify correctly
// ============================================================================
static void verify() {
    sep();
    if (!xvrf) { cout << "Run KeyGen and Eval first.\n"; return; }

    // Get public key from user
    cout << "Enter Public Key (64 hex chars): ";
    string pk_hex; cin >> pk_hex;
    HashVal pk = HashUtils::from_hex(pk_hex);
    if (pk.size() != LAMBDA) { cout << "Invalid PK.\n"; return; }

    // Get message from user (must match eval input)
    cout << "Enter message (must match Eval): ";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    string s; getline(cin, s);
    Bytes msg = hex2bytes(s);
    if (msg.empty()) msg = Bytes(s.begin(), s.end());
    msg.resize(M_LEN, 0);

    // Get VRF output from user
    cout << "Enter VRF output (64 hex chars): ";
    string y_hex; cin >> y_hex;
    HashVal y = HashUtils::from_hex(y_hex);

    // Re-derive verification parameters from seed
    Bytes key = HashUtils::hash(seed);
    vector<Bytes> r;
    PRG prg(seed);
    for (int i = 0; i < W - 1; i++) r.push_back(prg.next());

    auto t0 = high_resolution_clock::now();
    
    // Verify proof (use number of proof components to determine d)
    bool ok = XVRF::verify(pk, msg, y, proof, proof.indices.size(), xvrf->get_bitmasks(), r, key);
    
    auto dt = duration_cast<microseconds>(high_resolution_clock::now() - t0);

    // Display result
    cout << (ok ? "[VERIFY SUCCESS]\n" : "[VERIFY FAILED]\n");
    cout << "Time: " << dt.count() << " μs\n";
}

// ============================================================================
// main: Interactive XM-VRF Demonstration Program
// ============================================================================
// Paper Reference: Interactive implementation of XM-VRF algorithms
// Purpose: Provide user-friendly CLI for experimenting with all XM-VRF operations
// Implements all four main algorithms:
//   1. ParamGen(1λ) - Implicit via mode_selection (configures parameters)
//   2. KeyGen(ppXM-VRF) - Via keygen command
//   3. Eval(ppXM-VRF, skXM-VRF, x) - Via eval command
//   4. Verify(ppXM-VRF, vkXM-VRF, x, yXM-VRF, πXM-VRF) - Via verify command
// Workflow:
//   1. Display XM-VRF banner
//   2. Configure mode: X-VRF (d=1) or X-MVRF (d>1)
//   3. Interactive menu loop supporting:
//      - KeyGen: Generate new (skXM-VRF, vkXM-VRF) pair
//      - Eval: Compute next (yXM-VRF, πXM-VRF) for given message
//      - Verify: Check validity of (yXM-VRF, πXM-VRF) against vkXM-VRF
//      - Mode: Switch between X-VRF and X-MVRF modes
//      - Exit: Terminate program
// Paper application (Section 4): Can be extended for Algorand committee selection
// ============================================================================
int main() {
    cout << "\n╔═══════════════════════════════════════╗\n";
    cout << "║      X-MVRF Interactive Demo (C++)    ║\n";
    cout << "╚═══════════════════════════════════════╝\n";

    // Initial mode selection
    mode_selection();
    cout << "\nMode: " << (use_mvrf ? "X-MVRF" : "X-VRF") << "\n";

    // Main menu loop
    for (;;) {
        sep();
        cout << "1) KeyGen\n2) Eval\n3) Verify\n4) Change Mode\n5) Exit\nChoice [1-5]: ";
        int opt; if (!(cin >> opt)) break;
        
        switch (opt) {
            case 1: keygen(); break;           // Generate keys
            case 2: eval(); break;             // Evaluate VRF
            case 3: verify(); break;           // Verify output
            case 4: mode_selection(); break;   // Switch modes
            case 5: cout << "Exiting...\n"; return 0;  // Exit program
            default: cout << "Invalid option.\n";
        }
    }
    return 0;
}