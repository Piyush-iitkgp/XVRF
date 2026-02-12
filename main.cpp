// main.cpp - X-VRF CLI
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

static XVRF* vrf = nullptr;
static Bytes seed;
static VRFProof proof;

// hex string to bytes, empty on invalid
static Bytes hex2bytes(const string& hex) {
    Bytes out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        if (!isxdigit(hex[i]) || !isxdigit(hex[i+1])) return {};
        out.push_back((uint8_t)strtol(hex.substr(i, 2).c_str(), nullptr, 16));
    }
    return out;
}

static void sep() { cout << "────────────────────────────────────────────────────────\n"; }

static void keygen() {
    sep();
    cout << "Enter tree height [1-20] (e.g., 4=16 evals, 10=1024 evals): ";
    int h; cin >> h;
    if (h < 1 || h > 20) { cout << "Invalid height. Must be between 1 and 20.\n"; return; }

    auto t0 = high_resolution_clock::now();

    seed.resize(LAMBDA);
    for (size_t i = 0; i < LAMBDA; i++) seed[i] = rand() % 256;

    delete vrf;
    vrf = new XVRF(h, seed);
    cout << "Generating keys (2^" << h << " = " << (1 << h) << " leaves)...\n";
    vrf->keygen();

    auto dt = duration_cast<microseconds>(high_resolution_clock::now() - t0);

    cout << "\n[KEYGEN SUCCESS]\n";
    cout << "Public Key (Root): " << HashUtils::to_hex(vrf->get_pk()) << "\n";
    cout << "Secret Key (Seed): " << HashUtils::to_hex(seed) << "\n";
    cout << "\nKeygen time: " << dt.count() << " μs (" << dt.count()/1000.0 << " ms)\n";
}

static void eval() {
    sep();
    if (!vrf) { cout << "Run KeyGen first.\n"; return; }

    cout << "Enter message (any length, padded/truncated to 32 bytes)\n";
    cout << "  Format: hex (e.g., 48656c6c6f) or ASCII (e.g., Hello)\n";
    cout << "  Input: ";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    string s; getline(cin, s);

    Bytes msg = hex2bytes(s);
    if (msg.empty()) msg = Bytes(s.begin(), s.end());
    msg.resize(M_LEN, 0);

    auto t0 = high_resolution_clock::now();

    HashVal y;
    if (!vrf->eval(msg, y, proof)) { cout << "[ERROR] Tree exhausted\n"; return; }

    auto dt = duration_cast<microseconds>(high_resolution_clock::now() - t0);

    cout << "\n[EVAL SUCCESS]\n";
    cout << "VRF Output (y): " << HashUtils::to_hex(y) << "\n";
    cout << "Leaf Index:     " << proof.index << "\n";
    cout << "Auth Path Len:  " << proof.auth_path.size() << "\n";
    cout << "WOTS Sig Len:   " << proof.wots_sig.size() << " chains\n";

    cout << "\n--- Authentication Path (sibling hashes) ---\n";
    for (size_t i = 0; i < proof.auth_path.size(); i++)
        cout << "  Level " << i << ": " << HashUtils::to_hex(proof.auth_path[i]) << "\n";

    cout << "\n--- WOTS+ Signature (first 3 of " << proof.wots_sig.size() << " chains) ---\n";
    for (size_t i = 0; i < min((size_t)3, proof.wots_sig.size()); i++)
        cout << "  Chain " << i << ": " << HashUtils::to_hex(proof.wots_sig[i]) << "\n";
    if (proof.wots_sig.size() > 3)
        cout << "  ... (" << proof.wots_sig.size() - 3 << " more chains)\n";

    cout << "\nRemaining:      " << ((1 << vrf->get_height()) - vrf->get_idx()) << " uses\n";
    cout << "\nEval time: " << dt.count() << " μs (" << dt.count()/1000.0 << " ms)\n";
}

static void verify() {
    sep();
    if (!vrf) { cout << "Run KeyGen and Eval first.\n"; return; }

    cout << "Enter Public Key (exactly 64 hex chars): ";
    string pk_hex; cin >> pk_hex;
    HashVal pk = HashUtils::from_hex(pk_hex);
    if (pk.size() != LAMBDA) { cout << "Invalid PK. Must be exactly 64 hex characters (32 bytes).\n"; return; }

    cout << "Enter message (hex or ASCII, must match Eval input): ";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    string s; getline(cin, s);
    Bytes msg = hex2bytes(s);
    if (msg.empty()) msg = Bytes(s.begin(), s.end());
    msg.resize(M_LEN, 0);

    cout << "Enter VRF output y (exactly 64 hex chars): ";
    string y_hex; cin >> y_hex;
    HashVal y = HashUtils::from_hex(y_hex);

    // derive verification params
    Bytes key = HashUtils::hash(seed);
    vector<Bytes> r;
    PRG prg(seed);
    for (int i = 0; i < W - 1; i++) r.push_back(prg.next());

    cout << "(Using stored proof from last Eval)\n";

    auto t0 = high_resolution_clock::now();
    bool ok = XVRF::verify(pk, msg, y, proof, vrf->get_bitmasks(), r, key);
    auto dt = duration_cast<microseconds>(high_resolution_clock::now() - t0);

    cout << (ok ? "[VERIFY SUCCESS]\n" : "[VERIFY FAILED]\n");
    cout << "\nVerify time: " << dt.count() << " μs (" << dt.count()/1000.0 << " ms)\n";
}

int main() {
    cout << "\n╔═══════════════════════════════════════╗\n";
    cout << "║      X-VRF Interactive Demo (C++)     ║\n";
    cout << "╚═══════════════════════════════════════╝\n";

    for (;;) {
        sep();
        cout << "1) KeyGen\n2) Eval\n3) Verify\n4) Exit\nChoice [1-4]: ";
        int opt; if (!(cin >> opt)) break;
        switch (opt) {
            case 1: keygen(); break;
            case 2: eval(); break;
            case 3: verify(); break;
            case 4: cout << "Exiting...\n"; return 0;
            default: cout << "Invalid option. Enter 1, 2, 3, or 4.\n";
        }
    }
    return 0;
}