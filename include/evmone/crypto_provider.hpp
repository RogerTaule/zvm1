// evmone: Fast Ethereum Virtual Machine implementation
// SPDX-License-Identifier: Apache-2.0
//
// Swappable crypto provider for EVM precompile primitives. Mirrors revm's
// `Crypto` trait. Consumers (zkVM clients, alternate backends) plug in a
// custom implementation; evmone's precompile dispatch routes through
// current_crypto_provider() instead of calling the bundled software impls
// directly.
//
// Process-wide registry (set_crypto_provider / current_crypto_provider) keeps
// the dispatch hot-path branch-free. nullptr = use default. The provider
// returned by current_crypto_provider() is the active one if set, else the
// default (software-only, backed by evmone's lib/evmone_precompiles).
//
// BLS12-381 NOTE: the interface uses EVM byte format (each Fp is 64 bytes
// with a 16-byte zero prefix). Providers needing the compact 48-byte form
// (e.g. ziskos's zkvm_bls12_*) absorb the strip internally.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace evmone::crypto
{

class CryptoProvider
{
public:
    virtual ~CryptoProvider() = default;

    // 0x01 — ecrecover. Recovers a 20-byte Ethereum address from a signed message.
    // Returns false on any recovery failure (invalid signature, point at infinity, etc.).
    virtual bool ecrecover(uint8_t out_addr[20], const uint8_t msg[32],
        const uint8_t sig[64], uint8_t recid) const = 0;

    // 0x02 — SHA-256.
    virtual void sha256(uint8_t out[32], const uint8_t* data, size_t len) const = 0;

    // 0x03 — RIPEMD-160. Writes 20 bytes; caller is responsible for any zero padding.
    virtual void ripemd160(uint8_t out[20], const uint8_t* data, size_t len) const = 0;

    // 0x05 — Modular exponentiation. Output buffer holds exactly mod.size() bytes.
    virtual void modexp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
        std::span<const uint8_t> mod, uint8_t* output) const = 0;

    // 0x06 / 0x07 / 0x08 — bn254. Points are 64 bytes (x||y), scalar is 32 bytes,
    // each pairing pair is 192 bytes (G1 64 || G2 128 in EVM byte order).
    virtual bool bn254_g1_add(uint8_t out[64], const uint8_t p1[64], const uint8_t p2[64]) const = 0;
    virtual bool bn254_g1_mul(
        uint8_t out[64], const uint8_t point[64], const uint8_t scalar[32]) const = 0;
    virtual bool bn254_pairing(
        bool& verified, const uint8_t* pairs_192_each, size_t num_pairs) const = 0;

    // 0x09 — BLAKE2b compression. h is updated in place.
    virtual void blake2f(uint32_t rounds, uint64_t h[8], const uint64_t m[16],
        const uint64_t t[2], uint8_t f) const = 0;

    // 0x0a — KZG point evaluation (EIP-4844). Verifies both the versioned_hash
    // contract (vh == sha256(commitment) with byte 0 = 0x01) and the KZG opening.
    // Returns true on success; sets `verified` iff both checks pass.
    virtual bool kzg_point_eval(bool& verified, const uint8_t versioned_hash[32],
        const uint8_t commitment[48], const uint8_t z[32], const uint8_t y[32],
        const uint8_t proof[48]) const = 0;

    // 0x0b … 0x11 — BLS12-381, all in EVM byte format (each Fp 64 bytes with
    // 16-byte zero prefix). Providers needing the compact 48-byte form absorb the strip.
    virtual bool bls12_g1_add(
        uint8_t out[128], const uint8_t p1[128], const uint8_t p2[128]) const = 0;
    // Each pair: 128 byte G1 point || 32 byte scalar = 160 bytes.
    virtual bool bls12_g1_msm(
        uint8_t out[128], const uint8_t* pairs_160_each, size_t num_pairs) const = 0;
    virtual bool bls12_g2_add(
        uint8_t out[256], const uint8_t p1[256], const uint8_t p2[256]) const = 0;
    // Each pair: 256 byte G2 point || 32 byte scalar = 288 bytes.
    virtual bool bls12_g2_msm(
        uint8_t out[256], const uint8_t* pairs_288_each, size_t num_pairs) const = 0;
    // Each pair: 128 byte G1 || 256 byte G2 = 384 bytes.
    virtual bool bls12_pairing(
        bool& verified, const uint8_t* pairs_384_each, size_t num_pairs) const = 0;
    virtual bool bls12_map_fp_to_g1(uint8_t out[128], const uint8_t fp[64]) const = 0;
    virtual bool bls12_map_fp2_to_g2(uint8_t out[256], const uint8_t fp2[128]) const = 0;

    // 0x100 — secp256r1 (P-256) signature verify (EIP-7212).
    virtual bool secp256r1_verify(bool& verified, const uint8_t msg[32], const uint8_t sig[64],
        const uint8_t pubkey[64]) const = 0;
};

/// Returns the always-available default provider (software impls backed by
/// evmone's bundled `crypto::*` free functions).
const CryptoProvider& default_crypto_provider() noexcept;

/// Returns the currently active provider — the one installed via
/// set_crypto_provider, or the default if none.
const CryptoProvider& current_crypto_provider() noexcept;

/// Installs a process-wide provider. Pass nullptr to revert to the default.
/// Pointer must outlive any subsequent precompile dispatch.
void set_crypto_provider(const CryptoProvider* provider) noexcept;

#ifdef EVMONE_CRYPTO_ZKVM
/// Installs the bundled zkVM provider (routes all crypto through ziskos's
/// `zkvm_accelerators`). Only available when evmone was built with
/// EVMONE_CRYPTO_ZKVM=ON. The implementation is in zkvm_crypto_provider.cpp.
void install_zkvm_provider() noexcept;
#endif

}  // namespace evmone::crypto
