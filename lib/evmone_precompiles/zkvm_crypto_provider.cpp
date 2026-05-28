// evmone: Fast Ethereum Virtual Machine implementation
// SPDX-License-Identifier: Apache-2.0
//
// zkVM-backed CryptoProvider: routes every interface method to ziskos's
// `zkvm_*` accelerators. Compiled only when EVMONE_CRYPTO_ZKVM is set, in
// which case the build is required to link a library that defines the
// `zkvm_*` symbols (e.g. libziskos_staticlib.a) — strong undef refs to those
// symbols pull the corresponding archive members at link time.
//
// Hint capture is a side effect of the zkvm_* implementations: every call
// records a hint AND computes the result. No additional plumbing here.

#include <evmone/crypto_provider.hpp>
#include <evmone_precompiles/keccak.hpp>

#include <cstring>
#include <vector>

extern "C" {

int zkvm_secp256k1_ecrecover(
    const uint8_t* msg, const uint8_t* sig, uint8_t recid, uint8_t* pubkey_out);
int zkvm_sha256(const uint8_t* data, size_t len, uint8_t* out_32);
int zkvm_ripemd160(const uint8_t* data, size_t len, uint8_t* out_32);
int zkvm_modexp(const uint8_t* base, size_t base_len, const uint8_t* exp, size_t exp_len,
    const uint8_t* mod, size_t mod_len, uint8_t* out);
int zkvm_bn254_g1_add(const uint8_t* p1_64, const uint8_t* p2_64, uint8_t* r_64);
int zkvm_bn254_g1_mul(const uint8_t* p_64, const uint8_t* s_32, uint8_t* r_64);
int zkvm_bn254_pairing(const uint8_t* pairs_192_each, size_t n, bool* verified);
int zkvm_blake2f(uint32_t rounds, uint64_t h[8], const uint64_t m[16], const uint64_t t[2],
    uint8_t f);
int zkvm_kzg_point_eval(const uint8_t* cmt_48, const uint8_t* z_32, const uint8_t* y_32,
    const uint8_t* proof_48, bool* verified);
int zkvm_bls12_g1_add(const uint8_t* p1_96, const uint8_t* p2_96, uint8_t* r_96);
int zkvm_bls12_g1_msm(const uint8_t* pairs_128_each, size_t n, uint8_t* r_96);
int zkvm_bls12_g2_add(const uint8_t* p1_192, const uint8_t* p2_192, uint8_t* r_192);
int zkvm_bls12_g2_msm(const uint8_t* pairs_224_each, size_t n, uint8_t* r_192);
int zkvm_bls12_pairing(const uint8_t* pairs_288_each, size_t n, bool* verified);
int zkvm_bls12_map_fp_to_g1(const uint8_t* fp_48, uint8_t* r_96);
int zkvm_bls12_map_fp2_to_g2(const uint8_t* fp2_96, uint8_t* r_192);
int zkvm_secp256r1_verify(
    const uint8_t* msg_32, const uint8_t* sig_64, const uint8_t* pk_64, bool* verified);

}  // extern "C"

namespace evmone::crypto
{
namespace
{

// EVM encodes each BLS12-381 Fp as 64 bytes (16 zero + 48 actual); ziskos's
// zkvm_bls12_* uses the compact 48-byte form. Conversion happens here.
inline void evm_fp_to_compact(const uint8_t* evm_64, uint8_t* compact_48) noexcept
{
    std::memcpy(compact_48, evm_64 + 16, 48);
}
inline void compact_fp_to_evm(const uint8_t* compact_48, uint8_t* evm_64) noexcept
{
    std::memset(evm_64, 0, 16);
    std::memcpy(evm_64 + 16, compact_48, 48);
}
inline void evm_g1_to_compact(const uint8_t* evm_128, uint8_t* compact_96) noexcept
{
    evm_fp_to_compact(evm_128, compact_96);
    evm_fp_to_compact(evm_128 + 64, compact_96 + 48);
}
inline void compact_g1_to_evm(const uint8_t* compact_96, uint8_t* evm_128) noexcept
{
    compact_fp_to_evm(compact_96, evm_128);
    compact_fp_to_evm(compact_96 + 48, evm_128 + 64);
}
inline void evm_g2_to_compact(const uint8_t* evm_256, uint8_t* compact_192) noexcept
{
    for (int i = 0; i < 4; ++i)
        evm_fp_to_compact(evm_256 + 64 * i, compact_192 + 48 * i);
}
inline void compact_g2_to_evm(const uint8_t* compact_192, uint8_t* evm_256) noexcept
{
    for (int i = 0; i < 4; ++i)
        compact_fp_to_evm(compact_192 + 48 * i, evm_256 + 64 * i);
}

class ZkvmCryptoProvider final : public CryptoProvider
{
public:
    bool ecrecover(uint8_t out_addr[20], const uint8_t msg[32], const uint8_t sig[64],
        uint8_t recid) const override
    {
        uint8_t pubkey[64];
        if (zkvm_secp256k1_ecrecover(msg, sig, recid, pubkey) != 0)
            return false;
        const auto h = ethash::keccak256(pubkey, 64);
        std::memcpy(out_addr, &h.bytes[12], 20);
        return true;
    }

    void sha256(uint8_t out[32], const uint8_t* data, size_t len) const override
    {
        zkvm_sha256(data, len, out);
    }

    void ripemd160(uint8_t out[20], const uint8_t* data, size_t len) const override
    {
        uint8_t scratch[32];
        zkvm_ripemd160(data, len, scratch);
        std::memcpy(out, scratch + 12, 20);
    }

    void modexp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
        std::span<const uint8_t> mod, uint8_t* output) const override
    {
        zkvm_modexp(base.data(), base.size(), exp.data(), exp.size(), mod.data(), mod.size(),
            output);
    }

    bool bn254_g1_add(uint8_t out[64], const uint8_t p1[64], const uint8_t p2[64]) const override
    {
        return zkvm_bn254_g1_add(p1, p2, out) == 0;
    }

    bool bn254_g1_mul(
        uint8_t out[64], const uint8_t point[64], const uint8_t scalar[32]) const override
    {
        return zkvm_bn254_g1_mul(point, scalar, out) == 0;
    }

    bool bn254_pairing(
        bool& verified, const uint8_t* pairs_192_each, size_t num_pairs) const override
    {
        return zkvm_bn254_pairing(pairs_192_each, num_pairs, &verified) == 0;
    }

    void blake2f(uint32_t rounds, uint64_t h[8], const uint64_t m[16], const uint64_t t[2],
        uint8_t f) const override
    {
        zkvm_blake2f(rounds, h, m, t, f);
    }

    bool kzg_point_eval(bool& verified, const uint8_t versioned_hash[32],
        const uint8_t commitment[48], const uint8_t z[32], const uint8_t y[32],
        const uint8_t proof[48]) const override
    {
        uint8_t expected_vh[32];
        zkvm_sha256(commitment, 48, expected_vh);
        expected_vh[0] = 0x01;
        if (std::memcmp(expected_vh, versioned_hash, 32) != 0)
            return false;
        return zkvm_kzg_point_eval(commitment, z, y, proof, &verified) == 0;
    }

    bool bls12_g1_add(
        uint8_t out[128], const uint8_t p1[128], const uint8_t p2[128]) const override
    {
        uint8_t p1c[96], p2c[96], rc[96];
        evm_g1_to_compact(p1, p1c);
        evm_g1_to_compact(p2, p2c);
        if (zkvm_bls12_g1_add(p1c, p2c, rc) != 0)
            return false;
        compact_g1_to_evm(rc, out);
        return true;
    }

    bool bls12_g1_msm(
        uint8_t out[128], const uint8_t* pairs_160_each, size_t num_pairs) const override
    {
        // Compact pair layout: 96-byte G1 || 32-byte scalar = 128 bytes.
        std::vector<uint8_t> pairs(num_pairs * 128);
        for (size_t i = 0; i < num_pairs; ++i)
        {
            const auto* src = pairs_160_each + i * 160;
            auto* dst = pairs.data() + i * 128;
            evm_g1_to_compact(src, dst);
            std::memcpy(dst + 96, src + 128, 32);
        }
        uint8_t rc[96];
        if (zkvm_bls12_g1_msm(pairs.data(), num_pairs, rc) != 0)
            return false;
        compact_g1_to_evm(rc, out);
        return true;
    }

    bool bls12_g2_add(
        uint8_t out[256], const uint8_t p1[256], const uint8_t p2[256]) const override
    {
        uint8_t p1c[192], p2c[192], rc[192];
        evm_g2_to_compact(p1, p1c);
        evm_g2_to_compact(p2, p2c);
        if (zkvm_bls12_g2_add(p1c, p2c, rc) != 0)
            return false;
        compact_g2_to_evm(rc, out);
        return true;
    }

    bool bls12_g2_msm(
        uint8_t out[256], const uint8_t* pairs_288_each, size_t num_pairs) const override
    {
        // Compact pair: 192-byte G2 || 32-byte scalar = 224 bytes.
        std::vector<uint8_t> pairs(num_pairs * 224);
        for (size_t i = 0; i < num_pairs; ++i)
        {
            const auto* src = pairs_288_each + i * 288;
            auto* dst = pairs.data() + i * 224;
            evm_g2_to_compact(src, dst);
            std::memcpy(dst + 192, src + 256, 32);
        }
        uint8_t rc[192];
        if (zkvm_bls12_g2_msm(pairs.data(), num_pairs, rc) != 0)
            return false;
        compact_g2_to_evm(rc, out);
        return true;
    }

    bool bls12_pairing(
        bool& verified, const uint8_t* pairs_384_each, size_t num_pairs) const override
    {
        // Compact pair: 96-byte G1 || 192-byte G2 = 288 bytes.
        std::vector<uint8_t> pairs(num_pairs * 288);
        for (size_t i = 0; i < num_pairs; ++i)
        {
            const auto* src = pairs_384_each + i * 384;
            auto* dst = pairs.data() + i * 288;
            evm_g1_to_compact(src, dst);
            evm_g2_to_compact(src + 128, dst + 96);
        }
        return zkvm_bls12_pairing(pairs.data(), num_pairs, &verified) == 0;
    }

    bool bls12_map_fp_to_g1(uint8_t out[128], const uint8_t fp[64]) const override
    {
        uint8_t fpc[48], rc[96];
        evm_fp_to_compact(fp, fpc);
        if (zkvm_bls12_map_fp_to_g1(fpc, rc) != 0)
            return false;
        compact_g1_to_evm(rc, out);
        return true;
    }

    bool bls12_map_fp2_to_g2(uint8_t out[256], const uint8_t fp2[128]) const override
    {
        uint8_t fp2c[96], rc[192];
        evm_fp_to_compact(fp2, fp2c);
        evm_fp_to_compact(fp2 + 64, fp2c + 48);
        if (zkvm_bls12_map_fp2_to_g2(fp2c, rc) != 0)
            return false;
        compact_g2_to_evm(rc, out);
        return true;
    }

    bool secp256r1_verify(bool& verified, const uint8_t msg[32], const uint8_t sig[64],
        const uint8_t pubkey[64]) const override
    {
        return zkvm_secp256r1_verify(msg, sig, pubkey, &verified) == 0;
    }
};

const ZkvmCryptoProvider kZkvmProvider{};

}  // namespace

void install_zkvm_provider() noexcept
{
    set_crypto_provider(&kZkvmProvider);
}

}  // namespace evmone::crypto
