// evmone: Fast Ethereum Virtual Machine implementation
// SPDX-License-Identifier: Apache-2.0
//
// Default CryptoProvider: routes every method to evmone's bundled software
// implementations under `evmone::crypto::*` / `evmmax::*`. Behavioural parity
// with pre-provider evmone is the goal here — no semantic changes.
//
// Also defines the process-wide registry (set/current_crypto_provider).

#include <evmone/crypto_provider.hpp>

#include <evmone_precompiles/blake2b.hpp>
#include <evmone_precompiles/bls.hpp>
#include <evmone_precompiles/bn254.hpp>
#include <evmone_precompiles/keccak.hpp>
#include <evmone_precompiles/kzg.hpp>
#include <evmone_precompiles/modexp.hpp>
#include <evmone_precompiles/ripemd160.hpp>
#include <evmone_precompiles/secp256k1.hpp>
#include <evmone_precompiles/secp256r1.hpp>
#include <evmone_precompiles/sha256.hpp>

#include <atomic>
#include <cstring>

namespace evmone::crypto
{
namespace
{

class DefaultCryptoProvider final : public CryptoProvider
{
public:
    bool ecrecover(uint8_t out_addr[20], const uint8_t msg[32], const uint8_t sig[64],
        uint8_t recid) const override
    {
        const auto opt = evmmax::secp256k1::ecrecover_sw(
            std::span<const uint8_t, 32>{msg, 32}, std::span<const uint8_t, 32>{sig, 32},
            std::span<const uint8_t, 32>{sig + 32, 32}, recid != 0);
        if (!opt)
            return false;
        std::memcpy(out_addr, opt->bytes, 20);
        return true;
    }

    void sha256(uint8_t out[32], const uint8_t* data, size_t len) const override
    {
        crypto::sha256(reinterpret_cast<std::byte*>(out),
            reinterpret_cast<const std::byte*>(data), len);
    }

    void ripemd160(uint8_t out[20], const uint8_t* data, size_t len) const override
    {
        crypto::ripemd160(reinterpret_cast<std::byte*>(out),
            reinterpret_cast<const std::byte*>(data), len);
    }

    void modexp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
        std::span<const uint8_t> mod, uint8_t* output) const override
    {
        crypto::modexp(base, exp, mod, output);
    }

    bool bn254_g1_add(uint8_t out[64], const uint8_t p1[64], const uint8_t p2[64]) const override
    {
        using namespace evmmax::bn254;
        const auto p = AffinePoint::from_bytes(std::span<const uint8_t, 64>{p1, 64});
        const auto q = AffinePoint::from_bytes(std::span<const uint8_t, 64>{p2, 64});
        if (!p.has_value() || !q.has_value())
            return false;
        if (!validate(*p) || !validate(*q))
            return false;
        const auto res = evmmax::ecc::add_affine(*p, *q);
        res.to_bytes(std::span<uint8_t, 64>{out, 64});
        return true;
    }

    bool bn254_g1_mul(
        uint8_t out[64], const uint8_t point[64], const uint8_t scalar[32]) const override
    {
        using namespace evmmax::bn254;
        const auto p = AffinePoint::from_bytes(std::span<const uint8_t, 64>{point, 64});
        if (!p.has_value() || !validate(*p))
            return false;
        const auto c = intx::be::unsafe::load<intx::uint256>(scalar);
        const auto res = mul(*p, c);
        res.to_bytes(std::span<uint8_t, 64>{out, 64});
        return true;
    }

    bool bn254_pairing(
        bool& verified, const uint8_t* pairs_192_each, size_t num_pairs) const override
    {
        std::vector<std::pair<evmmax::bn254::Point, evmmax::bn254::ExtPoint>> pairs;
        pairs.reserve(num_pairs);
        for (size_t i = 0; i < num_pairs; ++i)
        {
            const auto* p = pairs_192_each + 192 * i;
            const evmmax::bn254::Point g1{intx::be::unsafe::load<intx::uint256>(p),
                intx::be::unsafe::load<intx::uint256>(p + 32)};
            const evmmax::bn254::ExtPoint g2{
                {intx::be::unsafe::load<intx::uint256>(p + 96),
                    intx::be::unsafe::load<intx::uint256>(p + 64)},
                {intx::be::unsafe::load<intx::uint256>(p + 160),
                    intx::be::unsafe::load<intx::uint256>(p + 128)},
            };
            pairs.emplace_back(g1, g2);
        }
        const auto res = evmmax::bn254::pairing_check(pairs);
        if (!res.has_value())
            return false;
        verified = *res;
        return true;
    }

    void blake2f(uint32_t rounds, uint64_t h[8], const uint64_t m[16], const uint64_t t[2],
        uint8_t f) const override
    {
        crypto::blake2b_compress(rounds, h, m, t, f != 0);
    }

    bool kzg_point_eval(bool& verified, const uint8_t versioned_hash[32],
        const uint8_t commitment[48], const uint8_t z[32], const uint8_t y[32],
        const uint8_t proof[48]) const override
    {
        verified = crypto::kzg_verify_proof(reinterpret_cast<const std::byte*>(versioned_hash),
            reinterpret_cast<const std::byte*>(z), reinterpret_cast<const std::byte*>(y),
            reinterpret_cast<const std::byte*>(commitment),
            reinterpret_cast<const std::byte*>(proof));
        return true;
    }

    bool bls12_g1_add(
        uint8_t out[128], const uint8_t p1[128], const uint8_t p2[128]) const override
    {
        return crypto::bls::g1_add(out, &out[64], p1, &p1[64], p2, &p2[64]);
    }

    bool bls12_g1_msm(
        uint8_t out[128], const uint8_t* pairs_160_each, size_t num_pairs) const override
    {
        if (num_pairs == 0)
            return false;
        if (num_pairs == 1)
            return crypto::bls::g1_mul(
                out, &out[64], pairs_160_each, pairs_160_each + 64, pairs_160_each + 128);
        return crypto::bls::g1_msm(out, &out[64], pairs_160_each, num_pairs * 160);
    }

    bool bls12_g2_add(
        uint8_t out[256], const uint8_t p1[256], const uint8_t p2[256]) const override
    {
        return crypto::bls::g2_add(out, &out[128], p1, &p1[128], p2, &p2[128]);
    }

    bool bls12_g2_msm(
        uint8_t out[256], const uint8_t* pairs_288_each, size_t num_pairs) const override
    {
        if (num_pairs == 0)
            return false;
        if (num_pairs == 1)
            return crypto::bls::g2_mul(
                out, &out[128], pairs_288_each, pairs_288_each + 128, pairs_288_each + 256);
        return crypto::bls::g2_msm(out, &out[128], pairs_288_each, num_pairs * 288);
    }

    bool bls12_pairing(
        bool& verified, const uint8_t* pairs_384_each, size_t num_pairs) const override
    {
        uint8_t out[32];
        if (!crypto::bls::pairing_check(out, pairs_384_each, num_pairs * 384))
            return false;
        verified = (out[31] != 0);
        return true;
    }

    bool bls12_map_fp_to_g1(uint8_t out[128], const uint8_t fp[64]) const override
    {
        return crypto::bls::map_fp_to_g1(out, &out[64], fp);
    }

    bool bls12_map_fp2_to_g2(uint8_t out[256], const uint8_t fp2[128]) const override
    {
        return crypto::bls::map_fp2_to_g2(out, &out[128], fp2);
    }

    bool secp256r1_verify(bool& verified, const uint8_t msg[32], const uint8_t sig[64],
        const uint8_t pubkey[64]) const override
    {
        ethash::hash256 h{};
        std::copy_n(msg, sizeof(h), h.bytes);
        const auto r = intx::be::unsafe::load<intx::uint256>(sig);
        const auto s = intx::be::unsafe::load<intx::uint256>(sig + 32);
        const auto qx = intx::be::unsafe::load<intx::uint256>(pubkey);
        const auto qy = intx::be::unsafe::load<intx::uint256>(pubkey + 32);
        verified = evmmax::secp256r1::verify(h, r, s, qx, qy);
        return true;
    }
};

const DefaultCryptoProvider kDefaultProvider{};
std::atomic<const CryptoProvider*> g_provider{nullptr};

}  // namespace

const CryptoProvider& default_crypto_provider() noexcept
{
    return kDefaultProvider;
}

const CryptoProvider& current_crypto_provider() noexcept
{
    if (auto* p = g_provider.load(std::memory_order_acquire))
        return *p;
    return kDefaultProvider;
}

void set_crypto_provider(const CryptoProvider* provider) noexcept
{
    g_provider.store(provider, std::memory_order_release);
}

}  // namespace evmone::crypto
