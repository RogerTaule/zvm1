// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#include "secp256k1.hpp"
#include "keccak.hpp"

#if defined(SP1TURBO) || defined(SP1)
#include <sp1_syscalls.hpp>
#endif

namespace evmmax::secp256k1
{
namespace
{
constexpr auto B = Curve::Fp{7};

constexpr AffinePoint G{0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256};
}  // namespace

// FIXME: Change to "uncompress_point".
std::optional<Curve::Fp> calculate_y(const Curve::Fp& x, bool y_parity) noexcept
{
    // Calculate y = √(x³ + 7).
    const auto xxx = x * x * x;
    const auto opt_y = field_sqrt(xxx + B);
    if (!opt_y.has_value())
        return std::nullopt;

    // Negate if different parity requested.
    const auto& y = *opt_y;
    const auto candidate_parity = (y.value() & 1) != 0;
    return (candidate_parity == y_parity) ? y : -y;
}

evmc::address to_address(std::span<const uint8_t, 64> pubkey) noexcept
{
    const auto hashed = ethash::keccak256(pubkey.data(), pubkey.size());
    evmc::address ret;
    std::copy_n(&hashed.bytes[12], sizeof(ret), ret.bytes);
    return ret;
}

#if defined(SP1TURBO) || defined(SP1)

inline void sp1_mulmod(uint256& result, const uint256& x, const uint256& y)
{
    // TODO(sp1): This can be further optimized by requiring the layout from the caller.
    uint256 args[2];
    auto& arg = args[0];
    auto& mod = args[1];
    mod = Curve::FIELD_PRIME;
    arg = y;
    result = x;
    sp1::mulmod(result, args);
}

// Manual modular addition: (x + y) mod p
inline uint256 sp1_addmod(const uint256& x, const uint256& y)
{
    auto sum = intx::addc(x, y);
    // If carry or sum >= p, subtract p
    if (sum.carry || sum.value >= Curve::FIELD_PRIME)
        return sum.value - Curve::FIELD_PRIME;
    return sum.value;
}

// Manual modular subtraction: (x - y) mod p
inline uint256 sp1_submod(const uint256& x, const uint256& y)
{
    auto diff = intx::subc(x, y);
    // If borrow, add p
    if (diff.carry)
        return diff.value + Curve::FIELD_PRIME;
    return diff.value;
}


std::optional<uint256> field_sqrt_sp1(const uint256& field, const uint256& x) noexcept
{
    uint256 z;
    uint256 t0;
    uint256 t1;
    uint256 t2;
    uint256 t3;

    // Step 1: z = x^0x2
    sp1_mulmod(z, x, x);

    // Step 2: z = x^0x3
    sp1_mulmod(z, x, z);

    // Step 4: t0 = x^0xc
    sp1_mulmod(t0, z, z);
    for (int i = 1; i < 2; ++i)
        sp1_mulmod(t0, t0, t0);

    // Step 5: t0 = x^0xf
    sp1_mulmod(t0, z, t0);

    // Step 6: t1 = x^0x1e
    sp1_mulmod(t1, t0, t0);

    // Step 7: t2 = x^0x1f
    sp1_mulmod(t2, x, t1);

    // Step 9: t1 = x^0x7c
    sp1_mulmod(t1, t2, t2);
    for (int i = 1; i < 2; ++i)
        sp1_mulmod(t1, t1, t1);

    // Step 10: t1 = x^0x7f
    sp1_mulmod(t1, z, t1);

    // Step 14: t3 = x^0x7f0
    sp1_mulmod(t3, t1, t1);
    for (int i = 1; i < 4; ++i)
        sp1_mulmod(t3, t3, t3);

    // Step 15: t0 = x^0x7ff
    sp1_mulmod(t0, t0, t3);

    // Step 26: t3 = x^0x3ff800
    sp1_mulmod(t3, t0, t0);
    for (int i = 1; i < 11; ++i)
        sp1_mulmod(t3, t3, t3);

    // Step 27: t0 = x^0x3fffff
    sp1_mulmod(t0, t0, t3);

    // Step 32: t3 = x^0x7ffffe0
    sp1_mulmod(t3, t0, t0);
    for (int i = 1; i < 5; ++i)
        sp1_mulmod(t3, t3, t3);

    // Step 33: t2 = x^0x7ffffff
    sp1_mulmod(t2, t2, t3);

    // Step 60: t3 = x^0x3ffffff8000000
    sp1_mulmod(t3, t2, t2);
    for (int i = 1; i < 27; ++i)
        sp1_mulmod(t3, t3, t3);

    // Step 61: t2 = x^0x3fffffffffffff
    sp1_mulmod(t2, t2, t3);

    // Step 115: t3 = x^0xfffffffffffffc0000000000000
    sp1_mulmod(t3, t2, t2);
    for (int i = 1; i < 54; ++i)
        sp1_mulmod(t3, t3, t3);

    // Step 116: t2 = x^0xfffffffffffffffffffffffffff
    sp1_mulmod(t2, t2, t3);

    // Step 224: t3 = x^0xfffffffffffffffffffffffffff000000000000000000000000000
    sp1_mulmod(t3, t2, t2);
    for (int i = 1; i < 108; ++i)
        sp1_mulmod(t3, t3, t3);

    // Step 225: t2 = x^0xffffffffffffffffffffffffffffffffffffffffffffffffffffff
    sp1_mulmod(t2, t2, t3);

    // Step 232: t2 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff80
    for (int i = 0; i < 7; ++i)
        sp1_mulmod(t2, t2, t2);

    // Step 233: t1 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff
    sp1_mulmod(t1, t1, t2);

    // Step 256: t1 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
    for (int i = 0; i < 23; ++i)
        sp1_mulmod(t1, t1, t1);

    // Step 257: t0 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff
    sp1_mulmod(t0, t0, t1);

    // Step 263: t0 = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc0
    for (int i = 0; i < 6; ++i)
        sp1_mulmod(t0, t0, t0);

    // Step 264: z = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc3
    sp1_mulmod(z, z, t0);

    // Step 266: z = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
    for (int i = 0; i < 2; ++i)
        sp1_mulmod(z, z, z);

    // Verify: z^2 == x (mod p)
    uint256 z_squared;
    sp1_mulmod(z_squared, z, z);

    if (z_squared != x)
        return std::nullopt;  // Computed value is not the square root.

    return z;
}


/// Decompress a secp256k1 point from x-coordinate and y-parity (SP1 version).
/// Returns y-coordinate in regular (non-Montgomery) form, or nullopt if x is not on curve.
/// This version uses SP1 syscalls which operate on regular form values.

std::optional<uint256> decompress(const uint256& x, bool y_parity) noexcept
{
    // Calculate x^3 + 7 (all in regular/non-Montgomery form for SP1 syscalls)
    constexpr uint256 B_regular = 7;

    uint256 x_squared{};
    sp1_mulmod(x_squared, x, x);  // x_squared = x^2 mod p

    uint256 x_cubed{};
    sp1_mulmod(x_cubed, x_squared, x);  // x_cubed = x^3 mod p

    uint256 y_squared = sp1_addmod(x_cubed, B_regular);  // y_squared = x^3 + 7 mod p

    // sqrt(x^3 + 7)
    const auto y = field_sqrt_sp1(Curve::FIELD_PRIME, y_squared);
    if (!y.has_value())
        return std::nullopt;

    // Check parity and negate if needed (using regular form arithmetic)
    const auto candidate_parity = (*y & 1) != 0;
    if (candidate_parity == y_parity)
        return *y;
    else
        return sp1_submod(uint256{0}, *y);  // Return (0 - y) mod p
}
#endif


evmc::address to_address(const AffinePoint& pt) noexcept
{
    uint8_t serialized[64];
    pt.to_bytes(serialized);
    return to_address(serialized);
}

#if defined(SP1TURBO) || defined(SP1)
namespace
{
constexpr auto Gx_val = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256;
constexpr auto Gy_val = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256;

constexpr size_t SP1_POINT_SIZE = 64 / sizeof(size_t);

// sp1_G needs platform-specific constexpr initialization due to different limb sizes.
#ifdef SP1TURBO
constexpr sp1_AffinePoint sp1_G = {
    static_cast<uint32_t>(Gx_val[0]),
    static_cast<uint32_t>(Gx_val[0] >> 32),
    static_cast<uint32_t>(Gx_val[1]),
    static_cast<uint32_t>(Gx_val[1] >> 32),
    static_cast<uint32_t>(Gx_val[2]),
    static_cast<uint32_t>(Gx_val[2] >> 32),
    static_cast<uint32_t>(Gx_val[3]),
    static_cast<uint32_t>(Gx_val[3] >> 32),
    static_cast<uint32_t>(Gy_val[0]),
    static_cast<uint32_t>(Gy_val[0] >> 32),
    static_cast<uint32_t>(Gy_val[1]),
    static_cast<uint32_t>(Gy_val[1] >> 32),
    static_cast<uint32_t>(Gy_val[2]),
    static_cast<uint32_t>(Gy_val[2] >> 32),
    static_cast<uint32_t>(Gy_val[3]),
    static_cast<uint32_t>(Gy_val[3] >> 32),
};
#else  // SP1
constexpr sp1_AffinePoint sp1_G = {
    Gx_val[0], Gx_val[1], Gx_val[2], Gx_val[3],
    Gy_val[0], Gy_val[1], Gy_val[2], Gy_val[3],
};
#endif

/// Add p to r, handling edge cases that SP1 syscall doesn't support:
/// zero points (infinity) and points with the same x-coordinate.
void sp1_secp256k1_add(sp1_AffinePoint r, const sp1_AffinePoint p) noexcept
{
    if (is_zero(p)) [[unlikely]]
        return;
    if (is_zero(r)) [[unlikely]]
    {
        std::copy_n(p, SP1_POINT_SIZE, r);
        return;
    }

    const auto& rx = reinterpret_cast<const uint256&>(r[0]);
    const auto& px = reinterpret_cast<const uint256&>(p[0]);
    if (rx == px) [[unlikely]]
    {
        const auto& ry = reinterpret_cast<const uint256&>(r[SP1_POINT_SIZE / 2]);
        const auto& py = reinterpret_cast<const uint256&>(p[SP1_POINT_SIZE / 2]);
        if (ry == py)
            syscall_secp256k1_double(r);
        else  // r == -p
            std::fill_n(r, SP1_POINT_SIZE, 0);
        return;
    }

    syscall_secp256k1_add(r, p);
}

void sp1_mul(sp1_AffinePoint r, const sp1_AffinePoint p, uint256 c) noexcept
{
    std::fill_n(r, SP1_POINT_SIZE, 0);
    const auto bit_width = sizeof(c) * 8 - intx::clz(c);

    if (bit_width == 0)
        return;

    std::copy_n(p, SP1_POINT_SIZE, r);  // r = p
    for (auto i = bit_width - 1; i != 0; --i)
    {
        syscall_secp256k1_double(r);
        if (evmmax::ecc::test_bit(c, i - 1))
            syscall_secp256k1_add(r, p);
    }
}
}  // namespace
#endif

#ifdef ZISK
namespace
{
// Generator G (re-defined here independently of the SP1 block above, which
// is only compiled when SP1/SP1TURBO is defined).
constexpr auto zisk_Gx_val = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256;
constexpr auto zisk_Gy_val = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256;

// Mirror of Rust's SyscallPoint256 (in ziskos/.../syscalls/point.rs):
// 8 u64 limbs total, 4 for x followed by 4 for y, all little-endian.
struct ZiskPoint256
{
    uint64_t x[4];
    uint64_t y[4];
};

// Mirror of Rust's SyscallSecp256k1AddParams: { p1: &mut Point, p2: &Point }.
struct ZiskSecp256k1AddParams
{
    ZiskPoint256* p1;
    const ZiskPoint256* p2;
};

// Raw syscall wrappers — `csrs <id>, <reg>` is the Zisk syscall convention.
inline void zisk_syscall_secp256k1_add(ZiskPoint256& p1, const ZiskPoint256& p2) noexcept
{
    ZiskSecp256k1AddParams params{&p1, &p2};
    asm volatile("csrs 0x803, %0" : : "r"(&params) : "memory");
}

inline void zisk_syscall_secp256k1_dbl(ZiskPoint256& p) noexcept
{
    asm volatile("csrs 0x804, %0" : : "r"(&p) : "memory");
}

// Identity point is encoded as (0, 0).
inline bool zisk_is_zero(const ZiskPoint256& p) noexcept
{
    return (p.x[0] | p.x[1] | p.x[2] | p.x[3] | p.y[0] | p.y[1] | p.y[2] | p.y[3]) == 0;
}

inline bool zisk_x_eq(const ZiskPoint256& a, const ZiskPoint256& b) noexcept
{
    return a.x[0] == b.x[0] && a.x[1] == b.x[1] && a.x[2] == b.x[2] && a.x[3] == b.x[3];
}

inline bool zisk_y_eq(const ZiskPoint256& a, const ZiskPoint256& b) noexcept
{
    return a.y[0] == b.y[0] && a.y[1] == b.y[1] && a.y[2] == b.y[2] && a.y[3] == b.y[3];
}

// Generator G with little-endian u64 limbs. intx::uint256's limb[0] is the low
// 64 bits, so the layout matches directly.
constexpr ZiskPoint256 zisk_G = {
    {zisk_Gx_val[0], zisk_Gx_val[1], zisk_Gx_val[2], zisk_Gx_val[3]},
    {zisk_Gy_val[0], zisk_Gy_val[1], zisk_Gy_val[2], zisk_Gy_val[3]},
};

// Edge-case-safe add: wraps the syscall to handle identity (zero) inputs and
// the P+P / P+(-P) special cases that the raw syscall doesn't accept.
// Mirrors the SP1 `sp1_secp256k1_add` wrapper above.
void zisk_secp256k1_add(ZiskPoint256& r, const ZiskPoint256& p) noexcept
{
    if (zisk_is_zero(p)) [[unlikely]]
        return;
    if (zisk_is_zero(r)) [[unlikely]]
    {
        r = p;
        return;
    }
    if (zisk_x_eq(r, p)) [[unlikely]]
    {
        if (zisk_y_eq(r, p))
            zisk_syscall_secp256k1_dbl(r);  // P + P = [2]P
        else
            r = {};  // P + (-P) = 𝒪
        return;
    }
    zisk_syscall_secp256k1_add(r, p);
}

// Scalar multiplication via double-and-add, mirroring sp1_mul.
void zisk_mul(ZiskPoint256& result, const ZiskPoint256& p, uint256 c) noexcept
{
    result = {};
    const auto bit_width = sizeof(c) * 8 - intx::clz(c);
    if (bit_width == 0)
        return;

    result = p;
    for (auto i = bit_width - 1; i != 0; --i)
    {
        zisk_syscall_secp256k1_dbl(result);
        if (evmmax::ecc::test_bit(c, i - 1))
            zisk_syscall_secp256k1_add(result, p);
    }
}

// Simultaneous double-and-add ("Shamir's trick"): computes c1·P1 + c2·P2 in one
// interleaved loop, sharing the doublings. Saves ~30% of the syscalls vs two
// separate zisk_mul + one final add for an ecrecover-shaped use case where the
// scalars are typically full-width 256-bit values.
//
// Cost (assuming full 256-bit scalars):
//   * separate path:  2·(255 dbl + ~127 add) + 1 add ≈ 765 syscalls
//   * shamir path:    1 precompute (P1+P2) + 255 dbl + ~191 adds ≈ 447 syscalls
//
// Algorithm: initialize `result` from the topmost bit pattern, then for each
// remaining bit do one dbl + one conditional add (G, R, or G+R) per iteration.
// We use the edge-case-safe `zisk_secp256k1_add` for inner adds so that the
// rare case where the running sum equals one of the addends doesn't trip the
// raw syscall.
void zisk_mul2(ZiskPoint256& result, const ZiskPoint256& p1, const uint256& c1,
    const ZiskPoint256& p2, const uint256& c2) noexcept
{
    const uint256 combined = c1 | c2;
    const auto bit_width = sizeof(combined) * 8 - intx::clz(combined);
    if (bit_width == 0)
    {
        result = {};
        return;
    }

    // Precompute P1 + P2 (used whenever both scalar bits are set at the same
    // position). One add up-front for many adds saved across the loop.
    ZiskPoint256 p1_plus_p2 = p1;
    zisk_secp256k1_add(p1_plus_p2, p2);

    // Initialize result from the highest non-zero bit, avoiding a dbl-on-zero.
    const auto top = bit_width - 1;
    const bool top_c1 = evmmax::ecc::test_bit(c1, top);
    const bool top_c2 = evmmax::ecc::test_bit(c2, top);
    if (top_c1 && top_c2)
        result = p1_plus_p2;
    else if (top_c1)
        result = p1;
    else
        result = p2;  // top_c2 must be true since at least one bit is set

    // Inner loop uses the raw syscall (mirrors how zisk_mul / sp1_mul drop
    // the edge-case wrapper inside the doubling chain). With random scalars
    // the result is never equal to any of p1, p2, or p1+p2 with overwhelming
    // probability, so we don't pay the wrapper's compare overhead.
    for (auto i = top; i != 0; --i)
    {
        zisk_syscall_secp256k1_dbl(result);
        const bool b1 = evmmax::ecc::test_bit(c1, i - 1);
        const bool b2 = evmmax::ecc::test_bit(c2, i - 1);
        if (b1 && b2)
            zisk_syscall_secp256k1_add(result, p1_plus_p2);
        else if (b1)
            zisk_syscall_secp256k1_add(result, p1);
        else if (b2)
            zisk_syscall_secp256k1_add(result, p2);
    }
}

// Serialize a ZiskPoint256 to 64 bytes (big-endian, x || y) for hashing into
// the recovered address.
void zisk_point_to_bytes(uint8_t out[64], const ZiskPoint256& pt) noexcept
{
    uint256 x;
    x[0] = pt.x[0]; x[1] = pt.x[1]; x[2] = pt.x[2]; x[3] = pt.x[3];
    uint256 y;
    y[0] = pt.y[0]; y[1] = pt.y[1]; y[2] = pt.y[2]; y[3] = pt.y[3];
    intx::be::unsafe::store(&out[0], x);
    intx::be::unsafe::store(&out[32], y);
}

// ─── fcall (free-input call) protocol ────────────────────────────────
//
// Free-input calls let the prover hint the result of an expensive
// computation; the guest VERIFIES the hint with much cheaper math. For
// modular square root this is huge — the portable Fermat-based sqrt is
// ~253 squarings + ~13 multiplications in Fp, whereas verifying a
// hinted sqrt is just one squaring + one compare.
//
// Protocol (from ziskos/.../fcall.rs macros):
//   * Push parameter:  csrs 0x8F0+i, <ptr>     (i = words_to_port table)
//                      for 4-u64 (32-byte) inputs, port = 0x8F2.
//   * Trigger fcall:   csrwi 0x8C0+(id>>5), id&0x1f
//                      for FCALL_SECP256K1_FP_SQRT_ID = 3 → csrwi 0x8C0, 3.
//   * Read each result u64: csrr <reg>, 0xFFE.
//
// fp_sqrt returns 5 u64s: [exists_flag, sqrt[0], sqrt[1], sqrt[2], sqrt[3]].

inline std::optional<uint256> zisk_fcall_secp256k1_fp_sqrt(const uint256& input) noexcept
{
    // Push input pointer for a 4-u64 parameter (port 0x8F0+2=0x8F2).
    asm volatile("csrs 0x8F2, %0" : : "r"(&input) : "memory");
    // Trigger the fcall (FCALL_SECP256K1_FP_SQRT_ID = 3).
    asm volatile("csrwi 0x8C0, 3");

    uint64_t exists;
    asm volatile("csrr %0, 0xFFE" : "=r"(exists));
    if (!exists)
        return std::nullopt;

    uint256 result;
    uint64_t v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[0] = v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[1] = v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[2] = v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[3] = v;
    return result;
}

// Verify-on-hint Fp square root replacement for the portable field_sqrt /
// calculate_y combo. We compute `x³ + 7` via evmone's Montgomery Fp (cheap
// per multiplication), unwrap to standard form for the fcall, then verify
// the hinted sqrt by squaring once in Fp.
std::optional<Curve::Fp> zisk_calculate_y(const Curve::Fp& x, bool y_parity) noexcept
{
    const auto y_squared = x * x * x + B;             // Fp arith, ~3 muls
    const auto y_std_opt = zisk_fcall_secp256k1_fp_sqrt(y_squared.value());
    if (!y_std_opt.has_value())
        return std::nullopt;

    const auto y_mont = Curve::Fp{*y_std_opt};
    // Verify the hint: y² ≡ x³ + 7 (mod p).
    if (y_mont * y_mont != y_squared) [[unlikely]]
        return std::nullopt;

    const auto candidate_parity = (y_mont.value()[0] & 1) != 0;
    return (candidate_parity == y_parity) ? y_mont : -y_mont;
}

// Hint a modular inverse in the scalar field Fn via Zisk's fcall_secp256k1_fn_inv
// (FCALL_SECP256K1_FN_INV_ID = 2). Returns 4 u64s (the inverse) with no
// exists flag (it's caller's job to ensure input != 0). Verify by checking
// `input * inv ≡ 1 (mod n)` with one Fr multiplication.
inline uint256 zisk_fcall_secp256k1_fn_inv(const uint256& input) noexcept
{
    asm volatile("csrs 0x8F2, %0" : : "r"(&input) : "memory");
    asm volatile("csrwi 0x8C0, 2");

    uint256 result;
    uint64_t v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[0] = v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[1] = v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[2] = v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[3] = v;
    return result;
}

// Verify-on-hint scalar-field inverse: replaces evmone's Fermat-based
// `1 / r_fr` (~10 k rv64 steps) with a single fcall + one Fr mul check.
// Caller must guarantee `v != 0` (already validated upstream in ecrecover).
inline Curve::Fr zisk_fn_inv(const Curve::Fr& v) noexcept
{
    const auto inv_std = zisk_fcall_secp256k1_fn_inv(v.value());
    const auto inv_fr = Curve::Fr{inv_std};
    // Verify: v * inv == 1.
    if (v * inv_fr != Curve::Fr{1}) [[unlikely]]
    {
        // Hint was wrong — this shouldn't happen with a correct prover. The
        // best we can do here is bail out; return an invalid value that the
        // downstream u1/u2 computation will pollute, which the recovery's
        // final on-curve check will catch.
        return Curve::Fr{0};
    }
    return inv_fr;
}
}  // namespace
#endif


std::optional<AffinePoint> secp256k1_ecdsa_recover(std::span<const uint8_t, 32> hash,
    std::span<const uint8_t, 32> r_bytes, std::span<const uint8_t, 32> s_bytes,
    bool parity) noexcept
{
    // Follows "Elliptic Curve Digital Signature Algorithm - Public key recovery"
    // https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Public_key_recovery

    // 1. Validate r and s are within [1, n-1].
    const auto opt_r = Curve::Fr::from_bytes(r_bytes);
    if (!opt_r.has_value() || *opt_r == 0) [[unlikely]]
        return std::nullopt;

    const auto opt_s = Curve::Fr::from_bytes(s_bytes);
    if (!opt_s.has_value() || *opt_s == 0) [[unlikely]]
        return std::nullopt;

    const auto& r = *opt_r;
    const auto& s = *opt_s;

    // 3. Hash of the message is already calculated in e.
    // 4. Convert hash e to z field element by doing z = e % n.
    //    https://www.rfc-editor.org/rfc/rfc6979#section-2.3.2
    //    Converting to Montgomery form performs the e % n reduction.
    const auto z = Curve::Fr{intx::be::unsafe::load<uint256>(hash.data())};

    // 5. Calculate u1 and u2.
    const auto r_inv = 1 / r;
    const auto u1 = -z * r_inv;
    const auto u2 = s * r_inv;
    assert(u2 != 0);  // Because s != 0 and r_inv != 0.

    // 2. Calculate y coordinate of R from r and v.
    const auto r_mont = Curve::Fp{r.value()};
    const auto y = calculate_y(r_mont, parity);
    if (!y.has_value())
        return std::nullopt;

    // 6. Calculate public key point Q = u1×G + u2×R.
    const auto R = AffinePoint{r_mont, *y};
    const auto Q = msm(u1.value(), G, u2.value(), R);

    // The public key mustn't be the point at infinity. This check is cheaper on a non-affine point.
    if (Q == 0) [[unlikely]]
        return std::nullopt;

    return to_affine(Q);
}

std::optional<evmc::address> ecrecover(std::span<const uint8_t, 32> hash,
    std::span<const uint8_t, 32> r_bytes, std::span<const uint8_t, 32> s_bytes,
    bool parity) noexcept
{
#if defined(SP1TURBO) || defined(SP1)
    // Validate r and s.
    const auto opt_r = Curve::Fr::from_bytes(r_bytes);
    if (!opt_r.has_value() || *opt_r == 0)
        return std::nullopt;
    const auto opt_s = Curve::Fr::from_bytes(s_bytes);
    if (!opt_s.has_value() || *opt_s == 0)
        return std::nullopt;
    const auto& r_fr = *opt_r;
    const auto& s_fr = *opt_s;

    // Compute z, u1, u2 using FieldElement arithmetic.
    const auto z = Curve::Fr{intx::be::unsafe::load<uint256>(hash.data())};
    const auto r_inv = 1 / r_fr;
    const auto u1 = (-z * r_inv).value();
    const auto u2 = (s_fr * r_inv).value();
    assert(u2 != 0);

    const auto r_val = r_fr.value();

    // Point decompression and SP1 point operations.
#ifdef SP1TURBO
    uint8_t sp1_Rbytes[64]{};
    intx::be::unsafe::store(&sp1_Rbytes[0], r_val);
    syscall_secp256k1_decompress(sp1_Rbytes, parity);
    const auto y_sp1 = intx::be::unsafe::load<uint256>(&sp1_Rbytes[32]);
    if (y_sp1 == 0)
        return std::nullopt;
#else
    const auto y = decompress(r_val, parity);
    if (!y.has_value())
        return std::nullopt;
    uint8_t sp1_Rbytes[64]{};
    intx::be::unsafe::store(&sp1_Rbytes[0], r_val);
    intx::be::unsafe::store(&sp1_Rbytes[32], *y);
#endif

    sp1_AffinePoint sp1_R;
    sp1_point_from_bytes(sp1_R, sp1_Rbytes);

    sp1_AffinePoint sp1_T1;
    sp1_mul(sp1_T1, sp1_G, u1);
    sp1_AffinePoint sp1_T2;
    sp1_mul(sp1_T2, sp1_R, u2);

    sp1_AffinePoint sp1_Q;
    std::copy_n(sp1_T1, SP1_POINT_SIZE, sp1_Q);
    sp1_secp256k1_add(sp1_Q, sp1_T2);

    if (is_zero(sp1_Q)) [[unlikely]]
        return std::nullopt;

    uint8_t serialized[64];
    sp1_point_to_bytes(serialized, sp1_Q);
    return to_address(serialized);
#elif defined(ZISK)
    // Mirrors the SP1 path above but uses Zisk's secp256k1_add (0x803) and
    // secp256k1_dbl (0x804) CSR syscalls for point arithmetic. The portable
    // `decompress` is reused for lift_x; a future commit could route it
    // through the fcall_secp256k1_fp_sqrt fcall.

    // Validate r and s ∈ (0, n).
    const auto opt_r = Curve::Fr::from_bytes(r_bytes);
    if (!opt_r.has_value() || *opt_r == 0) [[unlikely]]
        return std::nullopt;
    const auto opt_s = Curve::Fr::from_bytes(s_bytes);
    if (!opt_s.has_value() || *opt_s == 0) [[unlikely]]
        return std::nullopt;
    const auto& r_fr = *opt_r;
    const auto& s_fr = *opt_s;

    // z, u1 = −z·r⁻¹, u2 = s·r⁻¹ (all in Fr). r_inv hinted via fcall
    // (FCALL_SECP256K1_FN_INV_ID = 2) and verified with one Fr multiplication,
    // replacing the Fermat-based inversion that costs ~10 k steps.
    const auto z = Curve::Fr{intx::be::unsafe::load<uint256>(hash.data())};
    const auto r_inv = zisk_fn_inv(r_fr);
    const auto u1 = (-z * r_inv).value();
    const auto u2 = (s_fr * r_inv).value();

    const auto r_val = r_fr.value();

    // Decompress R = (r, y) on the curve. zisk_calculate_y hints the modular
    // square root via fcall (FCALL_SECP256K1_FP_SQRT_ID = 3) and verifies the
    // hint with a single Fp squaring, replacing the ~253-squaring portable
    // Fermat-based field_sqrt. Saves ~10 k steps per ecrecover call.
    const auto r_mont = Curve::Fp{r_val};
    const auto y_opt = zisk_calculate_y(r_mont, parity);
    if (!y_opt.has_value())
        return std::nullopt;
    const auto y_val = (*y_opt).value();

    ZiskPoint256 R{
        {r_val[0], r_val[1], r_val[2], r_val[3]},
        {y_val[0], y_val[1], y_val[2], y_val[3]},
    };

    // Q = [u1]G + [u2]R via Shamir's interleaved double-and-add. One shared
    // doubling chain serves both scalars; cuts syscall count from ~765 to
    // ~447 per ecrecover call vs two separate scalar muls + a final add.
    ZiskPoint256 Q;
    zisk_mul2(Q, zisk_G, u1, R, u2);

    if (zisk_is_zero(Q)) [[unlikely]]
        return std::nullopt;

    uint8_t serialized[64];
    zisk_point_to_bytes(serialized, Q);
    return to_address(serialized);
#else
    const auto pubkey = secp256k1_ecdsa_recover(hash, r_bytes, s_bytes, parity);
    if (!pubkey.has_value())
        return std::nullopt;

    return to_address(*pubkey);
#endif
}

std::optional<Curve::Fp> field_sqrt(const Curve::Fp& x) noexcept
{
    // Computes modular exponentiation
    // x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
    // Operations: 253 squares 13 multiplies
    // Main part generated by github.com/mmcloughlin/addchain v0.4.0.
    //   addchain search 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
    //     > secp256k1_sqrt.acc
    //   addchain gen -tmpl expmod.tmpl secp256k1_sqrt.acc
    //     > secp256k1_sqrt.cpp
    //
    // Exponentiation computation is derived from the addition chain:
    //
    // _10      = 2*1
    // _11      = 1 + _10
    // _1100    = _11 << 2
    // _1111    = _11 + _1100
    // _11110   = 2*_1111
    // _11111   = 1 + _11110
    // _1111100 = _11111 << 2
    // _1111111 = _11 + _1111100
    // x11      = _1111111 << 4 + _1111
    // x22      = x11 << 11 + x11
    // x27      = x22 << 5 + _11111
    // x54      = x27 << 27 + x27
    // x108     = x54 << 54 + x54
    // x216     = x108 << 108 + x108
    // x223     = x216 << 7 + _1111111
    // return     ((x223 << 23 + x22) << 6 + _11) << 2

    // Allocate Temporaries.
    Curve::Fp z;
    Curve::Fp t0;
    Curve::Fp t1;
    Curve::Fp t2;
    Curve::Fp t3;


    // Step 1: z = x^0x2
    z = x * x;

    // Step 2: z = x^0x3
    z = x * z;

    // Step 4: t0 = x^0xc
    t0 = z * z;
    for (int i = 1; i < 2; ++i)
        t0 = t0 * t0;

    // Step 5: t0 = x^0xf
    t0 = z * t0;

    // Step 6: t1 = x^0x1e
    t1 = t0 * t0;

    // Step 7: t2 = x^0x1f
    t2 = x * t1;

    // Step 9: t1 = x^0x7c
    t1 = t2 * t2;
    for (int i = 1; i < 2; ++i)
        t1 = t1 * t1;

    // Step 10: t1 = x^0x7f
    t1 = z * t1;

    // Step 14: t3 = x^0x7f0
    t3 = t1 * t1;
    for (int i = 1; i < 4; ++i)
        t3 = t3 * t3;

    // Step 15: t0 = x^0x7ff
    t0 = t0 * t3;

    // Step 26: t3 = x^0x3ff800
    t3 = t0 * t0;
    for (int i = 1; i < 11; ++i)
        t3 = t3 * t3;

    // Step 27: t0 = x^0x3fffff
    t0 = t0 * t3;

    // Step 32: t3 = x^0x7ffffe0
    t3 = t0 * t0;
    for (int i = 1; i < 5; ++i)
        t3 = t3 * t3;

    // Step 33: t2 = x^0x7ffffff
    t2 = t2 * t3;

    // Step 60: t3 = x^0x3ffffff8000000
    t3 = t2 * t2;
    for (int i = 1; i < 27; ++i)
        t3 = t3 * t3;

    // Step 61: t2 = x^0x3fffffffffffff
    t2 = t2 * t3;

    // Step 115: t3 = x^0xfffffffffffffc0000000000000
    t3 = t2 * t2;
    for (int i = 1; i < 54; ++i)
        t3 = t3 * t3;

    // Step 116: t2 = x^0xfffffffffffffffffffffffffff
    t2 = t2 * t3;

    // Step 224: t3 = x^0xfffffffffffffffffffffffffff000000000000000000000000000
    t3 = t2 * t2;
    for (int i = 1; i < 108; ++i)
        t3 = t3 * t3;

    // Step 225: t2 = x^0xffffffffffffffffffffffffffffffffffffffffffffffffffffff
    t2 = t2 * t3;

    // Step 232: t2 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff80
    for (int i = 0; i < 7; ++i)
        t2 = t2 * t2;

    // Step 233: t1 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff
    t1 = t1 * t2;

    // Step 256: t1 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
    for (int i = 0; i < 23; ++i)
        t1 = t1 * t1;

    // Step 257: t0 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff
    t0 = t0 * t1;

    // Step 263: t0 = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc0
    for (int i = 0; i < 6; ++i)
        t0 = t0 * t0;

    // Step 264: z = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc3
    z = z * t0;

    // Step 266: z = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
    for (int i = 0; i < 2; ++i)
        z = z * z;

    if (z * z != x)
        return std::nullopt;  // Computed value is not the square root.

    return z;
}


}  // namespace evmmax::secp256k1
