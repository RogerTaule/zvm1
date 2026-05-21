// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#include "secp256r1.hpp"

#ifdef ZISK
#include <optional>
#endif

namespace evmmax::secp256r1
{
namespace
{
bool is_on_curve(const AffinePoint& p) noexcept
{
    static constexpr AffinePoint::FE A{Curve::A};
    static constexpr AffinePoint::FE B{Curve::B};
    return p.y * p.y == p.x * p.x * p.x + A * p.x + B;
}
}  // namespace

#ifdef ZISK
namespace
{
// ─── Affine point + syscall wrappers (SECP256R1_ADD = 0x817, _DBL = 0x818) ───
//
// SECP256R1_ADD/DBL operate on plain-modular-form affine points: two coordinates
// of 4 u64 limbs (little-endian, matching intx::uint256's internal layout).

struct ZiskR1Point
{
    uint64_t x[4];
    uint64_t y[4];
};

// Mirror of Rust's SyscallSecp256r1AddParams: { p1: &mut Point, p2: &Point }.
struct ZiskR1AddParams
{
    ZiskR1Point* p1;
    const ZiskR1Point* p2;
};

inline void zisk_r1_syscall_add(ZiskR1Point& p1, const ZiskR1Point& p2) noexcept
{
    ZiskR1AddParams params{&p1, &p2};
    asm volatile("csrs 0x817, %0" : : "r"(&params) : "memory");
}

inline void zisk_r1_syscall_dbl(ZiskR1Point& p) noexcept
{
    asm volatile("csrs 0x818, %0" : : "r"(&p) : "memory");
}

inline bool zisk_r1_is_zero(const ZiskR1Point& p) noexcept
{
    return (p.x[0] | p.x[1] | p.x[2] | p.x[3] | p.y[0] | p.y[1] | p.y[2] | p.y[3]) == 0;
}

inline bool zisk_r1_x_eq(const ZiskR1Point& a, const ZiskR1Point& b) noexcept
{
    return a.x[0] == b.x[0] && a.x[1] == b.x[1] && a.x[2] == b.x[2] && a.x[3] == b.x[3];
}

inline bool zisk_r1_y_eq(const ZiskR1Point& a, const ZiskR1Point& b) noexcept
{
    return a.y[0] == b.y[0] && a.y[1] == b.y[1] && a.y[2] == b.y[2] && a.y[3] == b.y[3];
}

// Identity-aware add wrapping the raw syscall to handle 𝒪, P+P and P+(-P).
inline void zisk_r1_add(ZiskR1Point& r, const ZiskR1Point& p) noexcept
{
    if (zisk_r1_is_zero(p)) [[unlikely]]
        return;
    if (zisk_r1_is_zero(r)) [[unlikely]]
    {
        r = p;
        return;
    }
    if (zisk_r1_x_eq(r, p)) [[unlikely]]
    {
        if (zisk_r1_y_eq(r, p))
            zisk_r1_syscall_dbl(r);  // P + P
        else
            r = {};  // P + (-P) = 𝒪
        return;
    }
    zisk_r1_syscall_add(r, p);
}

// Generator G with plain-modular limbs (little-endian).
inline ZiskR1Point zisk_r1_G_const() noexcept
{
    constexpr auto Gx_val =
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296_u256;
    constexpr auto Gy_val =
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_u256;
    return ZiskR1Point{
        {Gx_val[0], Gx_val[1], Gx_val[2], Gx_val[3]},
        {Gy_val[0], Gy_val[1], Gy_val[2], Gy_val[3]},
    };
}

// Simultaneous double-and-add ("Shamir's trick"): R = c1·P1 + c2·P2, sharing
// the doubling chain. Halves the syscall budget vs two independent muls + add.
void zisk_r1_mul2(ZiskR1Point& result, const ZiskR1Point& p1, const uint256& c1,
    const ZiskR1Point& p2, const uint256& c2) noexcept
{
    const uint256 combined = c1 | c2;
    const auto bit_width = sizeof(combined) * 8 - intx::clz(combined);
    if (bit_width == 0)
    {
        result = {};
        return;
    }

    ZiskR1Point p1_plus_p2 = p1;
    zisk_r1_add(p1_plus_p2, p2);

    const auto top = bit_width - 1;
    const bool top_c1 = evmmax::ecc::test_bit(c1, top);
    const bool top_c2 = evmmax::ecc::test_bit(c2, top);
    if (top_c1 && top_c2)
        result = p1_plus_p2;
    else if (top_c1)
        result = p1;
    else
        result = p2;

    // Inner loop uses the edge-case-safe add. Unlike ecrecover's random-scalar
    // case, ECDSA *verify* receives user-supplied (r, s, Q) and EEST exercises
    // pathological combinations where u1·G + u2·Q passes through 𝒪 or where
    // intermediate sums collide. The SECP256R1_ADD / _DBL syscalls panic on
    // identity / P+P / P+(-P), so we route every inner step through the
    // identity-aware wrappers.
    for (auto i = top; i != 0; --i)
    {
        if (!zisk_r1_is_zero(result)) [[likely]]
            zisk_r1_syscall_dbl(result);
        const bool b1 = evmmax::ecc::test_bit(c1, i - 1);
        const bool b2 = evmmax::ecc::test_bit(c2, i - 1);
        if (b1 && b2)
            zisk_r1_add(result, p1_plus_p2);
        else if (b1)
            zisk_r1_add(result, p1);
        else if (b2)
            zisk_r1_add(result, p2);
    }
}

// ─── ARITH256_MOD syscall (0x802): d = (a·b + c) mod m, all 4-u64 little-endian
struct ZiskArith256ModParams
{
    const uint64_t* a;
    const uint64_t* b;
    const uint64_t* c;
    const uint64_t* module_;
    uint64_t* d;
};

inline void zisk_arith256_mod(uint256& d, const uint256& a, const uint256& b, const uint256& c,
    const uint256& m) noexcept
{
    ZiskArith256ModParams p{
        reinterpret_cast<const uint64_t*>(&a),
        reinterpret_cast<const uint64_t*>(&b),
        reinterpret_cast<const uint64_t*>(&c),
        reinterpret_cast<const uint64_t*>(&m),
        reinterpret_cast<uint64_t*>(&d),
    };
    asm volatile("csrs 0x802, %0" : : "r"(&p) : "memory");
}

// ─── fcall_uint256_inv_mod (id 21): hints x such that a·x ≡ 1 (mod m), or None.
//   * Push a (4 u64s) at port 0x8F0 + words_to_port(4) = 0x8F2.
//   * Push m (4 u64s) at port 0x8F2.
//   * Trigger:   csrwi 0x8C0 + (21 >> 5), 21 & 0x1f  →  csrwi 0x8C0, 21.
//   * Read flag (0 = no inverse) then 4 limbs.
inline std::optional<uint256> zisk_fcall_uint256_inv_mod(
    const uint256& a, const uint256& m) noexcept
{
    asm volatile("csrs 0x8F2, %0" : : "r"(&a) : "memory");
    asm volatile("csrs 0x8F2, %0" : : "r"(&m) : "memory");
    asm volatile("csrwi 0x8C0, 21");

    uint64_t has_inv;
    asm volatile("csrr %0, 0xFFE" : "=r"(has_inv));
    if (!has_inv)
        return std::nullopt;

    uint256 result;
    uint64_t v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[0] = v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[1] = v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[2] = v;
    asm volatile("csrr %0, 0xFFE" : "=r"(v)); result[3] = v;
    return result;
}

// On-curve check via 4 ARITH256_MOD calls.  y² ≡ x³ + A·x + B (mod p) where
// A = p − 3.  Factored to fit the (a·b + c) mod p form natively:
//   t1  = x · x  mod p                    =  x²
//   t2  = x · t1 + B  mod p               =  x³ + B
//   rhs = A · x + t2  mod p               =  x³ + A·x + B  =  x³ − 3x + B
//   lhs = y · y  mod p                    =  y²
bool zisk_r1_is_on_curve_xy(const uint256& x, const uint256& y) noexcept
{
    static constexpr uint256 kZero{0};
    static constexpr uint256 P_field = Curve::FIELD_PRIME;
    static constexpr uint256 A_coeff = Curve::A;  // p − 3
    static constexpr uint256 B_coeff = Curve::B;

    uint256 t1, t2, rhs, lhs;
    zisk_arith256_mod(t1, x, x, kZero, P_field);     // x²
    zisk_arith256_mod(t2, x, t1, B_coeff, P_field);  // x³ + B
    zisk_arith256_mod(rhs, A_coeff, x, t2, P_field); // x³ − 3x + B
    zisk_arith256_mod(lhs, y, y, kZero, P_field);    // y²
    return lhs == rhs;
}

bool verify_zisk(const ethash::hash256& h, const uint256& r, const uint256& s, const uint256& qx,
    const uint256& qy) noexcept
{
    // EIP-7951 verification, ARITH256_MOD + SECP256R1 syscall based.

    // 1. r, s ∈ [1, n − 1].
    if (r == 0 || r >= Curve::ORDER || s == 0 || s >= Curve::ORDER)
        return false;

    // 2. qx, qy < p ;  Q ≠ 𝒪 ;  Q on curve.
    if (qx >= Curve::FIELD_PRIME || qy >= Curve::FIELD_PRIME)
        return false;
    if ((qx | qy) == 0)
        return false;
    if (!zisk_r1_is_on_curve_xy(qx, qy))
        return false;

    // 3. z = leftmost Lₙ bits of HASH(m). For secp256r1 Lₙ = 256, so z is the
    //    full hash as a uint256. ARITH256_MOD requires inputs < module:
    //    n > 2²⁵⁵ ⇒ z < 2·n, so one conditional subtraction is enough.
    auto z = intx::be::load<uint256>(h.bytes);
    if (z >= Curve::ORDER)
        z -= Curve::ORDER;

    // 4. s_inv = s⁻¹ mod n via fcall, verified with one ARITH256_MOD.
    const auto s_inv_opt = zisk_fcall_uint256_inv_mod(s, Curve::ORDER);
    if (!s_inv_opt.has_value()) [[unlikely]]
        return false;
    const auto s_inv = *s_inv_opt;

    static constexpr uint256 kZero{0};
    static constexpr uint256 kOne{1};
    uint256 check;
    zisk_arith256_mod(check, s, s_inv, kZero, Curve::ORDER);
    if (check != kOne) [[unlikely]]
        return false;

    // 5. u1 = z · s_inv mod n,  u2 = r · s_inv mod n.
    uint256 u1, u2;
    zisk_arith256_mod(u1, z, s_inv, kZero, Curve::ORDER);
    zisk_arith256_mod(u2, r, s_inv, kZero, Curve::ORDER);

    // 6. R = [u1]G + [u2]Q via SECP256R1_ADD / DBL with Shamir's trick.
    const ZiskR1Point G_pt = zisk_r1_G_const();
    const ZiskR1Point Q_pt{
        {qx[0], qx[1], qx[2], qx[3]},
        {qy[0], qy[1], qy[2], qy[3]},
    };
    ZiskR1Point R;
    zisk_r1_mul2(R, G_pt, u1, Q_pt, u2);
    if (zisk_r1_is_zero(R)) [[unlikely]]
        return false;

    // 7. r ≡ R.x (mod n).
    uint256 x1;
    x1[0] = R.x[0]; x1[1] = R.x[1]; x1[2] = R.x[2]; x1[3] = R.x[3];
    if (x1 >= Curve::ORDER)
        x1 -= Curve::ORDER;
    return x1 == r;
}
}  // namespace
#endif

bool verify(const ethash::hash256& h, const uint256& r, const uint256& s, const uint256& qx,
    const uint256& qy) noexcept
{
#ifdef ZISK
    return verify_zisk(h, r, s, qx, qy);
#else
    // The implementation follows "Elliptic Curve Digital Signature Algorithm"
    // https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_verification_algorithm
    // but EIP-7951 spec is also a good source:
    // https://eips.ethereum.org/EIPS/eip-7951#signature-verification-algorithm

    // 1. Validate r and s are within [1, n-1].
    if (r == 0 || r >= Curve::ORDER || s == 0 || s >= Curve::ORDER)
        return false;

    // Check that Q is not equal to the identity element O, and its coordinates are otherwise valid.
    if (qx >= Curve::FIELD_PRIME || qy >= Curve::FIELD_PRIME)
        return false;
    const AffinePoint Q{AffinePoint::FE{qx}, AffinePoint::FE{qy}};
    if (Q == 0)
        return false;

    // Check that Q lies on the curve.
    if (!is_on_curve(Q))
        return false;

    const ModArith n{Curve::ORDER};

    // 3. Let z be the Lₙ leftmost bits of e = HASH(m).
    static_assert(Curve::ORDER > 1_u256 << 255);
    const auto z = intx::be::load<uint256>(h.bytes);

    // 4. Calculate u₁ = zs⁻¹ mod n and u₂ = rs⁻¹ mod n.
    const auto s_inv = n.inv(n.to_mont(s));
    const auto u1 = n.from_mont(n.mul(n.to_mont(z), s_inv));
    const auto u2 = n.from_mont(n.mul(n.to_mont(r), s_inv));

    // 5. Calculate the curve point R = (x₁, y₁) = u₁×G + u₂×Q.
    const auto R = ecc::to_affine(msm(u1, G, u2, Q));

    //    If R is at infinity, the signature is invalid.
    //    In this case x₁ is 0 and cannot be equal to r.
    // 6. The signature is valid if r ≡ x₁ (mod n).
    auto x1 = R.x.value();
    if (x1 >= Curve::ORDER)
        x1 -= Curve::ORDER;

    return x1 == r;
#endif
}
}  // namespace evmmax::secp256r1
