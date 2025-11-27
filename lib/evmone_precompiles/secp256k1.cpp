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
constexpr auto B = Curve::Fp.to_mont(7);

constexpr AffinePoint G{0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256};
}  // namespace

// FIXME: Change to "uncompress_point".
std::optional<uint256> calculate_y(
    const ModArith<uint256>& m, const uint256& x, bool y_parity) noexcept
{
    // Calculate sqrt(x^3 + 7)
    const auto x3 = m.mul(m.mul(x, x), x);
    const auto y = field_sqrt(m, m.add(x3, B));
    if (!y.has_value())
        return std::nullopt;

    // Negate if different parity requested
    const auto candidate_parity = (m.from_mont(*y) & 1) != 0;
    return (candidate_parity == y_parity) ? *y : m.sub(0, *y);
}

#if defined(SP1TURBO) || defined(SP1)


// extern "C" void sys_bigint(uint64_t result[4],
//                 uint64_t op,
//                 const uint64_t x[4],
//                 const uint64_t y[4],
//                 const uint64_t modulus[4]);

inline void sp1_mulmod(uint64_t result[4], const uint64_t x[4], const uint64_t y[4])
{
    sys_bigint(result, 2, x, y, as_words(Curve::FIELD_PRIME));
}

inline void sp1_mulmod(uint256& result, const uint256& x, const uint256& y)
{
    sys_bigint(as_words(result), 2, as_words(x), as_words(y), as_words(Curve::FIELD_PRIME));
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
    // Allocate Temporaries as uint64_t[4] arrays
    uint64_t z[4];
    uint64_t t0[4];
    uint64_t t1[4];
    uint64_t t2[4];
    uint64_t t3[4];


    // Copy input x to uint64_t[4] format
    auto x_arr = as_words(x);

    // Step 1: z = x^0x2
    sp1_mulmod(z, x_arr, x_arr);

    // Step 2: z = x^0x3
    sp1_mulmod(z, x_arr, z);

    // Step 4: t0 = x^0xc
    sp1_mulmod(t0, z, z);
    for (int i = 1; i < 2; ++i)
        sp1_mulmod(t0, t0, t0);

    // Step 5: t0 = x^0xf
    sp1_mulmod(t0, z, t0);

    // Step 6: t1 = x^0x1e
    sp1_mulmod(t1, t0, t0);

    // Step 7: t2 = x^0x1f
    sp1_mulmod(t2, x_arr, t1);

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
    uint64_t z_squared[4];
    sp1_mulmod(z_squared, z, z);

    uint256 result(z[0], z[1], z[2], z[3]);
    uint256 z_sq_check(z_squared[0], z_squared[1], z_squared[2], z_squared[3]);

    if (z_sq_check != x)
        return std::nullopt;  // Computed value is not the square root.

    return result;
}


/// Decompress a secp256k1 point from x-coordinate and y-parity (SP1 version).
/// Returns y-coordinate in regular (non-Montgomery) form, or nullopt if x is not on curve.
/// This version uses SP1 syscalls which operate on regular form values.

std::optional<uint256> decompress(const uint256& x, bool y_parity) noexcept
{
    static constexpr auto& Fp = Curve::Fp;

    // Calculate x^3 + 7 
    const auto B_regular = Fp.from_mont(B);

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


AffinePoint mul(const AffinePoint& p, const uint256& c) noexcept
{
    const auto r = ecc::mul(p, c);
    return ecc::to_affine<Curve>(r);
}

evmc::address to_address(const AffinePoint& pt) noexcept
{
    // This performs Ethereum's address hashing on an uncompressed pubkey.
    uint8_t serialized[64];
    pt.to_bytes(serialized);

    const auto hashed = ethash::keccak256(serialized, sizeof(serialized));
    evmc::address ret{};
    std::memcpy(ret.bytes, hashed.bytes + 12, 20);

    return ret;
}

#if defined(SP1TURBO) || defined(SP1)
namespace
{
constexpr auto Gx = G.x.value();
constexpr auto Gy = G.y.value();

#ifdef SP1TURBO
constexpr size_t SP1_POINT_SIZE = 16;
// SP1TURBO uses 32-bit
constexpr sp1_AffinePoint sp1_G = {
    static_cast<uint32_t>(Gx[0]),
    static_cast<uint32_t>(Gx[0] >> 32),
    static_cast<uint32_t>(Gx[1]),
    static_cast<uint32_t>(Gx[1] >> 32),
    static_cast<uint32_t>(Gx[2]),
    static_cast<uint32_t>(Gx[2] >> 32),
    static_cast<uint32_t>(Gx[3]),
    static_cast<uint32_t>(Gx[3] >> 32),
    static_cast<uint32_t>(Gy[0]),
    static_cast<uint32_t>(Gy[0] >> 32),
    static_cast<uint32_t>(Gy[1]),
    static_cast<uint32_t>(Gy[1] >> 32),
    static_cast<uint32_t>(Gy[2]),
    static_cast<uint32_t>(Gy[2] >> 32),
    static_cast<uint32_t>(Gy[3]),
    static_cast<uint32_t>(Gy[3] >> 32),
};


uint256 sp1_to_uint256(const uint32_t v[8]) noexcept
{
    return uint256{uint64_t(v[0]) | (uint64_t(v[1]) << 32), uint64_t(v[2]) | (uint64_t(v[3]) << 32),
        uint64_t(v[4]) | (uint64_t(v[5]) << 32), uint64_t(v[6]) | (uint64_t(v[7]) << 32)};
}


#elif defined(SP1)
constexpr size_t SP1_POINT_SIZE = 8;
// HyperCube uses 64-bit
constexpr sp1_AffinePoint sp1_G = {
    Gx[0],
    Gx[1],
    Gx[2],
    Gx[3],
    Gy[0],
    Gy[1],
    Gy[2],
    Gy[3],
};

#endif

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


std::optional<AffinePoint> secp256k1_ecdsa_recover(
    const ethash::hash256& e, const uint256& r, const uint256& s, bool v) noexcept
{
    // Follows
    // https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Public_key_recovery

    // 1. Validate r and s are within [1, n-1].
    if (r == 0 || r >= Curve::ORDER || s == 0 || s >= Curve::ORDER)
        return std::nullopt;

    // 3. Hash of the message is already calculated in e.
    // 4. Convert hash e to z field element by doing z = e % n.
    //    https://www.rfc-editor.org/rfc/rfc6979#section-2.3.2
    //    We can do this by n - e because n > 2^255.
    static_assert(Curve::ORDER > 1_u256 << 255);
    auto z = intx::be::load<uint256>(e.bytes);
    if (z >= Curve::ORDER)
        z -= Curve::ORDER;

    const ModArith n{Curve::ORDER};

    // 5. Calculate u1 and u2.
    const auto r_n = n.to_mont(r);
    const auto r_inv = n.inv(r_n);

    const auto z_mont = n.to_mont(z);
    const auto z_neg = n.sub(0, z_mont);
    const auto u1_mont = n.mul(z_neg, r_inv);
    const auto u1 = n.from_mont(u1_mont);

    const auto s_mont = n.to_mont(s);
    const auto u2_mont = n.mul(s_mont, r_inv);
    const auto u2 = n.from_mont(u2_mont);
    assert(u2 != 0);  // Because s != 0 and r_inv != 0.

    // 2. Calculate y coordinate of R from r and v.
    static constexpr auto& Fp = Curve::Fp;
    const auto r_mont = Fp.to_mont(r);
    const auto y_mont = calculate_y(Fp, r_mont, v);
    if (!y_mont.has_value())
        return std::nullopt;

    // 6. Calculate public key point Q.
    const auto R = AffinePoint{AffinePoint::FE::wrap(r_mont), AffinePoint::FE::wrap(*y_mont)};
    // u1 and u2 are less than `Curve::ORDER`, so the multiplications will not reduce.
    const auto T1 = ecc::mul(G, u1);
    const auto T2 = ecc::mul(R, u2);
    assert(T2 != 0);  // Because u2 != 0 and R != 0.
    const auto pQ = ecc::add(T1, T2);

    const auto Q = ecc::to_affine<Curve>(pQ);

    if (Q == 0)
        return std::nullopt;

    return Q;
}

std::optional<evmc::address> ecrecover(
    const ethash::hash256& e, const uint256& r, const uint256& s, bool v) noexcept
{
#if defined(SP1TURBO) || defined(SP1)
    // First part: copy-paste code from secp256k1_ecdsa_recover()
    if (r == 0 || r >= Curve::ORDER || s == 0 || s >= Curve::ORDER)
        return std::nullopt;

    static_assert(Curve::ORDER > 1_u256 << 255);
    auto z = intx::be::load<uint256>(e.bytes);
    if (z >= Curve::ORDER)
        z -= Curve::ORDER;

    const ModArith n{Curve::ORDER};

    const auto r_n = n.to_mont(r);
    const auto r_inv = n.inv(r_n);

    const auto z_mont = n.to_mont(z);
    const auto z_neg = n.sub(0, z_mont);
    const auto u1_mont = n.mul(z_neg, r_inv);
    const auto u1 = n.from_mont(u1_mont);

    const auto s_mont = n.to_mont(s);
    const auto u2_mont = n.mul(s_mont, r_inv);
    const auto u2 = n.from_mont(u2_mont);
    assert(u2 != 0);  // Because s != 0 and r_inv != 0.

    // Second part: handle the points.
#ifdef SP1TURBO
    // SP1TURBO: decompress syscall takes uint8_t[64]
    uint8_t sp1_Rbytes[64]{};
    intx::be::unsafe::store(&sp1_Rbytes[0], r);
    syscall_secp256k1_decompress(sp1_Rbytes, v);
    const auto y_sp1 = intx::be::unsafe::load<uint256>(&sp1_Rbytes[32]);
    if (y_sp1 == 0)
        return std::nullopt;

    sp1_AffinePoint sp1_R;
    sp1_point_from_bytes(sp1_R, sp1_Rbytes);

#else
    // SP1 Hypercube no longer has the secp256k1_decompress precompile
    const auto y = decompress(r, v);
    if (!y.has_value())
        return std::nullopt;

    sp1_AffinePoint sp1_R{};
    for (size_t i = 0; i < 4; ++i)
        sp1_R[i] = r[i];

    for (size_t i = 4; i < 8; ++i)
        sp1_R[i] = (*y)[i - 4];

#endif

    sp1_AffinePoint sp1_T1;
    sp1_mul(sp1_T1, sp1_G, u1);
    sp1_AffinePoint sp1_T2;
    sp1_mul(sp1_T2, sp1_R, u2);

    // FIXME: This can be double, in this case SP1 runtime panics.
    sp1_AffinePoint sp1_Q;
    std::copy_n(sp1_T1, SP1_POINT_SIZE, sp1_Q);
    syscall_secp256k1_add(sp1_Q, sp1_T2);

    if (is_zero(sp1_Q))
        return std::nullopt;

    // Third part: hash it.
    uint8_t serialized[64];
    sp1_point_to_bytes(serialized, sp1_Q);

    const auto hashed = ethash::keccak256(serialized, sizeof(serialized));
    evmc::address ret{};
    std::memcpy(ret.bytes, hashed.bytes + 12, 20);
    return ret;
#else
    const auto point = secp256k1_ecdsa_recover(e, r, s, v);
    if (!point.has_value())
        return std::nullopt;

    return to_address(*point);
#endif
}

std::optional<uint256> field_sqrt(const ModArith<uint256>& m, const uint256& x) noexcept
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
    uint256 z;
    uint256 t0;
    uint256 t1;
    uint256 t2;
    uint256 t3;


    // Step 1: z = x^0x2
    z = m.mul(x, x);

    // Step 2: z = x^0x3
    z = m.mul(x, z);

    // Step 4: t0 = x^0xc
    t0 = m.mul(z, z);
    for (int i = 1; i < 2; ++i)
        t0 = m.mul(t0, t0);

    // Step 5: t0 = x^0xf
    t0 = m.mul(z, t0);

    // Step 6: t1 = x^0x1e
    t1 = m.mul(t0, t0);

    // Step 7: t2 = x^0x1f
    t2 = m.mul(x, t1);

    // Step 9: t1 = x^0x7c
    t1 = m.mul(t2, t2);
    for (int i = 1; i < 2; ++i)
        t1 = m.mul(t1, t1);

    // Step 10: t1 = x^0x7f
    t1 = m.mul(z, t1);

    // Step 14: t3 = x^0x7f0
    t3 = m.mul(t1, t1);
    for (int i = 1; i < 4; ++i)
        t3 = m.mul(t3, t3);

    // Step 15: t0 = x^0x7ff
    t0 = m.mul(t0, t3);

    // Step 26: t3 = x^0x3ff800
    t3 = m.mul(t0, t0);
    for (int i = 1; i < 11; ++i)
        t3 = m.mul(t3, t3);

    // Step 27: t0 = x^0x3fffff
    t0 = m.mul(t0, t3);

    // Step 32: t3 = x^0x7ffffe0
    t3 = m.mul(t0, t0);
    for (int i = 1; i < 5; ++i)
        t3 = m.mul(t3, t3);

    // Step 33: t2 = x^0x7ffffff
    t2 = m.mul(t2, t3);

    // Step 60: t3 = x^0x3ffffff8000000
    t3 = m.mul(t2, t2);
    for (int i = 1; i < 27; ++i)
        t3 = m.mul(t3, t3);

    // Step 61: t2 = x^0x3fffffffffffff
    t2 = m.mul(t2, t3);

    // Step 115: t3 = x^0xfffffffffffffc0000000000000
    t3 = m.mul(t2, t2);
    for (int i = 1; i < 54; ++i)
        t3 = m.mul(t3, t3);

    // Step 116: t2 = x^0xfffffffffffffffffffffffffff
    t2 = m.mul(t2, t3);

    // Step 224: t3 = x^0xfffffffffffffffffffffffffff000000000000000000000000000
    t3 = m.mul(t2, t2);
    for (int i = 1; i < 108; ++i)
        t3 = m.mul(t3, t3);

    // Step 225: t2 = x^0xffffffffffffffffffffffffffffffffffffffffffffffffffffff
    t2 = m.mul(t2, t3);

    // Step 232: t2 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff80
    for (int i = 0; i < 7; ++i)
        t2 = m.mul(t2, t2);

    // Step 233: t1 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff
    t1 = m.mul(t1, t2);

    // Step 256: t1 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
    for (int i = 0; i < 23; ++i)
        t1 = m.mul(t1, t1);

    // Step 257: t0 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff
    t0 = m.mul(t0, t1);

    // Step 263: t0 = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc0
    for (int i = 0; i < 6; ++i)
        t0 = m.mul(t0, t0);

    // Step 264: z = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc3
    z = m.mul(z, t0);

    // Step 266: z = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
    for (int i = 0; i < 2; ++i)
        z = m.mul(z, z);

    if (m.mul(z, z) != x)
        return std::nullopt;  // Computed value is not the square root.

    return z;
}


}  // namespace evmmax::secp256k1
