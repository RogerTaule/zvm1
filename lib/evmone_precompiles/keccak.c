// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018 Pawel Bylica.
// SPDX-License-Identifier: Apache-2.0

#include "keccak.h"

#ifdef SP1TURBO
void syscall_keccak_permute(uint64_t (*state)[25]);
#elif defined(SP1)
static inline __attribute__((always_inline)) void syscall_keccak_permute(uint64_t state[25])
{
    register uint64_t t0 asm("t0") = 0x00010109;
    register uint64_t* a0 asm("a0") = state;
    register uint64_t a1 asm("a1") = 0;
    asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");
}
#elif defined(ZISK)
/* Issue Zisk's keccak_f CSR syscall (id 0x800) on the 25-u64 state in
 * place. Inlined here so every call site emits a single `csrs` insn —
 * no jalr-through-function-pointer overhead like the generic dispatch.
 * Mirrors the SP1 ecall-based inline above. */
static inline __attribute__((always_inline)) void syscall_keccak_permute(uint64_t state[25])
{
    asm volatile("csrs 0x800, %0" : : "r"(state) : "memory");
}
#endif

// Provide __has_attribute macro if not defined.
#ifndef __has_attribute
#define __has_attribute(name) 0
#endif

// Provide __has_builtin macro if not defined.
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

// [[always_inline]]
#if defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#elif __has_attribute(always_inline)
#define ALWAYS_INLINE __attribute__((always_inline))
#else
#define ALWAYS_INLINE
#endif

#if !__has_builtin(__builtin_memcpy) && !defined(__GNUC__)
#include <string.h>
#define __builtin_memcpy memcpy
#endif

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define to_le64(X) __builtin_bswap64(X)
#else
#define to_le64(X) X
#endif

/// Loads 64-bit integer from given memory location as little-endian number.
static inline ALWAYS_INLINE uint64_t load_le(const uint8_t* data)
{
    /* memcpy is the best way of expressing the intention. Every compiler will
       optimize is to single load instruction if the target architecture
       supports unaligned memory access (GCC and clang even in O0).
       This is great trick because we are violating C/C++ memory alignment
       restrictions with no performance penalty. */
    uint64_t word;
    __builtin_memcpy(&word, data, sizeof(word));
    return to_le64(word);
}

/// Rotates the bits of x left by the count value specified by s.
/// The s must be in range <0, 64> exclusively, otherwise the result is undefined.
static inline uint64_t rol(uint64_t x, unsigned s)
{
    return (x << s) | (x >> (64 - s));
}

static const uint64_t round_constants[24] = {  //
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};


/// The Keccak-f[1600] function.
///
/// The implementation of the Keccak-f function with 1600-bit width of the permutation (b).
/// The size of the state is also 1600 bit what gives 25 64-bit words.
///
/// @param state  The state of 25 64-bit words on which the permutation is to be performed.
///
/// The implementation based on:
/// - "simple" implementation by Ronny Van Keer, included in "Reference and optimized code in C",
///   https://keccak.team/archives.html, CC0-1.0 / Public Domain.
static inline ALWAYS_INLINE void keccakf1600_implementation(uint64_t state[25])
{
    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;

    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    uint64_t Ba, Be, Bi, Bo, Bu;

    uint64_t Da, De, Di, Do, Du;

    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for (size_t n = 0; n < 24; n += 2)
    {
        // Round (n + 0): Axx -> Exx

        Ba = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        Be = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        Bi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        Bo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        Bu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        Da = Bu ^ rol(Be, 1);
        De = Ba ^ rol(Bi, 1);
        Di = Be ^ rol(Bo, 1);
        Do = Bi ^ rol(Bu, 1);
        Du = Bo ^ rol(Ba, 1);

        Ba = Aba ^ Da;
        Be = rol(Age ^ De, 44);
        Bi = rol(Aki ^ Di, 43);
        Bo = rol(Amo ^ Do, 21);
        Bu = rol(Asu ^ Du, 14);
        Eba = Ba ^ (~Be & Bi) ^ round_constants[n];
        Ebe = Be ^ (~Bi & Bo);
        Ebi = Bi ^ (~Bo & Bu);
        Ebo = Bo ^ (~Bu & Ba);
        Ebu = Bu ^ (~Ba & Be);

        Ba = rol(Abo ^ Do, 28);
        Be = rol(Agu ^ Du, 20);
        Bi = rol(Aka ^ Da, 3);
        Bo = rol(Ame ^ De, 45);
        Bu = rol(Asi ^ Di, 61);
        Ega = Ba ^ (~Be & Bi);
        Ege = Be ^ (~Bi & Bo);
        Egi = Bi ^ (~Bo & Bu);
        Ego = Bo ^ (~Bu & Ba);
        Egu = Bu ^ (~Ba & Be);

        Ba = rol(Abe ^ De, 1);
        Be = rol(Agi ^ Di, 6);
        Bi = rol(Ako ^ Do, 25);
        Bo = rol(Amu ^ Du, 8);
        Bu = rol(Asa ^ Da, 18);
        Eka = Ba ^ (~Be & Bi);
        Eke = Be ^ (~Bi & Bo);
        Eki = Bi ^ (~Bo & Bu);
        Eko = Bo ^ (~Bu & Ba);
        Eku = Bu ^ (~Ba & Be);

        Ba = rol(Abu ^ Du, 27);
        Be = rol(Aga ^ Da, 36);
        Bi = rol(Ake ^ De, 10);
        Bo = rol(Ami ^ Di, 15);
        Bu = rol(Aso ^ Do, 56);
        Ema = Ba ^ (~Be & Bi);
        Eme = Be ^ (~Bi & Bo);
        Emi = Bi ^ (~Bo & Bu);
        Emo = Bo ^ (~Bu & Ba);
        Emu = Bu ^ (~Ba & Be);

        Ba = rol(Abi ^ Di, 62);
        Be = rol(Ago ^ Do, 55);
        Bi = rol(Aku ^ Du, 39);
        Bo = rol(Ama ^ Da, 41);
        Bu = rol(Ase ^ De, 2);
        Esa = Ba ^ (~Be & Bi);
        Ese = Be ^ (~Bi & Bo);
        Esi = Bi ^ (~Bo & Bu);
        Eso = Bo ^ (~Bu & Ba);
        Esu = Bu ^ (~Ba & Be);


        // Round (n + 1): Exx -> Axx

        Ba = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        Be = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        Bi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        Bo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        Bu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        Da = Bu ^ rol(Be, 1);
        De = Ba ^ rol(Bi, 1);
        Di = Be ^ rol(Bo, 1);
        Do = Bi ^ rol(Bu, 1);
        Du = Bo ^ rol(Ba, 1);

        Ba = Eba ^ Da;
        Be = rol(Ege ^ De, 44);
        Bi = rol(Eki ^ Di, 43);
        Bo = rol(Emo ^ Do, 21);
        Bu = rol(Esu ^ Du, 14);
        Aba = Ba ^ (~Be & Bi) ^ round_constants[n + 1];
        Abe = Be ^ (~Bi & Bo);
        Abi = Bi ^ (~Bo & Bu);
        Abo = Bo ^ (~Bu & Ba);
        Abu = Bu ^ (~Ba & Be);

        Ba = rol(Ebo ^ Do, 28);
        Be = rol(Egu ^ Du, 20);
        Bi = rol(Eka ^ Da, 3);
        Bo = rol(Eme ^ De, 45);
        Bu = rol(Esi ^ Di, 61);
        Aga = Ba ^ (~Be & Bi);
        Age = Be ^ (~Bi & Bo);
        Agi = Bi ^ (~Bo & Bu);
        Ago = Bo ^ (~Bu & Ba);
        Agu = Bu ^ (~Ba & Be);

        Ba = rol(Ebe ^ De, 1);
        Be = rol(Egi ^ Di, 6);
        Bi = rol(Eko ^ Do, 25);
        Bo = rol(Emu ^ Du, 8);
        Bu = rol(Esa ^ Da, 18);
        Aka = Ba ^ (~Be & Bi);
        Ake = Be ^ (~Bi & Bo);
        Aki = Bi ^ (~Bo & Bu);
        Ako = Bo ^ (~Bu & Ba);
        Aku = Bu ^ (~Ba & Be);

        Ba = rol(Ebu ^ Du, 27);
        Be = rol(Ega ^ Da, 36);
        Bi = rol(Eke ^ De, 10);
        Bo = rol(Emi ^ Di, 15);
        Bu = rol(Eso ^ Do, 56);
        Ama = Ba ^ (~Be & Bi);
        Ame = Be ^ (~Bi & Bo);
        Ami = Bi ^ (~Bo & Bu);
        Amo = Bo ^ (~Bu & Ba);
        Amu = Bu ^ (~Ba & Be);

        Ba = rol(Ebi ^ Di, 62);
        Be = rol(Ego ^ Do, 55);
        Bi = rol(Eku ^ Du, 39);
        Bo = rol(Ema ^ Da, 41);
        Bu = rol(Ese ^ De, 2);
        Asa = Ba ^ (~Be & Bi);
        Ase = Be ^ (~Bi & Bo);
        Asi = Bi ^ (~Bo & Bu);
        Aso = Bo ^ (~Bu & Ba);
        Asu = Bu ^ (~Ba & Be);
    }

    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

static void keccakf1600_generic(uint64_t state[25])
{
    keccakf1600_implementation(state);
}

/// The pointer to the best Keccak-f[1600] function implementation,
/// selected during runtime initialization.
#if defined(SP1TURBO) || defined(SP1) || defined(ZISK)
#define DEFAULT_keccakf1600 syscall_keccak_permute
#else
#define DEFAULT_keccakf1600 keccakf1600_generic
#endif

#if defined(ZISK)
/* Skip the function-pointer indirection entirely on ZISK: the syscall
 * is always available and inlines down to a single `csrs` instruction.
 * Routing every keccak() call through a static function pointer would
 * cost a load + jalr + ret per call (~5-7 insns of overhead) for no
 * runtime-selection benefit. */
#define keccakf1600_best syscall_keccak_permute
#else
static void (*keccakf1600_best)(uint64_t[25]) = DEFAULT_keccakf1600;
#endif


#if !defined(_MSC_VER) && defined(__x86_64__) && __has_attribute(target)
__attribute__((target("bmi,bmi2"))) static void keccakf1600_bmi(uint64_t state[25])
{
    keccakf1600_implementation(state);
}

__attribute__((constructor)) static void select_keccakf1600_implementation(void)
{
    // Init CPU information.
    // This is needed on macOS because of the bug: https://bugs.llvm.org/show_bug.cgi?id=48459.
    __builtin_cpu_init();

    // Check if both BMI and BMI2 are supported. Some CPUs like Intel E5-2697 v2 incorrectly
    // report BMI2 but not BMI being available.
    if (__builtin_cpu_supports("bmi") && __builtin_cpu_supports("bmi2"))
        keccakf1600_best = keccakf1600_bmi;
}
#endif


static inline ALWAYS_INLINE void keccak(
    uint64_t* out, size_t bits, const uint8_t* data, size_t size)
{
    static const size_t word_size = sizeof(uint64_t);
    const size_t hash_size = bits / 8;
    const size_t block_size = (1600 - bits * 2) / 8;

    size_t i;
    uint64_t* state_iter;
    uint64_t last_word = 0;
    uint8_t* last_word_iter = (uint8_t*)&last_word;

    uint64_t state[25] = {0};

    while (size >= block_size)
    {
        for (i = 0; i < (block_size / word_size); ++i)
        {
            state[i] ^= load_le(data);
            data += word_size;
        }

        keccakf1600_best(state);

        size -= block_size;
    }

    state_iter = state;

    while (size >= word_size)
    {
        *state_iter ^= load_le(data);
        ++state_iter;
        data += word_size;
        size -= word_size;
    }

    while (size > 0)
    {
        *last_word_iter = *data;
        ++last_word_iter;
        ++data;
        --size;
    }
    *last_word_iter = 0x01;
    *state_iter ^= to_le64(last_word);

    state[(block_size / word_size) - 1] ^= 0x8000000000000000;

    keccakf1600_best(state);

    for (i = 0; i < (hash_size / word_size); ++i)
        out[i] = to_le64(state[i]);
}

#ifdef ZISK
/* ─── Small-input keccak content cache (ZISK only) ────────────────────
 *
 * A keccak256 call costs ~190 K Zisk cost on average (one or more
 * keccakf permutation syscalls plus the padding / state-init wrapper).
 * Profiling block 25,146,162 (23,719 keccak calls) with a content
 * fingerprint shows that 17.4 % of calls were duplicates by content,
 * concentrated almost entirely in the 20- / 32- / 64-byte size buckets:
 *
 *   size 64 — 4,033 calls, 55.7 % duplicates  (EVM SHA3 of address||slot
 *                                              keys, ecrecover pk→address)
 *   size 32 — 2,186 calls, 52.1 % duplicates  (logs_bloom topic hashing)
 *   size 20 — 2,249 calls, 24.3 % duplicates  (logs_bloom addresses,
 *                                              state-root MPT key derivation)
 *
 * Top sources: EVM SHA3 opcode (~1,800 dup hits), logs_bloom (~800 hits)
 * and check_root state-root verification (~380 hits).
 *
 * A direct-mapped 256-entry cache covering inputs ≤ 64 bytes captures
 * ~4,128 invocations per heavy block. Each cache hit replaces a
 * ~190 K-cost keccak call with a ~80-cost FNV+memcmp+memcpy sequence.
 * Cache miss overhead is under 100 cost (≈0.05 %); inputs > 64 bytes
 * bypass the cache entirely and pay no overhead at all.
 *
 * Memory: 256 entries × ~104 B per entry = ~26 KB in .bss, zero-init
 * by default. An entry with `size == 0` is treated as empty (we never
 * cache size-0 inputs — keccak("") is a known constant and only
 * occurs as a parsing artefact). */
#define KECCAK_CACHE_BITS    12u
#define KECCAK_CACHE_SIZE    (1U << KECCAK_CACHE_BITS)
#define KECCAK_CACHE_MAX_IN  64u

typedef struct {
    uint8_t  input[KECCAK_CACHE_MAX_IN];
    uint64_t hash[4];
    uint32_t size;  /* 0 means slot empty */
} keccak_cache_entry_t;

static keccak_cache_entry_t keccak_cache[KECCAK_CACHE_SIZE];

__attribute__((always_inline)) static inline uint64_t keccak_fnv_hash(
    const uint8_t* data, size_t size)
{
    uint64_t h = 0xcbf29ce484222325UL;
    for (size_t i = 0; i < size; ++i)
        h = (h ^ data[i]) * 0x100000001b3UL;
    return h;
}

/* Constant-iteration u64-stride equality (size ≤ 64). Single memcmp call
 * via DMA would also work but the inlined u64 stride is cheaper for the
 * common small sizes where the cache fires. */
__attribute__((always_inline)) static inline int keccak_cache_eq(
    const uint8_t* a, const uint8_t* b, size_t n)
{
    size_t i = 0;
    while (i + 8 <= n) {
        uint64_t aa, bb;
        __builtin_memcpy(&aa, a + i, 8);
        __builtin_memcpy(&bb, b + i, 8);
        if (aa != bb) return 0;
        i += 8;
    }
    while (i < n) {
        if (a[i] != b[i]) return 0;
        ++i;
    }
    return 1;
}
#endif  /* ZISK */

union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size)
{
    union ethash_hash256 hash;

#ifdef ZISK
    if (size > 0 && size <= KECCAK_CACHE_MAX_IN) {
        const uint64_t key = keccak_fnv_hash(data, size);
        keccak_cache_entry_t* const e =
            &keccak_cache[key & (KECCAK_CACHE_SIZE - 1)];
        if (e->size == (uint32_t)size && keccak_cache_eq(e->input, data, size)) {
            hash.word64s[0] = e->hash[0];
            hash.word64s[1] = e->hash[1];
            hash.word64s[2] = e->hash[2];
            hash.word64s[3] = e->hash[3];
            return hash;
        }
        keccak(hash.word64s, 256, data, size);
        __builtin_memcpy(e->input, data, size);
        e->hash[0] = hash.word64s[0];
        e->hash[1] = hash.word64s[1];
        e->hash[2] = hash.word64s[2];
        e->hash[3] = hash.word64s[3];
        e->size = (uint32_t)size;
        return hash;
    }
#endif

    keccak(hash.word64s, 256, data, size);
    return hash;
}

union ethash_hash256 ethash_keccak256_32(const uint8_t data[32])
{
    union ethash_hash256 hash;

#ifdef ZISK
    /* Size is fixed at 32: skip the size check, use the same hash + lookup. */
    const uint64_t key = keccak_fnv_hash(data, 32);
    keccak_cache_entry_t* const e =
        &keccak_cache[key & (KECCAK_CACHE_SIZE - 1)];
    if (e->size == 32 && keccak_cache_eq(e->input, data, 32)) {
        hash.word64s[0] = e->hash[0];
        hash.word64s[1] = e->hash[1];
        hash.word64s[2] = e->hash[2];
        hash.word64s[3] = e->hash[3];
        return hash;
    }
    keccak(hash.word64s, 256, data, 32);
    __builtin_memcpy(e->input, data, 32);
    e->hash[0] = hash.word64s[0];
    e->hash[1] = hash.word64s[1];
    e->hash[2] = hash.word64s[2];
    e->hash[3] = hash.word64s[3];
    e->size = 32;
    return hash;
#else
    keccak(hash.word64s, 256, data, 32);
    return hash;
#endif
}
