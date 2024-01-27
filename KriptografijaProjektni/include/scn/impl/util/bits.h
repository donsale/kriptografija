// Copyright 2017 Elias Kosunen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is a part of scnlib:
//     https://github.com/eliaskosunen/scnlib

#pragma once

#include <scn/fwd.h>

#include <cstdint>

#if SCN_HAS_BITOPS
#include <bit>
#elif SCN_MSVC
#include <IntSafe.h>
#include <intrin.h>
#elif SCN_POSIX && !SCN_GCC_COMPAT

SCN_CLANG_PUSH
SCN_CLANG_IGNORE("-Wreserved-id-macro")
#define _XOPEN_SOURCE 700
SCN_CLANG_POP

#include <strings.h>
#endif

namespace scn {
SCN_BEGIN_NAMESPACE

namespace impl {
inline int count_trailing_zeroes(uint64_t val)
{
    SCN_EXPECT(val != 0);
#if SCN_HAS_BITOPS
    return std::countr_zero(val);
#elif SCN_GCC_COMPAT
    return __builtin_ctzll(val);
#elif SCN_MSVC && SCN_WINDOWS_64BIT
    DWORD ret{};
    _BitScanForward64(&ret, val);
    return static_cast<int>(ret);
#elif SCN_MSVC && !SCN_WINDOWS_64BIT
    DWORD ret{};
    if (_BitScanForward(&ret, static_cast<uint32_t>(val))) {
        return static_cast<int>(ret);
    }

    _BitScanForward(&ret, static_cast<uint32_t>(val >> 32));
    return static_cast<int>(ret + 32);
#elif SCN_POSIX
    return ::ctzll(val);
#else
#define SCN_HAS_BITS_CTZ 0
    SCN_EXPECT(false);
    SCN_UNREACHABLE;
#endif
}

#ifndef SCN_HAS_BITS_CTZ
#define SCN_HAS_BITS_CTZ 1
#endif

constexpr uint64_t has_zero_byte(uint64_t word)
{
    return (word - 0x0101010101010101ull) & ~word & 0x8080808080808080ull;
}

constexpr uint64_t has_byte_between(uint64_t word, uint8_t a, uint8_t b)
{
    const auto m = static_cast<uint64_t>(a) - 1,
               n = static_cast<uint64_t>(b) + 1;
    return (((~0ull / 255 * (127 + (n)) - ((word) & ~0ull / 255 * 127)) &
             ~(word) &
             (((word) & ~0ull / 255 * 127) + ~0ull / 255 * (127 - (m)))) &
            (~0ull / 255 * 128));
}

constexpr uint64_t has_byte_greater(uint64_t word, uint8_t n)
{
    return (word + ~0ull / 255 * (127 - n) | word) & ~0ull / 255 * 128;
}

inline size_t get_index_of_first_nonmatching_byte(uint64_t word)
{
    word ^= 0x8080808080808080ull;
    if (word == 0) {
        return 8;
    }
    return static_cast<size_t>(count_trailing_zeroes(word)) / 8;
}

inline size_t get_index_of_first_matching_byte(uint64_t word, uint64_t pattern)
{
    constexpr auto mask = 0x7f7f7f7f7f7f7f7full;
    auto input = word ^ pattern;
    auto tmp = (input & mask) + mask;
    tmp = ~(tmp | input | mask);
    return static_cast<size_t>(count_trailing_zeroes(tmp)) / 8;
}

constexpr uint32_t log2_fast(uint32_t val)
{
    constexpr uint8_t lookup[] = {0,  9,  1,  10, 13, 21, 2,  29, 11, 14, 16,
                                  18, 22, 25, 3,  30, 8,  12, 20, 28, 15, 17,
                                  24, 7,  19, 27, 23, 6,  26, 5,  4,  31};

    val |= val >> 1;
    val |= val >> 2;
    val |= val >> 4;
    val |= val >> 8;
    val |= val >> 16;

    return static_cast<uint32_t>(lookup[(val * 0x07c4acddu) >> 27]);
}

constexpr uint32_t log2_pow2_fast(uint32_t val)
{
    constexpr uint8_t lookup[] = {0,  1,  28, 2,  29, 14, 24, 3,  30, 22, 20,
                                  15, 25, 17, 4,  8,  31, 27, 13, 23, 21, 19,
                                  16, 7,  26, 12, 18, 6,  11, 5,  10, 9};

    return static_cast<uint32_t>(lookup[(val * 0x077cb531u) >> 27]);
}

constexpr uint64_t byteswap(uint64_t val)
{
    return (val & 0xFF00000000000000) >> 56 | (val & 0x00FF000000000000) >> 40 |
           (val & 0x0000FF0000000000) >> 24 | (val & 0x000000FF00000000) >> 8 |
           (val & 0x00000000FF000000) << 8 | (val & 0x0000000000FF0000) << 24 |
           (val & 0x000000000000FF00) << 40 | (val & 0x00000000000000FF) << 56;
}
}  // namespace impl

SCN_END_NAMESPACE
}  // namespace scn
