#pragma once

using FNV1A_t = ULONGLONG;

namespace FNV1A
{
constexpr FNV1A_t ullBasis = 0xCBF29CE484222325ULL;
constexpr FNV1A_t ullPrime = 0x100000001B3ULL;

/// <param name="str">string for which you want to generate a hash</param>
/// <param name="key">key of hash generation</param>
/// <returns>FNV1A hash calculated at compile-time of given string</returns>
consteval FNV1A_t HashConst(const char *str, const FNV1A_t key = ullBasis) noexcept
{
    return (str[0] == '\0') ? key : HashConst(&str[1], (key ^ static_cast<FNV1A_t>(str[0])) * ullPrime);
}

/// <param name="str">string for which you want to generate a hash</param>
/// <param name="key">key of hash generation</param>
/// <returns>FNV1A hash calculated at run-time of given string</returns>
inline FNV1A_t Hash(const char *str, FNV1A_t key = ullBasis) noexcept
{
    const char *s;

    for (s = str; *s; ++s)
    {
        key ^= *s;
        key *= ullPrime;
    }

    return key;
}
} // namespace FNV1A

#define FNV(s) FNV1A::HashConst(s)