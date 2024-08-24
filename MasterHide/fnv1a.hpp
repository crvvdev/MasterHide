#pragma once

using FNV1A_t = ULONGLONG;

/*
 * 64-BIT FNV1A HASH
 */
namespace FNV1A
{
/* @section: [internal] constants */
constexpr FNV1A_t ullBasis = 0xCBF29CE484222325ULL;
constexpr FNV1A_t ullPrime = 0x100000001B3ULL;

/* @section: get */
/// @param[in] szString string for which you want to generate a hash
/// @param[in] uKey key of hash generation
/// @returns: calculated at compile-time hash of given string
consteval FNV1A_t HashConst(const char *szString, const FNV1A_t uKey = ullBasis) noexcept
{
    return (szString[0] == '\0') ? uKey
                                 : HashConst(&szString[1], (uKey ^ static_cast<FNV1A_t>(szString[0])) * ullPrime);
}

/// @param[in] szString string for which you want to generate a hash
/// @param[in] uKey key of hash generation
/// @returns: calculated at run-time hash of given string
inline FNV1A_t Hash(const char *szString, FNV1A_t uKey = ullBasis) noexcept
{

    const char *s;

    for (s = szString; *s; ++s)
    {
        uKey ^= *s;
        uKey *= ullPrime;
    }

    return uKey;
}
} // namespace FNV1A

#define FNV(s) FNV1A::HashConst(s)