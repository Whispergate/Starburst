#ifndef STARBURST_STRINGS_H
#define STARBURST_STRINGS_H

#include <common.h>

namespace starburst {

    auto declfn str_len(
        _In_ const char* str
    ) -> uint32_t;

    auto declfn wstr_len(
        _In_ const wchar_t* str
    ) -> uint32_t;

    auto declfn str_copy(
        _Out_ char*       dst,
        _In_  const char* src
    ) -> char*;

    auto declfn str_concat(
        _Out_ char*       dst,
        _In_  const char* src
    ) -> char*;

    auto declfn str_cmp(
        _In_ const char* a,
        _In_ const char* b
    ) -> int;

    auto declfn str_ncmp(
        _In_ const char* a,
        _In_ const char* b,
        _In_ uint32_t    n
    ) -> int;

    auto declfn int_to_str(
        _Out_ char*    buf,
        _In_  uint32_t val,
        _In_  int      base
    ) -> char*;

    auto declfn str_to_int(
        _In_ const char* str
    ) -> uint32_t;

    auto declfn mem_set(
        _Out_ void*    dst,
        _In_  uint8_t  val,
        _In_  uint32_t len
    ) -> void*;

}

#endif
