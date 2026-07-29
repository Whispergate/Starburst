#include <common.h>
#include <strings.h>

using namespace stardust;

auto declfn starburst::str_len(
    _In_ const char* str
) -> uint32_t {
    uint32_t len = 0;
    while ( str[len] ) len++;
    return len;
}

auto declfn starburst::wstr_len(
    _In_ const wchar_t* str
) -> uint32_t {
    uint32_t len = 0;
    while ( str[len] ) len++;
    return len;
}

auto declfn starburst::str_copy(
    _Out_ char*       dst,
    _In_  const char* src
) -> char* {
    char* ret = dst;
    while ( (*dst++ = *src++) );
    return ret;
}

auto declfn starburst::str_concat(
    _Out_ char*       dst,
    _In_  const char* src
) -> char* {
    char* ret = dst;
    while ( *dst ) dst++;
    while ( (*dst++ = *src++) );
    return ret;
}

auto declfn starburst::str_cmp(
    _In_ const char* a,
    _In_ const char* b
) -> int {
    while ( *a && *a == *b ) {
        a++;
        b++;
    }
    return *reinterpret_cast<const uint8_t*>(a) - *reinterpret_cast<const uint8_t*>(b);
}

auto declfn starburst::str_ncmp(
    _In_ const char* a,
    _In_ const char* b,
    _In_ uint32_t    n
) -> int {
    for ( uint32_t i = 0; i < n; i++ ) {
        uint8_t ca = reinterpret_cast<const uint8_t*>(a)[i];
        uint8_t cb = reinterpret_cast<const uint8_t*>(b)[i];
        if ( ca != cb ) return ca - cb;
        if ( ca == 0 ) return 0;
    }
    return 0;
}

auto declfn starburst::int_to_str(
    _Out_ char*    buf,
    _In_  uint32_t val,
    _In_  int      base
) -> char* {
    char  tmp[12];
    int   i = 0;

    if ( val == 0 ) {
        buf[0] = '0';
        buf[1] = '\0';
        return buf;
    }

    while ( val > 0 ) {
        uint32_t digit = val % base;
        tmp[i++] = digit < 10 ? '0' + digit : 'a' + digit - 10;
        val /= base;
    }

    int j = 0;
    while ( i > 0 ) {
        buf[j++] = tmp[--i];
    }
    buf[j] = '\0';

    return buf;
}

auto declfn starburst::str_to_int(
    _In_ const char* str
) -> uint32_t {
    uint32_t result = 0;
    while ( *str >= '0' && *str <= '9' ) {
        result = result * 10 + (*str - '0');
        str++;
    }
    return result;
}

auto declfn starburst::mem_set(
    _Out_ void*    dst,
    _In_  uint8_t  val,
    _In_  uint32_t len
) -> void* {
    auto p = static_cast<uint8_t*>( dst );
    for ( uint32_t i = 0; i < len; i++ ) {
        p[i] = val;
    }
    return dst;
}
