#include <common.h>

typedef __SIZE_TYPE__ size_t_pic;

extern "C" {

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-prototypes"

__attribute__((section(".text$B")))
void* memset( void* dst, int val, size_t_pic len ) {
    auto p = static_cast<unsigned char*>( dst );
    for ( size_t_pic i = 0; i < len; i++ ) {
        p[i] = static_cast<unsigned char>( val );
    }
    return dst;
}

__attribute__((section(".text$B")))
void* memcpy( void* dst, const void* src, size_t_pic len ) {
    auto d = static_cast<unsigned char*>( dst );
    auto s = static_cast<const unsigned char*>( src );
    for ( size_t_pic i = 0; i < len; i++ ) {
        d[i] = s[i];
    }
    return dst;
}

__attribute__((section(".text$B")))
size_t_pic strlen( const char* s ) {
    size_t_pic len = 0;
    while ( s[len] ) len++;
    return len;
}

__attribute__((section(".text$B")))
size_t_pic wcslen( const wchar_t* s ) {
    size_t_pic len = 0;
    while ( s[len] ) len++;
    return len;
}

#ifndef _WIN64

typedef unsigned long long u64_div;
typedef long long          s64_div;

__attribute__((section(".text$B")))
u64_div __udivdi3( u64_div num, u64_div den )
{
    if ( den == 0 || den > num )
        return 0;

    u64_div quot = 0;
    u64_div rem  = 0;

    for ( int i = 63; i >= 0; i-- )
    {
        rem = ( rem << 1 ) | ( ( num >> i ) & 1 );
        if ( rem >= den )
        {
            rem  -= den;
            quot |= ( 1ULL << i );
        }
    }
    return quot;
}

__attribute__((section(".text$B")))
s64_div __divdi3( s64_div a, s64_div b )
{
    int neg = 0;
    u64_div ua, ub;

    if ( a < 0 ) { ua = (u64_div)( -a ); neg = 1; }
    else         { ua = (u64_div)a; }

    if ( b < 0 ) { ub = (u64_div)( -b ); neg ^= 1; }
    else         { ub = (u64_div)b; }

    u64_div result = __udivdi3( ua, ub );
    return neg ? -(s64_div)result : (s64_div)result;
}

__attribute__((section(".text$B")))
u64_div __umoddi3( u64_div num, u64_div den )
{
    return num - __udivdi3( num, den ) * den;
}

__attribute__((section(".text$B")))
s64_div __moddi3( s64_div a, s64_div b )
{
    return a - __divdi3( a, b ) * b;
}

#endif // !_WIN64

#pragma clang diagnostic pop

} // extern "C"
