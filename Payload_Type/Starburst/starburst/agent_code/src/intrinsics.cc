#include <common.h>

typedef __SIZE_TYPE__ size_t_pic;

extern "C" {

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-prototypes"

void* memset( void* dst, int val, size_t_pic len ) {
    auto p = static_cast<unsigned char*>( dst );
    for ( size_t_pic i = 0; i < len; i++ ) {
        p[i] = static_cast<unsigned char>( val );
    }
    return dst;
}

void* memcpy( void* dst, const void* src, size_t_pic len ) {
    auto d = static_cast<unsigned char*>( dst );
    auto s = static_cast<const unsigned char*>( src );
    for ( size_t_pic i = 0; i < len; i++ ) {
        d[i] = s[i];
    }
    return dst;
}

size_t_pic strlen( const char* s ) {
    size_t_pic len = 0;
    while ( s[len] ) len++;
    return len;
}

size_t_pic wcslen( const wchar_t* s ) {
    size_t_pic len = 0;
    while ( s[len] ) len++;
    return len;
}

void ___chkstk_ms( void ) {
}

void __chkstk_ms( void ) {
}

#pragma clang diagnostic pop

} // extern "C"
