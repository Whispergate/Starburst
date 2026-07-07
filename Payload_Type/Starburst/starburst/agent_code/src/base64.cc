#include <common.h>
#include <base64.h>

using namespace stardust;

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64url_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static auto declfn b64_decode_char( char c ) -> uint8_t {
    if ( c >= 'A' && c <= 'Z' ) return c - 'A';
    if ( c >= 'a' && c <= 'z' ) return c - 'a' + 26;
    if ( c >= '0' && c <= '9' ) return c - '0' + 52;
    if ( c == '+' || c == '-' ) return 62;
    if ( c == '/' || c == '_' ) return 63;
    return 0xFF;
}

static auto declfn do_b64_encode(
    _Inout_ instance&   inst,
    _In_    uint8_t*    data,
    _In_    uint32_t    len,
    _Out_   uint32_t*   out_len,
    _In_    const char* table
) -> uint8_t* {
    auto tbl = symbol<const char*>( table );

    uint32_t enc_len = 4 * ((len + 2) / 3);
    auto output = static_cast<uint8_t*>( inst.heap_alloc( enc_len + 1 ) );
    if ( !output ) { *out_len = 0; return nullptr; }

    uint32_t j = 0;
    for ( uint32_t i = 0; i < len; ) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;

        uint32_t triple = (a << 16) | (b << 8) | c;

        output[j++] = tbl[(triple >> 18) & 0x3F];
        output[j++] = tbl[(triple >> 12) & 0x3F];
        output[j++] = tbl[(triple >> 6)  & 0x3F];
        output[j++] = tbl[ triple        & 0x3F];
    }

    uint32_t mod = len % 3;
    if ( mod == 1 ) {
        output[j - 1] = '=';
        output[j - 2] = '=';
    } else if ( mod == 2 ) {
        output[j - 1] = '=';
    }

    output[j] = '\0';
    *out_len = j;

    return output;
}

static auto declfn do_b64_decode(
    _Inout_ instance& inst,
    _In_    uint8_t*  data,
    _In_    uint32_t  len,
    _Out_   uint32_t* out_len
) -> uint8_t* {
    uint32_t pad = 0;
    if ( len > 0 && data[len - 1] == '=' ) pad++;
    if ( len > 1 && data[len - 2] == '=' ) pad++;

    uint32_t dec_len = (len / 4) * 3 - pad;
    auto output = static_cast<uint8_t*>( inst.heap_alloc( dec_len + 1 ) );
    if ( !output ) { *out_len = 0; return nullptr; }

    uint32_t j = 0;
    for ( uint32_t i = 0; i < len; ) {
        uint8_t a = (i < len && data[i] != '=') ? b64_decode_char( data[i] ) : 0; i++;
        uint8_t b = (i < len && data[i] != '=') ? b64_decode_char( data[i] ) : 0; i++;
        uint8_t c = (i < len && data[i] != '=') ? b64_decode_char( data[i] ) : 0; i++;
        uint8_t d = (i < len && data[i] != '=') ? b64_decode_char( data[i] ) : 0; i++;

        uint32_t triple = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | d;

        if ( j < dec_len ) output[j++] = (triple >> 16) & 0xFF;
        if ( j < dec_len ) output[j++] = (triple >> 8)  & 0xFF;
        if ( j < dec_len ) output[j++] =  triple        & 0xFF;
    }

    *out_len = j;
    return output;
}

auto declfn starburst::base64_encode(
    _Inout_ instance& inst,
    _In_    uint8_t*  data,
    _In_    uint32_t  len,
    _Out_   uint32_t* out_len
) -> uint8_t* {
    return do_b64_encode( inst, data, len, out_len, b64_table );
}

auto declfn starburst::base64_decode(
    _Inout_ instance& inst,
    _In_    uint8_t*  data,
    _In_    uint32_t  len,
    _Out_   uint32_t* out_len
) -> uint8_t* {
    return do_b64_decode( inst, data, len, out_len );
}

auto declfn starburst::base64url_encode(
    _Inout_ instance& inst,
    _In_    uint8_t*  data,
    _In_    uint32_t  len,
    _Out_   uint32_t* out_len
) -> uint8_t* {
    return do_b64_encode( inst, data, len, out_len, b64url_table );
}

auto declfn starburst::base64url_decode(
    _Inout_ instance& inst,
    _In_    uint8_t*  data,
    _In_    uint32_t  len,
    _Out_   uint32_t* out_len
) -> uint8_t* {
    return do_b64_decode( inst, data, len, out_len );
}
