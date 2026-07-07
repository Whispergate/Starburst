#include <common.h>
#include <parser.h>

using namespace stardust;

auto declfn starburst::parser_init(
    _Inout_ Parser*  p,
    _In_    uint8_t* data,
    _In_    uint32_t size
) -> void {
    p->original      = data;
    p->buffer        = data;
    p->original_size = size;
    p->length        = size;
}

auto declfn starburst::parser_byte(
    _Inout_ Parser* p
) -> uint8_t {
    if ( p->length < 1 ) return 0;

    uint8_t val = p->buffer[0];
    p->buffer++;
    p->length--;

    return val;
}

auto declfn starburst::parser_int32(
    _Inout_ Parser* p
) -> uint32_t {
    if ( p->length < 4 ) return 0;

    uint32_t val = ( (uint32_t)p->buffer[0] << 24 ) |
                   ( (uint32_t)p->buffer[1] << 16 ) |
                   ( (uint32_t)p->buffer[2] << 8  ) |
                   ( (uint32_t)p->buffer[3]       );

    p->buffer += 4;
    p->length -= 4;

    return val;
}

auto declfn starburst::parser_bytes(
    _Inout_ Parser*   p,
    _Out_   uint32_t* out_len
) -> uint8_t* {
    uint32_t len = parser_int32( p );

    if ( len > p->length ) {
        *out_len = 0;
        return nullptr;
    }

    uint8_t* ptr = p->buffer;
    p->buffer += len;
    p->length -= len;
    *out_len = len;

    return ptr;
}

auto declfn starburst::parser_string(
    _Inout_ Parser*   p,
    _Out_   uint32_t* out_len
) -> char* {
    return reinterpret_cast<char*>( parser_bytes( p, out_len ) );
}

auto declfn starburst::parser_raw(
    _Inout_ Parser*  p,
    _In_    uint32_t len
) -> uint8_t* {
    if ( len > p->length ) return nullptr;

    uint8_t* ptr = p->buffer;
    p->buffer += len;
    p->length -= len;

    return ptr;
}

auto declfn starburst::parser_remaining(
    _In_ Parser* p
) -> uint32_t {
    return p->length;
}
