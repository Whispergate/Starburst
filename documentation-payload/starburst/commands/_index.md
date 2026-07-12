+++
title = "Commands"
chapter = true
weight = 10
pre = "<b>2. </b>"
+++

## Commands

All Starburst commands are compiled conditionally. Only commands selected during payload creation are included in the final shellcode, reducing binary size and attack surface.

{{% children %}}

## Table of Contents

- Host Enumeration
    * [whoami](/agents/starburst/commands/whoami/)
    * [getuid](/agents/starburst/commands/getuid/)
    * [pwd](/agents/starburst/commands/pwd/)
    * [env](/agents/starburst/commands/env/)
    * [ps](/agents/starburst/commands/ps/)
    * [ifconfig](/agents/starburst/commands/ifconfig/)
    * [netstat](/agents/starburst/commands/netstat/)
    * [arp](/agents/starburst/commands/arp/)
    * [listpipes](/agents/starburst/commands/listpipes/)
    * [getprivs](/agents/starburst/commands/getprivs/)
    * [screenshot](/agents/starburst/commands/screenshot/)
    * [token_list](/agents/starburst/commands/token_list/)
    * [net_localgroup](/agents/starburst/commands/net_localgroup/)
    * [net_localgroup_member](/agents/starburst/commands/net_localgroup_member/)
    * [net_loggedon](/agents/starburst/commands/net_loggedon/)
    * [net_sessions](/agents/starburst/commands/net_sessions/)
    * [net_shares](/agents/starburst/commands/net_shares/)
    * [enumdesktops](/agents/starburst/commands/enumdesktops/)
    * [localtime](/agents/starburst/commands/localtime/)
    * [idletime](/agents/starburst/commands/idletime/)
    * [uptime](/agents/starburst/commands/uptime/)
    * [drives](/agents/starburst/commands/drives/)
    * [clipboard](/agents/starburst/commands/clipboard/)
    * [windows](/agents/starburst/commands/windows/)
- File Operations
    * [ls](/agents/starburst/commands/ls/)
    * [cd](/agents/starburst/commands/cd/)
    * [cat](/agents/starburst/commands/cat/)
    * [mkdir](/agents/starburst/commands/mkdir/)
    * [rm](/agents/starburst/commands/rm/)
    * [cp](/agents/starburst/commands/cp/)
    * [mv](/agents/starburst/commands/mv/)
    * [download](/agents/starburst/commands/download/)
    * [upload](/agents/starburst/commands/upload/)
- Execution
    * [shell](/agents/starburst/commands/shell/)
    * [run](/agents/starburst/commands/run/)
    * [powerpick](/agents/starburst/commands/powerpick/)
    * [execute_assembly](/agents/starburst/commands/execute_assembly/)
    * [execute_coff](/agents/starburst/commands/execute_coff/)
    * [execute_pic](/agents/starburst/commands/execute_pic/)
    * [inline_execute](/agents/starburst/commands/inline_execute/)
    * [shinject](/agents/starburst/commands/shinject/)
    * [spawn](/agents/starburst/commands/spawn/)
    * [runas](/agents/starburst/commands/runas/)
    * [load](/agents/starburst/commands/load/)
- Registry
    * [reg_query](/agents/starburst/commands/reg_query/)
    * [reg_write_value](/agents/starburst/commands/reg_write_value/)
    * [reg_create_key](/agents/starburst/commands/reg_create_key/)
    * [reg_delete](/agents/starburst/commands/reg_delete/)
- Token Manipulation
    * [make_token](/agents/starburst/commands/make_token/)
    * [steal_token](/agents/starburst/commands/steal_token/)
    * [rev2self](/agents/starburst/commands/rev2self/)
    * [token_store](/agents/starburst/commands/token_store/)
- Process Management
    * [kill](/agents/starburst/commands/kill/)
    * [jobkill](/agents/starburst/commands/jobkill/)
    * [ppid_spoof](/agents/starburst/commands/ppid_spoof/)
    * [argue](/agents/starburst/commands/argue/)
- Lateral Movement
    * [jump_psexec](/agents/starburst/commands/jump_psexec/)
    * [jump_scshell](/agents/starburst/commands/jump_scshell/)
    * [jump_wmiexec](/agents/starburst/commands/jump_wmiexec/)
    * [jump_dcomexec](/agents/starburst/commands/jump_dcomexec/)
    * [wmiexec](/agents/starburst/commands/wmiexec/)
    * [dcomexec](/agents/starburst/commands/dcomexec/)
- Peer-to-Peer
    * [link](/agents/starburst/commands/link/)
    * [unlink](/agents/starburst/commands/unlink/)
    * [connect](/agents/starburst/commands/connect/)
    * [disconnect](/agents/starburst/commands/disconnect/)
- Proxying
    * [socks](/agents/starburst/commands/socks/)
    * [rpfwd](/agents/starburst/commands/rpfwd/)
    * [browserpivot](/agents/starburst/commands/browserpivot/)
    * [ssh](/agents/starburst/commands/ssh/)
- Evasion & Defense
    * [migrate](/agents/starburst/commands/migrate/)
    * [blockdlls](/agents/starburst/commands/blockdlls/)
    * [timestomp](/agents/starburst/commands/timestomp/)
- Persistence
    * [persist_run](/agents/starburst/commands/persist_run/)
    * [persist_schtask](/agents/starburst/commands/persist_schtask/)
    * [persist_service](/agents/starburst/commands/persist_service/)
- Credential Access
    * [keylog](/agents/starburst/commands/keylog/)
    * [hashdump](/agents/starburst/commands/hashdump/)
    * [lsass_dump](/agents/starburst/commands/lsass_dump/)
- Network Scanning
    * [portscan](/agents/starburst/commands/portscan/)
- Session Management
    * [sleep](/agents/starburst/commands/sleep/)
    * [config](/agents/starburst/commands/config/)
    * [spawnto_x64](/agents/starburst/commands/spawnto_x64/)
    * [spawnto_x86](/agents/starburst/commands/spawnto_x86/)
    * [exit](/agents/starburst/commands/exit/)
