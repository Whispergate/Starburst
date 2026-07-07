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
    * [pwd](/agents/starburst/commands/pwd/)
    * [env](/agents/starburst/commands/env/)
    * [ps](/agents/starburst/commands/ps/)
    * [ifconfig](/agents/starburst/commands/ifconfig/)
    * [netstat](/agents/starburst/commands/netstat/)
    * [listpipes](/agents/starburst/commands/listpipes/)
    * [getprivs](/agents/starburst/commands/getprivs/)
    * [screenshot](/agents/starburst/commands/screenshot/)
    * [token_list](/agents/starburst/commands/token_list/)
    * [net_localgroup](/agents/starburst/commands/net_localgroup/)
    * [net_localgroup_member](/agents/starburst/commands/net_localgroup_member/)
    * [enumdesktops](/agents/starburst/commands/enumdesktops/)
    * [localtime](/agents/starburst/commands/localtime/)
    * [idletime](/agents/starburst/commands/idletime/)
    * [getuid](/agents/starburst/commands/getuid/)
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
    * [execute_assembly](/agents/starburst/commands/execute_assembly/)
    * [execute_coff](/agents/starburst/commands/execute_coff/)
    * [execute_pic](/agents/starburst/commands/execute_pic/)
    * [shinject](/agents/starburst/commands/shinject/)
- Registry
    * [reg_query](/agents/starburst/commands/reg_query/)
    * [reg_write_value](/agents/starburst/commands/reg_write_value/)
- Token Manipulation
    * [make_token](/agents/starburst/commands/make_token/)
    * [steal_token](/agents/starburst/commands/steal_token/)
    * [rev2self](/agents/starburst/commands/rev2self/)
- Process Management
    * [kill](/agents/starburst/commands/kill/)
    * [jobkill](/agents/starburst/commands/jobkill/)
- Lateral Movement
    * [jump_psexec](/agents/starburst/commands/jump_psexec/)
    * [jump_scshell](/agents/starburst/commands/jump_scshell/)
    * [jump_wmiexec](/agents/starburst/commands/jump_wmiexec/)
    * [jump_dcomexec](/agents/starburst/commands/jump_dcomexec/)
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
- Credential & Input
    * [keylog](/agents/starburst/commands/keylog/)
- Session Management
    * [sleep](/agents/starburst/commands/sleep/)
    * [config](/agents/starburst/commands/config/)
    * [exit](/agents/starburst/commands/exit/)
