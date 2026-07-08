from translator.utils import *


def pack_checkin_response(mythic_msg):
    p = Packer()
    p.add_byte(ACTION_CHECKIN_RSP)
    p.add_string(mythic_msg.get("id", ""))
    return p.build()


def pack_tasking(mythic_msg):
    p = Packer()
    p.add_byte(ACTION_GET_TASKING)

    tasks = mythic_msg.get("tasks", [])
    p.add_int32(len(tasks))

    for task in tasks:
        cmd_name = task.get("command", "")
        cmd_id = CMD_MAP.get(cmd_name, 0x00)
        p.add_byte(cmd_id)

        task_id = task.get("id", "")
        if isinstance(task_id, str):
            uuid_bytes = task_id.encode("utf-8")
        else:
            uuid_bytes = str(task_id).encode("utf-8")
        uuid_bytes = uuid_bytes.ljust(36, b"\x00")[:36]
        p.data += uuid_bytes

        params = task.get("parameters", "")
        if isinstance(params, str):
            params_packed = pack_command_params(cmd_name, params)
        elif isinstance(params, dict):
            params_packed = pack_command_params(cmd_name, params)
        else:
            params_packed = b""

        p.add_int32(len(params_packed))
        p.data += params_packed

    return p.build()


def pack_command_params(cmd_name, params):
    import json
    pk = Packer()

    if isinstance(params, str):
        try:
            params = json.loads(params) if params else {}
        except json.JSONDecodeError:
            params = {"raw": params}

    if cmd_name == "exit":
        pass
    elif cmd_name == "sleep":
        pk.add_int32(int(params.get("interval", 5000)))
        pk.add_int32(int(params.get("jitter", 0)))
    elif cmd_name == "shell":
        pk.add_string(params.get("command", ""))
    elif cmd_name == "whoami":
        pass
    elif cmd_name == "pwd":
        pass
    elif cmd_name == "cd":
        pk.add_string(params.get("path", "."))
    elif cmd_name == "ls":
        pk.add_string(params.get("path", "."))
    elif cmd_name == "ps":
        pass
    elif cmd_name == "config":
        pk.add_int32(int(params.get("sleep", 0xFFFFFFFF)))
        pk.add_int32(int(params.get("jitter", 0xFFFFFFFF)))
        pk.add_int32(int(params.get("killdate", 0xFFFFFFFF)))
    elif cmd_name == "upload":
        import base64
        pk.add_string(params.get("file_id", ""))
        pk.add_string(params.get("remote_path", ""))
        pk.add_int32(int(params.get("total_chunks", 1)))
        pk.add_int32(int(params.get("chunk_num", 1)))
        chunk_b64 = params.get("chunk_data", "")
        if chunk_b64:
            chunk_raw = base64.b64decode(chunk_b64)
            pk.add_bytes(chunk_raw)
        else:
            pk.add_bytes(b"")
    elif cmd_name == "download":
        pk.add_string(params.get("file", ""))
    elif cmd_name == "shinject":
        import base64
        pk.add_int32(int(params.get("pid", 0)))
        sc_b64 = params.get("shellcode_data", "")
        if sc_b64:
            sc_raw = base64.b64decode(sc_b64)
            pk.add_bytes(sc_raw)
        else:
            pk.add_bytes(b"")
    elif cmd_name == "execute_pic":
        import base64
        pic_b64 = params.get("pic_data", "")
        if pic_b64:
            pic_raw = base64.b64decode(pic_b64)
            pk.add_bytes(pic_raw)
        else:
            pk.add_bytes(b"")
    elif cmd_name == "cat":
        pk.add_string(params.get("path", ""))
    elif cmd_name == "mkdir":
        pk.add_string(params.get("path", ""))
    elif cmd_name == "rm":
        pk.add_string(params.get("path", ""))
    elif cmd_name == "cp":
        pk.add_string(params.get("source", ""))
        pk.add_string(params.get("destination", ""))
    elif cmd_name == "mv":
        pk.add_string(params.get("source", ""))
        pk.add_string(params.get("destination", ""))
    elif cmd_name == "env":
        pass
    elif cmd_name == "reg_query":
        pk.add_string(params.get("hive", "HKLM"))
        pk.add_string(params.get("key", ""))
    elif cmd_name == "screenshot":
        pass
    elif cmd_name == "token_list":
        pass
    elif cmd_name == "execute_assembly":
        import base64
        asm_b64 = params.get("assembly_data", "")
        if asm_b64:
            asm_raw = base64.b64decode(asm_b64)
            pk.add_bytes(asm_raw)
        else:
            pk.add_bytes(b"")
        pk.add_string(params.get("arguments", ""))
    elif cmd_name == "execute_coff":
        import base64
        coff_b64 = params.get("coff_data", "")
        if coff_b64:
            coff_raw = base64.b64decode(coff_b64)
            pk.add_bytes(coff_raw)
        else:
            pk.add_bytes(b"")
        args_str = params.get("arguments", "")
        if args_str:
            pk.add_bytes(bytes.fromhex(args_str) if all(c in "0123456789abcdefABCDEF" for c in args_str) and len(args_str) % 2 == 0 else args_str.encode())
        else:
            pk.add_bytes(b"")
        pk.add_string(params.get("entrypoint", "go"))

    elif cmd_name == "jump_psexec":
        pk.add_string(params.get("hostname", ""))
        pk.add_string(params.get("service_name", "StarSvc"))
        pk.add_string(params.get("binary_path", ""))
    elif cmd_name == "jump_scshell":
        pk.add_string(params.get("hostname", ""))
        pk.add_string(params.get("service_name", "SensSvc"))
        pk.add_string(params.get("command", ""))
    elif cmd_name == "jump_wmiexec":
        pk.add_string(params.get("hostname", ""))
        pk.add_string(params.get("command", ""))
    elif cmd_name == "jump_dcomexec":
        pk.add_string(params.get("hostname", ""))
        pk.add_string(params.get("command", ""))

    elif cmd_name == "ifconfig":
        pass
    elif cmd_name == "netstat":
        pass
    elif cmd_name == "kill":
        pk.add_int32(int(params.get("pid", 0)))
    elif cmd_name == "run":
        pk.add_string(params.get("command", ""))
    elif cmd_name == "getprivs":
        pass
    elif cmd_name == "listpipes":
        pass
    elif cmd_name == "reg_write_value":
        pk.add_string(params.get("hive", "HKLM"))
        pk.add_string(params.get("key", ""))
        pk.add_string(params.get("name", ""))
        pk.add_string(params.get("value", ""))
        pk.add_int32(int(params.get("type", 1)))
    elif cmd_name == "make_token":
        pk.add_string(params.get("domain", "."))
        pk.add_string(params.get("username", ""))
        pk.add_string(params.get("password", ""))
    elif cmd_name == "steal_token":
        pk.add_int32(int(params.get("pid", 0)))
    elif cmd_name == "rev2self":
        pass
    elif cmd_name == "net_localgroup":
        pk.add_string(params.get("hostname", ""))
    elif cmd_name == "net_localgroup_member":
        pk.add_string(params.get("hostname", ""))
        pk.add_string(params.get("group", ""))
    elif cmd_name == "jobkill":
        pk.add_string(params.get("task_id", ""))
    elif cmd_name == "link":
        connection_info = params.get("connection_info", {})
        pk.add_string(connection_info.get("host", ""))
        c2_profile = connection_info.get("c2_profile", {})
        c2_params = c2_profile.get("parameters", {})
        pk.add_string(c2_params.get("pipename", ""))
    elif cmd_name == "unlink":
        link_info = params.get("link_info", {})
        pk.add_string(link_info.get("callback_uuid", ""))

    elif cmd_name == "download_resp":
        pk.add_string(params.get("file_id", ""))

    elif cmd_name == "socks":
        pk.add_string(params.get("action", "start"))

    elif cmd_name == "ssh":
        pk.add_string(params.get("hostname", ""))
        pk.add_int32(int(params.get("port", 22)))
        pk.add_string(params.get("username", ""))
        pk.add_string(params.get("credential", ""))
        pk.add_byte(1 if params.get("use_key", False) else 0)
        pk.add_byte(0 if params.get("target_os", "linux") == "linux" else 1)
        pk.add_string(params.get("linux_binary_b64", ""))

    elif cmd_name == "rpfwd":
        pk.add_string(params.get("action", "start"))
        pk.add_string(params.get("remote_ip", "127.0.0.1"))
        pk.add_int32(int(params.get("remote_port", 80)))

    elif cmd_name == "migrate":
        pk.add_int32(int(params.get("pid", 0)))
    elif cmd_name == "blockdlls":
        pk.add_int32(1 if params.get("enable", True) else 0)
    elif cmd_name == "keylog":
        pk.add_int32(int(params.get("duration", 10)))
    elif cmd_name == "enumdesktops":
        pass
    elif cmd_name == "timestomp":
        pk.add_string(params.get("path", ""))
        pk.add_string(params.get("source", ""))
    elif cmd_name == "localtime":
        pass
    elif cmd_name == "idletime":
        pass
    elif cmd_name == "getuid":
        pass

    elif cmd_name == "browserpivot":
        pk.add_string(params.get("action", "start"))
        pk.add_int32(int(params.get("pid", 0)))
        pk.add_int32(int(params.get("port", 8080)))

    elif cmd_name == "connect":
        connection_info = params.get("connection_info", {})
        pk.add_string(connection_info.get("host", ""))
        c2_profile = connection_info.get("c2_profile", {})
        c2_params = c2_profile.get("parameters", {})
        pk.add_int32(int(c2_params.get("port", 7000)))
    elif cmd_name == "disconnect":
        link_info = params.get("link_info", {})
        pk.add_string(link_info.get("callback_uuid", ""))

    elif cmd_name == "powerpick":
        import base64
        runner_b64 = params.get("runner_data", "")
        if runner_b64:
            runner_raw = base64.b64decode(runner_b64)
            pk.add_bytes(runner_raw)
        else:
            pk.add_bytes(b"")
        pk.add_string(params.get("script", ""))

    elif cmd_name in ("spawnto_x64", "spawnto_x86"):
        pk.add_string(params.get("application", ""))
        pk.add_string(params.get("arguments", ""))

    elif cmd_name == "spawn":
        import base64
        pid_val = int(params.get("pid", 0))
        pk.add_int32(pid_val)
        sc_b64 = params.get("shellcode_data", "")
        if sc_b64:
            sc_raw = base64.b64decode(sc_b64)
            pk.add_bytes(sc_raw)
        else:
            pk.add_bytes(b"")

    return pk.build()


def pack_socks_datagrams(datagrams):
    import base64
    p = Packer()
    p.add_byte(ACTION_SOCKS_MSG)
    p.add_int32(len(datagrams))
    for d in datagrams:
        p.add_int32(int(d.get("server_id", 0)))
        p.add_byte(1 if d.get("exit", False) else 0)
        data = d.get("data", "")
        if isinstance(data, str) and data:
            raw = base64.b64decode(data)
        elif isinstance(data, bytes):
            raw = data
        else:
            raw = b""
        p.add_bytes(raw)
    return p.build()


def pack_rpfwd_datagrams(datagrams):
    import base64
    p = Packer()
    p.add_byte(ACTION_RPFWD_MSG)
    p.add_int32(len(datagrams))
    for d in datagrams:
        p.add_int32(int(d.get("server_id", 0)))
        p.add_byte(1 if d.get("exit", False) else 0)
        data = d.get("data", "")
        if isinstance(data, str) and data:
            raw = base64.b64decode(data)
        elif isinstance(data, bytes):
            raw = data
        else:
            raw = b""
        p.add_bytes(raw)
    return p.build()


def pack_delegate_messages(delegates):
    p = Packer()
    p.add_byte(ACTION_LINK_MSG)
    for d in delegates:
        p.add_string(d.get("uuid", ""))
        msg = d.get("message", "")
        if isinstance(msg, str):
            msg = msg.encode("utf-8")
        p.add_bytes(msg)
    return p.build()
