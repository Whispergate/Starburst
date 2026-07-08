from translator.utils import *


def parse_checkin(data):
    p = Parser(data)
    action = p.byte()

    msg = {"action": "checkin"}
    msg["uuid"] = p.string()

    ip_count = p.int32()
    ips = []
    for _ in range(ip_count):
        ips.append(p.string())
    msg["ips"] = ips

    msg["os"] = p.string()
    msg["user"] = p.string()
    msg["host"] = p.string()
    msg["pid"] = p.int32()
    msg["architecture"] = p.string()
    msg["domain"] = p.string()
    msg["integrity_level"] = p.int32()
    msg["external_ip"] = p.string()
    msg["process_name"] = p.string()

    return msg


def parse_get_tasking(data):
    p = Parser(data)
    action = p.byte()

    msg = {"action": "get_tasking", "tasking_size": -1}

    responses_len = p.int32()
    if responses_len > 0 and p.remaining() >= responses_len:
        responses_data = p.raw(responses_len)
        responses, delegates, socks = parse_responses_blob(responses_data)
        if responses:
            msg["responses"] = responses
        if delegates:
            msg["delegates"] = delegates
        if socks:
            msg["proxies"] = socks

    return msg


def parse_responses_blob(data):
    import base64
    responses = []
    delegates = []
    socks = []
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            break
        rsp_size = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4
        if offset + rsp_size > len(data):
            break
        rsp_data = data[offset:offset + rsp_size]
        offset += rsp_size

        if len(rsp_data) > 0 and rsp_data[0] in (ACTION_LINK_ADD, ACTION_LINK_MSG, ACTION_LINK_REMOVE):
            delegate_msgs = parse_delegate_messages(rsp_data)
            delegates.extend(delegate_msgs)
        elif len(rsp_data) > 0 and rsp_data[0] == ACTION_SOCKS_MSG:
            p = Parser(rsp_data)
            p.byte()  # consume action
            server_id = p.int32()
            do_exit = p.byte() != 0
            data_bytes = p.bytes()
            socks.append({
                "server_id": server_id,
                "data": base64.b64encode(data_bytes).decode() if data_bytes else "",
                "exit": do_exit,
            })
        elif len(rsp_data) > 0 and rsp_data[0] == ACTION_RPFWD_MSG:
            p = Parser(rsp_data)
            p.byte()  # consume action
            server_id = p.int32()
            do_exit = p.byte() != 0
            data_bytes = p.bytes()
            socks.append({
                "server_id": server_id,
                "data": base64.b64encode(data_bytes).decode() if data_bytes else "",
                "exit": do_exit,
            })
        else:
            responses.append(parse_single_response(rsp_data))
    return responses, delegates, socks


def parse_single_response(data):
    p = Parser(data)
    action = p.byte()
    task_id = p.string()
    status_byte = p.byte()

    if status_byte == RESPONSE_ERROR:
        output = p.string()
        return {
            "task_id": task_id,
            "user_output": output,
            "completed": True,
            "status": "error",
        }

    remaining = p.remaining()

    # check for sub-protocol byte (download/upload file transfer)
    if remaining >= 1:
        peek_byte = p.data[p.offset]

        if peek_byte == DOWNLOAD_INIT:
            return parse_download_init(p, task_id)

        if peek_byte == DOWNLOAD_CHUNK:
            return parse_download_chunk(p, task_id, status_byte)

        if peek_byte == UPLOAD_REQUEST:
            return parse_upload_request(p, task_id)

    # try structured responses (ls/ps) via heuristic
    if remaining >= 4:
        peek_count = struct.unpack(">I", p.data[p.offset:p.offset + 4])[0]

        if peek_count > 0 and remaining > 8:
            result = try_parse_ls(p, task_id, peek_count)
            if result:
                return result

            result = try_parse_ps(p, task_id, peek_count)
            if result:
                return result

    # fallback: plain text response
    p_reset = Parser(data)
    p_reset.byte()   # action
    p_reset.string()  # task_id
    p_reset.byte()   # status
    output = p_reset.string()

    return {
        "task_id": task_id,
        "user_output": output,
        "completed": True,
    }


def parse_download_init(p, task_id):
    import base64
    p.byte()  # consume DOWNLOAD_INIT marker
    total_chunks = p.int32()
    total_size = p.int32()
    full_path = p.string()

    is_screenshot = full_path.lower().endswith((".bmp", ".png", ".jpg", ".jpeg")) and "screenshot" in full_path.lower()

    result = {
        "task_id": task_id,
        "completed": False,
        "download": {
            "total_chunks": total_chunks,
            "full_path": full_path,
        },
        "user_output": f"Downloading {full_path} ({total_size} bytes, {total_chunks} chunks)",
    }
    if is_screenshot:
        result["is_screenshot"] = True
    return result


def parse_download_chunk(p, task_id, status_byte):
    import base64
    p.byte()  # consume DOWNLOAD_CHUNK marker
    chunk_num = p.int32()
    file_id = p.string()
    chunk_data = p.bytes()

    is_last = (status_byte == RESPONSE_SUCCESS)

    return {
        "task_id": task_id,
        "completed": is_last,
        "download": {
            "chunk_num": chunk_num,
            "file_id": file_id,
            "chunk_data": base64.b64encode(chunk_data).decode(),
        },
    }


def parse_upload_request(p, task_id):
    p.byte()  # consume UPLOAD_REQUEST marker
    file_id = p.string()
    chunk_num = p.int32()
    remote_path = p.string()
    total_chunks = p.int32()

    return {
        "task_id": task_id,
        "completed": False,
        "upload": {
            "file_id": file_id,
            "chunk_num": chunk_num,
            "remote_path": remote_path,
            "total_chunks": total_chunks,
        },
    }


def try_parse_ls(p, task_id, count):
    import json
    saved_offset = p.offset

    # new format: path(string) + count(int32) + entries
    # old format: count(int32) + entries
    # detect by checking if count looks like a string length with valid path chars after
    try:
        # try new format: path string first, then count + entries
        path_offset = p.offset
        p.offset = saved_offset
        full_path = p.string()
        entry_count = p.int32()

        files = []
        for _ in range(entry_count):
            name = p.string()
            size = p.int32()
            is_dir = p.byte()
            files.append({
                "name": name,
                "size": size,
                "is_file": is_dir == 0,
            })

        # split full_path into parent_path and dir name
        full_path = full_path.replace("/", "\\")
        if "\\" in full_path:
            idx = full_path.rstrip("\\").rfind("\\")
            parent_path = full_path[:idx] if idx > 0 else full_path[:idx + 1]
            dir_name = full_path[idx + 1:].rstrip("\\")
        else:
            parent_path = ""
            dir_name = full_path

        file_browser = {
            "host": "",
            "is_file": False,
            "name": dir_name or ".",
            "parent_path": parent_path,
            "full_path": full_path,
            "success": True,
            "files": files,
        }
        return {
            "task_id": task_id,
            "completed": True,
            "file_browser": file_browser,
            "user_output": json.dumps(files, indent=2),
        }
    except Exception:
        pass

    # fallback: old format (count + entries, no path)
    p.offset = saved_offset
    try:
        p.int32()  # consume count
        files = []
        for _ in range(count):
            name = p.string()
            size = p.int32()
            is_dir = p.byte()
            files.append({
                "name": name,
                "size": size,
                "is_file": is_dir == 0,
            })
        file_browser = {
            "host": "",
            "is_file": False,
            "name": ".",
            "success": True,
            "files": files,
        }
        return {
            "task_id": task_id,
            "completed": True,
            "file_browser": file_browser,
            "user_output": json.dumps(files, indent=2),
        }
    except Exception:
        p.offset = saved_offset
        return None


def try_parse_ps(p, task_id, count):
    import json
    saved_offset = p.offset
    try:
        p.int32()  # consume count
        processes = []
        for _ in range(count):
            name = p.string()
            pid = p.int32()
            ppid = p.int32()
            processes.append({
                "process_id": pid,
                "parent_process_id": ppid,
                "name": name,
            })
        return {
            "task_id": task_id,
            "completed": True,
            "processes": processes,
            "user_output": json.dumps(processes, indent=2),
        }
    except Exception:
        p.offset = saved_offset
        return None


_link_profiles = {}

C2_PROFILE_NAMES = {
    C2_PROFILE_SMB: "smb",
    C2_PROFILE_TCP: "tcp",
}


def parse_delegate_messages(data):
    p = Parser(data)
    action = p.byte()
    messages = []

    if action == ACTION_LINK_ADD:
        c2_type = p.byte()
        c2_profile = C2_PROFILE_NAMES.get(c2_type, "smb")
        link_id = p.int32()
        agent_uuid = p.string()
        msg_data = p.bytes()
        _link_profiles[agent_uuid] = c2_profile
        messages.append({
            "c2_profile": c2_profile,
            "message": msg_data.decode("utf-8", errors="replace"),
            "uuid": agent_uuid,
        })
    elif action == ACTION_LINK_MSG:
        while p.remaining() > 0:
            agent_uuid = p.string()
            msg_data = p.bytes()
            c2_profile = _link_profiles.get(agent_uuid, "smb")
            if agent_uuid not in _link_profiles:
                for old_uuid, prof in _link_profiles.items():
                    _link_profiles[agent_uuid] = prof
                    break
            messages.append({
                "c2_profile": c2_profile,
                "message": msg_data.decode("utf-8", errors="replace"),
                "uuid": agent_uuid,
            })
    elif action == ACTION_LINK_REMOVE:
        link_id = p.int32()
        agent_uuid = p.string()
        c2_profile = _link_profiles.pop(agent_uuid, "smb")
        messages.append({
            "c2_profile": c2_profile,
            "message": "",
            "uuid": agent_uuid,
            "mythic_uuid": agent_uuid,
        })

    return messages


def parse_delegate_remove(data):
    return parse_delegate_messages(data)


import struct
