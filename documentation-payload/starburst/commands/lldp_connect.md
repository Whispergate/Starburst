+++
title = "lldp_connect"
chapter = false
weight = 310
+++

## Summary

Connect to a peer-to-peer (P2P) agent over LLDP (IEEE 802.1AB). Establishes a Layer 2 link using raw Ethernet frames with Org-Specific TLVs.

- **Needs Admin:** False (but requires `CAP_NET_RAW`/`CAP_NET_ADMIN` on Linux, or Npcap on Windows)
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `connection_info` | ConnectionInfo | Yes | N/A | Host, peer IP, interface, and C2 profile parameters. Uses the `callback_table:connect` UI feature. |

### Usage

Use the Mythic UI `callback_table:connect` button to initiate an LLDP connection to a P2P agent. Select the LLDP profile and provide the peer's IP address and interface name.

```
lldp_connect -connection_info {"host": "172.18.0.3", "interface": "eth0", "peer_ip": "172.18.0.3", "c2_profile": {"name": "lldp", "parameters": {...}}}
```

**Example Output:**

```
LLDP link established via eth0
Peer MAC: 3a:be:f1:98:81:cb
Agent: 706f2005-ce4a-411c-904b-959453e6dd6a
```

## Detailed Summary

The command resolves the peer IP to a MAC address using ARP, opens a raw Ethernet socket on the specified interface filtered to EtherType 0x88CC, and begins listening for LLDP frames with the matching OUI and subtype. When the child agent's frames arrive, the egress agent reads the initial checkin data, establishes the delegate relay, and reports the link to Mythic.

On Linux, the raw socket uses `AF_PACKET` with `SO_BINDTODEVICE` to bind to the specific interface. On Windows, the socket uses Npcap's `pcap_open_live` with `pcap_sendpacket`/`pcap_next_ex` for frame I/O.

Once linked, the child agent's traffic is relayed through the egress agent's C2 channel to the Mythic server. The egress agent polls all LLDP links each beacon cycle, reassembling multi-chunk messages from incoming frames.

### APIs Used

#### Linux

| API | Purpose |
|-----|---------|
| `socket(AF_PACKET, SOCK_RAW, ...)` | Create raw Ethernet socket |
| `setsockopt(SO_BINDTODEVICE)` | Bind socket to interface |
| `ioctl(SIOCGIFHWADDR)` | Get interface MAC address |
| `ioctl(SIOCGIFINDEX)` | Get interface index |
| `sendto` | Send LLDP frames |
| `recv` | Receive LLDP frames |

#### Windows

| API | Purpose |
|-----|---------|
| `pcap_open_live` (wpcap.dll) | Open adapter for capture and injection |
| `pcap_sendpacket` (wpcap.dll) | Send LLDP frames |
| `pcap_next_ex` (wpcap.dll) | Receive LLDP frames |
| `SendARP` (iphlpapi.dll) | Resolve peer IP to MAC address |
| `GetAdaptersInfo` (iphlpapi.dll) | Enumerate network adapters |

## MITRE ATT&CK Mapping

- **T1095** - Non-Application Layer Protocol
- **T1572** - Protocol Tunneling
- **T1205** - Traffic Signaling
