+++
title = "LLDP"
chapter = false
weight = 30
+++

## Summary

Peer-to-peer (P2P) communication profile using IEEE 802.1AB (LLDP) frames at Layer 2. LLDP agents do not communicate directly with the Mythic server - they relay traffic through an egress agent (HTTP/HTTPX/GitHub) via the `lldp_connect` and `lldp_disconnect` commands.

LLDP operates below IP, so both agents must share an Ethernet broadcast domain (same VLAN/switch segment).

## Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| OUI Profile | ChooseOne | Cisco (00000C) | Vendor OUI to place in Org-Specific TLVs. Spoofs the frame's vendor identity. |
| OUI Custom | String | (empty) | Custom 3-byte OUI as 6 hex characters. Only used when OUI Profile is "Custom". |
| Subtype | String | 01 | 1-byte Org-Specific TLV subtype (2 hex characters). Both ends must match. |
| Kill Date | Date | - | Agent self-termination date |
| AESPSK | Crypto | aes256_hmac | Encryption type for the channel |
| Encrypted Exchange Check | Boolean | true | Perform key exchange during link establishment |
| Peer IP | String | (empty) | Optional peer IP for ARP-based MAC resolution during connect |

## Architecture

```
[Mythic Server] <--HTTP--> [Egress Agent] <--LLDP--> [P2P Agent]
```

The P2P agent opens a raw Ethernet socket filtered to EtherType 0x88CC and waits for an egress agent to initiate the LLDP link. Once linked, the egress agent relays messages between the P2P agent and the Mythic server as delegate messages.

## Wire Format

C2 data is carried inside LLDP Org-Specific TLVs (Type 127). Each TLV contains a chunk header (message ID, sequence number, total chunks) followed by up to 499 bytes of payload. Up to 3 TLVs are packed into a single Ethernet frame for higher throughput.

After reassembly, the message format matches other Starburst transports:

```
[base64(UUID + AES_CBC(TLV) + HMAC-SHA256)]
```

## Platform Support

### Linux

Uses `AF_PACKET` raw sockets with `ETH_P_LLDP` (0x88CC). Requires `CAP_NET_RAW` and `CAP_NET_ADMIN`, or root. The socket is bound to a specific interface via `SO_BINDTODEVICE`. Supports both primary transport (LLDP child) and P2P link commands (egress with `lldp_connect`).

### Windows

Uses Npcap's `wpcap.dll` loaded at runtime. Adapter discovery via `pcap_findalldevs`, MAC resolution via `SendARP` from `iphlpapi.dll`. Supports P2P link commands (`lldp_connect`/`lldp_disconnect`). Primary transport (LLDP as the sole C2 channel) is not supported on Windows.

## Connect/Disconnect Commands

### Connecting

From the egress agent, use `lldp_connect` to establish an LLDP link to a P2P agent:

1. Egress agent resolves the peer IP to a MAC address via ARP
2. Egress opens a raw socket on the specified interface and sends an initial LLDP probe
3. P2P agent responds with its checkin data over LLDP
4. Egress forwards the checkin to Mythic as a delegate message
5. Mythic registers the P2P agent as a new callback with an edge to the egress agent
6. Each beacon cycle, the egress agent polls linked LLDP peers and relays delegate messages

### Disconnecting

Use `lldp_disconnect` to tear down the LLDP link to a P2P agent. The link state is removed and the edge is deleted from the Mythic graph.

## Delegate Message Flow

Each egress agent beacon cycle:

1. **Uplink (P2P -> Mythic)**: Poll all LLDP links for incoming frames. Parse Org-Specific TLVs, reassemble multi-chunk messages, and queue completed messages as `ACTION_LINK_MSG` delegates in the get_tasking request.
2. **Downlink (Mythic -> P2P)**: After receiving tasking, any delegate messages from Mythic are sent to the appropriate LLDP peer by matching agent UUID. Messages are chunked into LLDP frames with multi-TLV packing.

## OUI Vendor Spoofing

The OUI in every Org-Specific TLV is configurable. Setting it to a known network vendor makes C2 frames look like that vendor's LLDP extensions on the wire. Presets include Cisco, Aruba/HPE, Juniper, Arista, Dell, VMware, Ubiquiti, MikroTik, Samsung, and IANA/IETF. Operators can supply a custom OUI instead.

Both ends of the link must use the same OUI and subtype. Frames with a non-matching OUI are ignored.

## OPSEC Notes

- LLDP operates at Layer 2 with no IP headers, TCP sessions, or DNS lookups. It does not appear in firewall logs or standard network flow telemetry.
- On the wire, C2 frames are valid LLDP with a real vendor OUI. Passive inspection tools that do not deeply parse Org-Specific TLV contents will not flag them.
- LLDP from non-network-equipment MACs is anomalous. Workstation or server NICs sending EtherType 0x88CC are detectable via span port or TAP monitoring.
- C2 traffic produces frame bursts that exceed the normal LLDP cadence (one frame per 30 seconds). Sustained bursts of LLDP frames between two endpoints are suspicious.
- Raw socket creation (`AF_PACKET` on Linux, `wpcap.dll` load on Windows) is detectable by host-based security tooling.
- Choose an OUI that matches equipment actually present on the target network segment for best blending.
