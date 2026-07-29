#include "starburst.h"

void pk_init(packer_t *p) {
    p->cap = 1024;
    p->data = (uint8_t *)malloc(p->cap);
    p->len = 0;
}

void pk_ensure(packer_t *p, uint32_t need) {
    while (p->len + need > p->cap) {
        p->cap *= 2;
        p->data = (uint8_t *)realloc(p->data, p->cap);
    }
}

void pk_byte(packer_t *p, uint8_t v) {
    pk_ensure(p, 1);
    p->data[p->len++] = v;
}

void pk_int32(packer_t *p, uint32_t v) {
    pk_ensure(p, 4);
    p->data[p->len++] = (v >> 24) & 0xFF;
    p->data[p->len++] = (v >> 16) & 0xFF;
    p->data[p->len++] = (v >> 8) & 0xFF;
    p->data[p->len++] = v & 0xFF;
}

void pk_bytes(packer_t *p, const uint8_t *d, uint32_t dlen) {
    pk_int32(p, dlen);
    pk_ensure(p, dlen);
    memcpy(p->data + p->len, d, dlen);
    p->len += dlen;
}

void pk_string(packer_t *p, const char *s) {
    uint32_t slen = s ? (uint32_t)strlen(s) : 0;
    pk_bytes(p, (const uint8_t *)s, slen);
}

void pk_free(packer_t *p) {
    free(p->data);
    p->data = NULL;
    p->len = p->cap = 0;
}

void pr_init(parser_t *p, const uint8_t *data, uint32_t len) {
    p->data = data;
    p->len = len;
    p->off = 0;
}

uint8_t pr_byte(parser_t *p) {
    if (p->off >= p->len) return 0;
    return p->data[p->off++];
}

uint32_t pr_int32(parser_t *p) {
    if (p->off + 4 > p->len) return 0;
    uint32_t v = ((uint32_t)p->data[p->off] << 24) |
                 ((uint32_t)p->data[p->off+1] << 16) |
                 ((uint32_t)p->data[p->off+2] << 8) |
                 (uint32_t)p->data[p->off+3];
    p->off += 4;
    return v;
}

const uint8_t *pr_bytes(parser_t *p, uint32_t *out_len) {
    uint32_t blen = pr_int32(p);
    if (p->off + blen > p->len) { *out_len = 0; return NULL; }
    const uint8_t *ptr = p->data + p->off;
    p->off += blen;
    *out_len = blen;
    return ptr;
}

char *pr_string(parser_t *p) {
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

void pr_raw(parser_t *p, uint8_t *out, uint32_t count) {
    if (p->off + count > p->len) return;
    memcpy(out, p->data + p->off, count);
    p->off += count;
}

uint32_t pr_remaining(parser_t *p) {
    return p->len > p->off ? p->len - p->off : 0;
}
