#include "starburst.h"

void hex_to_bytes(const char *hex, uint8_t *out, int len) {
    for (int i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + i * 2, "%02x", &b);
        out[i] = (uint8_t)b;
    }
}

char *b64_encode(const uint8_t *data, size_t len, size_t *out_len) {
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

uint8_t *b64_decode(const char *input, size_t in_len, size_t *out_len) {
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

uint8_t *aes_encrypt(const uint8_t *plaintext, uint32_t pt_len, uint32_t *out_len) {
    uint32_t pad = 16 - (pt_len % 16);
    uint32_t padded_len = pt_len + pad;
    uint8_t *padded = (uint8_t *)malloc(padded_len);
    memcpy(padded, plaintext, pt_len);
    memset(padded + pt_len, (uint8_t)pad, pad);

    uint8_t iv[16];
    RAND_bytes(iv, 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_state.aes_key, iv);

    uint8_t *ct = (uint8_t *)malloc(padded_len + 16);
    int ct_len = 0, final_len = 0;
    EVP_EncryptUpdate(ctx, ct, &ct_len, padded, (int)padded_len);
    EVP_EncryptFinal_ex(ctx, ct + ct_len, &final_len);
    ct_len += final_len;
    EVP_CIPHER_CTX_free(ctx);
    free(padded);

    uint32_t hmac_input_len = 16 + (uint32_t)ct_len;
    uint8_t *hmac_input = (uint8_t *)malloc(hmac_input_len);
    memcpy(hmac_input, iv, 16);
    memcpy(hmac_input + 16, ct, ct_len);

    uint8_t hmac[32];
    unsigned int hmac_len = 32;
    HMAC(EVP_sha256(), g_state.aes_key, 32, hmac_input, hmac_input_len, hmac, &hmac_len);
    free(hmac_input);

    uint32_t total = 16 + (uint32_t)ct_len + 32;
    uint8_t *result = (uint8_t *)malloc(total);
    memcpy(result, iv, 16);
    memcpy(result + 16, ct, ct_len);
    memcpy(result + 16 + ct_len, hmac, 32);
    free(ct);

    *out_len = total;
    return result;
}

uint8_t *aes_decrypt(const uint8_t *blob, uint32_t blob_len, uint32_t *out_len) {
    if (blob_len < 48) return NULL;

    const uint8_t *iv = blob;
    uint32_t ct_len = blob_len - 16 - 32;
    const uint8_t *ct = blob + 16;
    const uint8_t *recv_hmac = blob + blob_len - 32;

    uint8_t calc_hmac[32];
    unsigned int hmac_len = 32;
    HMAC(EVP_sha256(), g_state.aes_key, 32, blob, 16 + ct_len, calc_hmac, &hmac_len);
    if (CRYPTO_memcmp(calc_hmac, recv_hmac, 32) != 0) {
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_state.aes_key, iv);

    uint8_t *pt = (uint8_t *)malloc(ct_len + 16);
    int pt_len = 0, final_len = 0;
    EVP_DecryptUpdate(ctx, pt, &pt_len, ct, (int)ct_len);
    EVP_DecryptFinal_ex(ctx, pt + pt_len, &final_len);
    pt_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    if (pt_len > 0) {
        uint8_t pad_val = pt[pt_len - 1];
        if (pad_val > 0 && pad_val <= 16) {
            pt_len -= pad_val;
        }
    }

    *out_len = (uint32_t)pt_len;
    return pt;
}
