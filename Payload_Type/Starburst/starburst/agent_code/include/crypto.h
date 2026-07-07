#ifndef STARBURST_CRYPTO_H
#define STARBURST_CRYPTO_H

#include <common.h>

namespace starburst {

    auto declfn crypto_init( instance& inst ) -> bool;
    auto declfn crypto_encrypt( instance& inst, uint8_t* key, uint8_t* plaintext, uint32_t plain_len, uint8_t** out, uint32_t* out_len ) -> bool;
    auto declfn crypto_decrypt( instance& inst, uint8_t* key, uint8_t* cipherblob, uint32_t blob_len, uint8_t** out, uint32_t* out_len ) -> bool;
    auto declfn crypto_destroy( instance& inst ) -> void;

}

#endif
