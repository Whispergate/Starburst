#ifndef STARBURST_BASE64_H
#define STARBURST_BASE64_H

#include <common.h>

namespace starburst {

    auto declfn base64_encode( instance& inst, uint8_t* data, uint32_t len, uint32_t* out_len ) -> uint8_t*;
    auto declfn base64_decode( instance& inst, uint8_t* data, uint32_t len, uint32_t* out_len ) -> uint8_t*;
    auto declfn base64url_encode( instance& inst, uint8_t* data, uint32_t len, uint32_t* out_len ) -> uint8_t*;
    auto declfn base64url_decode( instance& inst, uint8_t* data, uint32_t len, uint32_t* out_len ) -> uint8_t*;

}

#endif
