#ifndef STARBURST_PARSER_H
#define STARBURST_PARSER_H

#include <common.h>

namespace starburst {

    struct Parser {
        uint8_t* original;
        uint8_t* buffer;
        uint32_t original_size;
        uint32_t length;
    };

    auto declfn parser_init( Parser* p, uint8_t* data, uint32_t size ) -> void;
    auto declfn parser_byte( Parser* p ) -> uint8_t;
    auto declfn parser_int32( Parser* p ) -> uint32_t;
    auto declfn parser_bytes( Parser* p, uint32_t* out_len ) -> uint8_t*;
    auto declfn parser_string( Parser* p, uint32_t* out_len ) -> char*;
    auto declfn parser_raw( Parser* p, uint32_t len ) -> uint8_t*;
    auto declfn parser_remaining( Parser* p ) -> uint32_t;
}

#endif
