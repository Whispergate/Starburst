#ifndef STARBURST_PACKAGE_H
#define STARBURST_PACKAGE_H

#include <common.h>

namespace starburst {

    struct Package {
        uint8_t* buffer;
        uint32_t length;
        uint32_t capacity;
    };

    auto declfn package_create( instance& inst ) -> Package*;
    auto declfn package_add_byte( instance& inst, Package* pkg, uint8_t val ) -> void;
    auto declfn package_add_int32( instance& inst, Package* pkg, uint32_t val ) -> void;
    auto declfn package_add_bytes( instance& inst, Package* pkg, uint8_t* data, uint32_t len ) -> void;
    auto declfn package_add_string( instance& inst, Package* pkg, char* str ) -> void;
    auto declfn package_add_wstring( instance& inst, Package* pkg, wchar_t* str, uint32_t len ) -> void;
    auto declfn package_build( Package* pkg, uint32_t* out_len ) -> uint8_t*;
    auto declfn package_destroy( instance& inst, Package* pkg ) -> void;

    auto declfn queue_response( instance& inst, char* task_uuid, uint8_t status, char* output ) -> void;

}

#endif
