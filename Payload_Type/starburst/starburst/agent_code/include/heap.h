#ifndef STARBURST_HEAP_H
#define STARBURST_HEAP_H

#include <common.h>

namespace starburst {

    auto declfn heap_alloc(
        _In_ uint32_t size
    ) -> void*;

    auto declfn heap_realloc(
        _In_ void*    ptr,
        _In_ uint32_t size
    ) -> void*;

    auto declfn heap_free(
        _In_ void* ptr
    ) -> void;

}

#endif
