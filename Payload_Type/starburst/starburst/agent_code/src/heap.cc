#include <common.h>

using namespace stardust;

auto declfn instance::heap_alloc(
    _In_ uint32_t size
) -> void* {
    return ntdll.RtlAllocateHeap(
        NtCurrentPeb()->ProcessHeap,
        HEAP_ZERO_MEMORY,
        size
    );
}

auto declfn instance::heap_realloc(
    _In_ void*    ptr,
    _In_ uint32_t size
) -> void* {
    if ( !ptr ) {
        return heap_alloc( size );
    }

    return ntdll.RtlReAllocateHeap(
        NtCurrentPeb()->ProcessHeap,
        HEAP_ZERO_MEMORY,
        ptr,
        size
    );
}

auto declfn instance::heap_free(
    _In_ void* ptr
) -> void {
    if ( ptr ) {
        ntdll.RtlFreeHeap(
            NtCurrentPeb()->ProcessHeap,
            0,
            ptr
        );
    }
}
