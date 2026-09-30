#include <common.h>

using namespace stardust;

auto declfn instance::heap_alloc(
    _In_ uint32_t size
) -> void* {
    void* ptr = ntdll.RtlAllocateHeap(
        NtCurrentPeb()->ProcessHeap,
        HEAP_ZERO_MEMORY,
        size
    );

    if ( ptr && heap_tracker.count < HEAP_TRACKER_CAPACITY ) {
        auto& rec = heap_tracker.entries[heap_tracker.count++];
        rec.ptr  = ptr;
        rec.size = size;
    }

    return ptr;
}

auto declfn instance::heap_realloc(
    _In_ void*    ptr,
    _In_ uint32_t size
) -> void* {
    if ( !ptr ) {
        return heap_alloc( size );
    }

    void* new_ptr = ntdll.RtlReAllocateHeap(
        NtCurrentPeb()->ProcessHeap,
        HEAP_ZERO_MEMORY,
        ptr,
        size
    );

    if ( new_ptr ) {
        for ( uint32_t i = 0; i < heap_tracker.count; i++ ) {
            if ( heap_tracker.entries[i].ptr == ptr ) {
                heap_tracker.entries[i].ptr  = new_ptr;
                heap_tracker.entries[i].size = size;
                return new_ptr;
            }
        }
        if ( heap_tracker.count < HEAP_TRACKER_CAPACITY ) {
            auto& rec = heap_tracker.entries[heap_tracker.count++];
            rec.ptr  = new_ptr;
            rec.size = size;
        }
    }

    return new_ptr;
}

auto declfn instance::heap_free(
    _In_ void* ptr
) -> void {
    if ( ptr ) {
        for ( uint32_t i = 0; i < heap_tracker.count; i++ ) {
            if ( heap_tracker.entries[i].ptr == ptr ) {
                heap_tracker.entries[i] = heap_tracker.entries[--heap_tracker.count];
                break;
            }
        }

        ntdll.RtlFreeHeap(
            NtCurrentPeb()->ProcessHeap,
            0,
            ptr
        );
    }
}
