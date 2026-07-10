#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_UPTIME

using namespace stardust;
using namespace starburst;

typedef ULONGLONG (WINAPI *fn_GetTickCount64)( void );
typedef void      (WINAPI *fn_GetSystemTime)( LPSYSTEMTIME );

auto declfn starburst::cmd_uptime(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    auto k32 = (HMODULE)inst.kernel32.handle;

    auto pGetTickCount64 = reinterpret_cast<fn_GetTickCount64>(
        inst.kernel32.GetProcAddress( k32,
            symbol<LPCSTR>( "GetTickCount64" ) ) );
    auto pGetSystemTime = reinterpret_cast<fn_GetSystemTime>(
        inst.kernel32.GetProcAddress( k32,
            symbol<LPCSTR>( "GetSystemTime" ) ) );

    if ( !pGetTickCount64 || !pGetSystemTime ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "API resolution failed" ) ) );
        return;
    }

    ULONGLONG tick_ms = pGetTickCount64();
    uint32_t total_sec = static_cast<uint32_t>( tick_ms / 1000 );
    uint32_t days    = total_sec / 86400;
    uint32_t hours   = ( total_sec % 86400 ) / 3600;
    uint32_t minutes = ( total_sec % 3600 ) / 60;
    uint32_t seconds = total_sec % 60;

    // Get current system time (UTC)
    SYSTEMTIME now = {};
    pGetSystemTime( &now );

    // Approximate boot time by subtracting uptime seconds from current time
    // Simple subtraction handling borrows
    int boot_sec  = now.wSecond - (int)(seconds);
    int boot_min  = now.wMinute - (int)(minutes);
    int boot_hour = now.wHour   - (int)(hours);
    int boot_day  = now.wDay    - (int)(days);
    int boot_mon  = now.wMonth;
    int boot_year = now.wYear;

    if ( boot_sec < 0 )  { boot_sec += 60; boot_min--; }
    if ( boot_min < 0 )  { boot_min += 60; boot_hour--; }
    if ( boot_hour < 0 ) { boot_hour += 24; boot_day--; }
    if ( boot_day < 1 )  { boot_mon--; boot_day += 28; }
    if ( boot_mon < 1 )  { boot_mon += 12; boot_year--; }

    char output[256] = { 0 };
    uint32_t off = 0;
    char num[16];

    // "Uptime: Xd Xh Xm Xs\n"
    str_copy( output + off, symbol<char*>( const_cast<char*>( "Uptime: " ) ) );
    off = str_len( output );

    int_to_str( num, days, 10 );
    memory::copy( output + off, num, str_len( num ) ); off += str_len( num );
    output[off++] = 'd'; output[off++] = ' ';

    int_to_str( num, hours, 10 );
    memory::copy( output + off, num, str_len( num ) ); off += str_len( num );
    output[off++] = 'h'; output[off++] = ' ';

    int_to_str( num, minutes, 10 );
    memory::copy( output + off, num, str_len( num ) ); off += str_len( num );
    output[off++] = 'm'; output[off++] = ' ';

    int_to_str( num, seconds, 10 );
    memory::copy( output + off, num, str_len( num ) ); off += str_len( num );
    output[off++] = 's';
    output[off++] = '\n';

    // "Boot: approx YYYY-MM-DD HH:MM:SS"
    str_copy( output + off, symbol<char*>( const_cast<char*>( "Boot: approx " ) ) );
    off += 13;

    int_to_str( num, boot_year, 10 );
    uint32_t ylen = str_len( num );
    for ( uint32_t i = ylen; i < 4; i++ ) output[off++] = '0';
    memory::copy( output + off, num, ylen ); off += ylen;
    output[off++] = '-';

    int_to_str( num, boot_mon, 10 );
    if ( boot_mon < 10 ) output[off++] = '0';
    uint32_t mlen = str_len( num );
    memory::copy( output + off, num, mlen ); off += mlen;
    output[off++] = '-';

    int_to_str( num, boot_day, 10 );
    if ( boot_day < 10 ) output[off++] = '0';
    uint32_t dlen = str_len( num );
    memory::copy( output + off, num, dlen ); off += dlen;
    output[off++] = ' ';

    int_to_str( num, boot_hour, 10 );
    if ( boot_hour < 10 ) output[off++] = '0';
    uint32_t hlen = str_len( num );
    memory::copy( output + off, num, hlen ); off += hlen;
    output[off++] = ':';

    int_to_str( num, boot_min, 10 );
    if ( boot_min < 10 ) output[off++] = '0';
    uint32_t mnlen = str_len( num );
    memory::copy( output + off, num, mnlen ); off += mnlen;
    output[off++] = ':';

    int_to_str( num, boot_sec, 10 );
    if ( boot_sec < 10 ) output[off++] = '0';
    uint32_t slen = str_len( num );
    memory::copy( output + off, num, slen ); off += slen;

    output[off] = '\0';
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
}

#endif
