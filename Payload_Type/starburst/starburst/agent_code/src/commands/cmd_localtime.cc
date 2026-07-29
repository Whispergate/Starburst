#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_LOCALTIME

using namespace stardust;
using namespace starburst;

typedef void ( WINAPI *fn_GetLocalTime )( LPSYSTEMTIME );

auto declfn starburst::cmd_localtime(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    DBG_PRINT( inst, "cmd_localtime\n" );

    auto k32 = inst.kernel32.handle;

    auto pGetLocalTime = reinterpret_cast<fn_GetLocalTime>(
        inst.kernel32.GetProcAddress( (HMODULE)k32,
            symbol<LPCSTR>( "GetLocalTime" ) ) );

    if ( !pGetLocalTime ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve GetLocalTime" ) ) );
        return;
    }

    SYSTEMTIME st = {};
    pGetLocalTime( &st );

    // format: YYYY-MM-DD HH:MM:SS (DayName)
    char output[128] = { 0 };
    uint32_t off = 0;
    char num[8];

    // year
    int_to_str( num, st.wYear, 10 );
    // pad year to 4 digits
    uint32_t ylen = str_len( num );
    for ( uint32_t i = ylen; i < 4; i++ ) output[off++] = '0';
    memory::copy( output + off, num, ylen );
    off += ylen;
    output[off++] = '-';

    // month
    int_to_str( num, st.wMonth, 10 );
    if ( st.wMonth < 10 ) output[off++] = '0';
    uint32_t mlen = str_len( num );
    memory::copy( output + off, num, mlen );
    off += mlen;
    output[off++] = '-';

    // day
    int_to_str( num, st.wDay, 10 );
    if ( st.wDay < 10 ) output[off++] = '0';
    uint32_t dlen = str_len( num );
    memory::copy( output + off, num, dlen );
    off += dlen;
    output[off++] = ' ';

    // hour
    int_to_str( num, st.wHour, 10 );
    if ( st.wHour < 10 ) output[off++] = '0';
    uint32_t hlen = str_len( num );
    memory::copy( output + off, num, hlen );
    off += hlen;
    output[off++] = ':';

    // minute
    int_to_str( num, st.wMinute, 10 );
    if ( st.wMinute < 10 ) output[off++] = '0';
    uint32_t minlen = str_len( num );
    memory::copy( output + off, num, minlen );
    off += minlen;
    output[off++] = ':';

    // second
    int_to_str( num, st.wSecond, 10 );
    if ( st.wSecond < 10 ) output[off++] = '0';
    uint32_t slen = str_len( num );
    memory::copy( output + off, num, slen );
    off += slen;

    // day of week
    str_copy( output + off, symbol<char*>( const_cast<char*>( " (" ) ) );
    off += 2;

    // wDayOfWeek: 0=Sunday .. 6=Saturday
    switch ( st.wDayOfWeek ) {
        case 0: str_copy( output + off, symbol<char*>( const_cast<char*>( "Sunday" ) ) );    off += 6; break;
        case 1: str_copy( output + off, symbol<char*>( const_cast<char*>( "Monday" ) ) );    off += 6; break;
        case 2: str_copy( output + off, symbol<char*>( const_cast<char*>( "Tuesday" ) ) );   off += 7; break;
        case 3: str_copy( output + off, symbol<char*>( const_cast<char*>( "Wednesday" ) ) ); off += 9; break;
        case 4: str_copy( output + off, symbol<char*>( const_cast<char*>( "Thursday" ) ) );  off += 8; break;
        case 5: str_copy( output + off, symbol<char*>( const_cast<char*>( "Friday" ) ) );    off += 6; break;
        case 6: str_copy( output + off, symbol<char*>( const_cast<char*>( "Saturday" ) ) );  off += 8; break;
        default: break;
    }

    output[off++] = ')';
    output[off] = '\0';

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
}

#endif
