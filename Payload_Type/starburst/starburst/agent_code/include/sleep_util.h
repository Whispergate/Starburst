#ifndef STARBURST_SLEEP_UTIL_H
#define STARBURST_SLEEP_UTIL_H

#include <windows.h>

static inline SIZE_T GetTimestamp( void )
{
    const SIZE_T UNIX_TIME_START       = 0x019DB1DED53E8000;
    const SIZE_T TICKS_PER_MILLISECOND = 10000;
    LARGE_INTEGER time;
    time.LowPart  = *( volatile DWORD* )( 0x7FFE0000 + 0x14 );
    time.HighPart = *( volatile long* )(  0x7FFE0000 + 0x1c );
    return (SIZE_T)( ( time.QuadPart - UNIX_TIME_START )
        / TICKS_PER_MILLISECOND );
}

static inline void SleepMs( _In_ SIZE_T Ms )
{
    volatile SIZE_T x = 0;
    SIZE_T end_time   = GetTimestamp() + Ms;
    while ( GetTimestamp() < end_time ) x += 1;
    /* overrun check removed: SharedUserData keeps ticking through VM
     * pause/hibernate/snapshot, so a resumed VM always "overran" and the
     * old code nulled itself here - killing the agent on legitimate
     * host suspend, not on tampering */
}

#endif
