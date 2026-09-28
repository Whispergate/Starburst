#ifndef STARBURST_STACKSTR_H
#define STARBURST_STACKSTR_H

#define STK_ADVAPI32(v)     xstr(v, "advapi32.dll")
#define STK_BCRYPT(v)       xstr(v, "bcrypt.dll")
#define STK_WINHTTP(v)      xstr(v, "winhttp.dll")
#define STK_WININET(v)      xstr(v, "wininet.dll")
#define STK_IPHLPAPI(v)     xstr(v, "iphlpapi.dll")
#define STK_WS2_32(v)       xstr(v, "ws2_32.dll")
#define STK_USER32(v)       xstr(v, "user32.dll")
#define STK_GDI32(v)        xstr(v, "gdi32.dll")
#define STK_GDIPLUS(v)      xstr(v, "gdiplus.dll")
#define STK_OLE32(v)        xstr(v, "ole32.dll")
#define STK_COMBASE(v)      xstr(v, "combase.dll")
#define STK_OLEAUT32(v)     xstr(v, "oleaut32.dll")
#define STK_MSCOREE(v)      xstr(v, "mscoree.dll")
#define STK_NETAPI32(v)     xstr(v, "netapi32.dll")
#define STK_DBGHELP(v)      xstr(v, "dbghelp.dll")
#define STK_AMSI(v)         xstr(v, "amsi.dll")
#define STK_WPCAP(v)        xstr(v, "wpcap.dll")
#define STK_NPCAP_PATH(v)   xstr(v, "C:\\Windows\\System32\\Npcap\\wpcap.dll")

#define STK_RUNDLL32_X64(v) xstr(v, "C:\\Windows\\System32\\rundll32.exe")
#define STK_RUNDLL32_X86(v) xstr(v, "C:\\Windows\\SysWOW64\\rundll32.exe")
#define STK_RUNTIMEBROKER(v) xstr(v, "C:\\Windows\\System32\\RuntimeBroker.exe")

#endif
