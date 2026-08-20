#ifndef STARBURST_STACKSTR_H
#define STARBURST_STACKSTR_H

#define STK_ADVAPI32(v)     char v[] = {'a','d','v','a','p','i','3','2','.','d','l','l',0}
#define STK_BCRYPT(v)       char v[] = {'b','c','r','y','p','t','.','d','l','l',0}
#define STK_WINHTTP(v)      char v[] = {'w','i','n','h','t','t','p','.','d','l','l',0}
#define STK_WININET(v)      char v[] = {'w','i','n','i','n','e','t','.','d','l','l',0}
#define STK_IPHLPAPI(v)     char v[] = {'i','p','h','l','p','a','p','i','.','d','l','l',0}
#define STK_WS2_32(v)       char v[] = {'w','s','2','_','3','2','.','d','l','l',0}
#define STK_USER32(v)       char v[] = {'u','s','e','r','3','2','.','d','l','l',0}
#define STK_GDI32(v)        char v[] = {'g','d','i','3','2','.','d','l','l',0}
#define STK_OLE32(v)        char v[] = {'o','l','e','3','2','.','d','l','l',0}
#define STK_OLEAUT32(v)     char v[] = {'o','l','e','a','u','t','3','2','.','d','l','l',0}
#define STK_MSCOREE(v)      char v[] = {'m','s','c','o','r','e','e','.','d','l','l',0}
#define STK_NETAPI32(v)     char v[] = {'n','e','t','a','p','i','3','2','.','d','l','l',0}
#define STK_DBGHELP(v)      char v[] = {'d','b','g','h','e','l','p','.','d','l','l',0}
#define STK_AMSI(v)         char v[] = {'a','m','s','i','.','d','l','l',0}
#define STK_WPCAP(v)        char v[] = {'w','p','c','a','p','.','d','l','l',0}
#define STK_NPCAP_PATH(v)   char v[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','N','p','c','a','p','\\','w','p','c','a','p','.','d','l','l',0}

#define STK_RUNDLL32_X64(v) char v[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','r','u','n','d','l','l','3','2','.','e','x','e',0}
#define STK_RUNDLL32_X86(v) char v[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','W','O','W','6','4','\\','r','u','n','d','l','l','3','2','.','e','x','e',0}
#define STK_RUNTIMEBROKER(v) char v[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','R','u','n','t','i','m','e','B','r','o','k','e','r','.','e','x','e',0}

#endif
