#ifndef STARBURST_OBFSTR_H
#define STARBURST_OBFSTR_H

namespace obf {

constexpr unsigned char XK = 0x41;
constexpr unsigned char XM = 131;

template<unsigned N>
struct enc {
    char data[N];
    consteval enc(const char (&s)[N]) {
        for (unsigned i = 0; i < N; i++)
            data[i] = s[i] ^ static_cast<char>((XK + i * XM) & 0xFFu);
    }
};
template<unsigned N> enc(const char (&)[N]) -> enc<N>;

template<unsigned N>
struct wenc {
    wchar_t data[N];
    consteval wenc(const wchar_t (&s)[N]) {
        for (unsigned i = 0; i < N; i++)
            data[i] = s[i] ^ static_cast<wchar_t>((XK + i * XM) & 0xFFFFu);
    }
};
template<unsigned N> wenc(const wchar_t (&)[N]) -> wenc<N>;

__attribute__((always_inline))
inline void dec(const char* s, char* d, unsigned n) {
    for (unsigned i = 0; i < n; i++)
        d[i] = s[i] ^ static_cast<char>((XK + i * XM) & 0xFFu);
}

__attribute__((always_inline))
inline void wdec(const wchar_t* s, wchar_t* d, unsigned n) {
    for (unsigned i = 0; i < n; i++)
        d[i] = s[i] ^ static_cast<wchar_t>((XK + i * XM) & 0xFFFFu);
}

} // namespace obf

#define xstr(var, s) \
    static constexpr obf::enc _xe_##var(s); \
    char var[sizeof(s)]; \
    obf::dec(stardust::symbol<char*>(const_cast<char*>(_xe_##var.data)), var, sizeof(s))

#define xwstr(var, s) \
    static constexpr obf::wenc _xwe_##var(s); \
    wchar_t var[sizeof(s) / sizeof(wchar_t)]; \
    obf::wdec(stardust::symbol<wchar_t*>(const_cast<wchar_t*>(_xwe_##var.data)), var, sizeof(s) / sizeof(wchar_t))

#define XSTR(s) \
    ({ \
        static constexpr obf::enc _xe(s); \
        char* _xb = (char*)__builtin_alloca(sizeof(s)); \
        obf::dec(stardust::symbol<char*>(const_cast<char*>(_xe.data)), _xb, sizeof(s)); \
        _xb; \
    })

#define XWSTR(s) \
    ({ \
        static constexpr obf::wenc _xwe(s); \
        wchar_t* _xwb = (wchar_t*)__builtin_alloca(sizeof(s)); \
        obf::wdec(stardust::symbol<wchar_t*>(const_cast<wchar_t*>(_xwe.data)), _xwb, sizeof(s) / sizeof(wchar_t)); \
        _xwb; \
    })

#endif
