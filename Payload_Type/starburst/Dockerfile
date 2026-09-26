FROM itsafeaturemythic/mythic_python_base:latest

RUN apt-get clean
RUN dpkg --add-architecture i386

RUN if grep -q bullseye /etc/apt/sources.list 2>/dev/null; then \
        sed -i \
            -e '/debian-security\|security\.debian/d' \
            -e 's|deb.debian.org/debian|archive.debian.org/debian|g' \
            -e '/bullseye-updates/d' -e '/bullseye-backports/d' \
            /etc/apt/sources.list && \
        echo 'deb http://snapshot.debian.org/archive/debian/20250101T000000Z/ bullseye main' \
            >> /etc/apt/sources.list && \
        echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive && \
        echo 'Acquire::Retries "3";' >> /etc/apt/apt.conf.d/99archive; \
    fi
RUN rm -f /etc/apt/sources.list.d/*.list 2>/dev/null || true

RUN printf 'Package: libc6* libc-bin libc-dev-bin libssl* lib32gcc-s1 lib32stdc++6\nPin: origin snapshot.debian.org\nPin-Priority: 1001\n' \
    > /etc/apt/preferences.d/99snapshot-compat

RUN apt-get update \
    && apt-get install -y --no-install-recommends --allow-downgrades \
        ccache clang gcc gcc-multilib nasm \
        mingw-w64 g++-mingw-w64-x86-64 g++-mingw-w64-i686 \
        binutils-mingw-w64 make \
        libssl-dev libssl-dev:i386 \
        zlib1g-dev wget apt-transport-https gnupg \
    && wget -qO- https://packages.adoptium.net/artifactory/api/gpg/key/public \
        | tee /etc/apt/trusted.gpg.d/adoptium.asc > /dev/null \
    && echo 'deb https://packages.adoptium.net/artifactory/deb bullseye main' \
        > /etc/apt/sources.list.d/adoptium.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends temurin-17-jre \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

ENV CCACHE_DIR=/var/cache/ccache
ENV CCACHE_MAXSIZE=500M

COPY [".", "/Mythic"]

WORKDIR /Mythic/

RUN mkdir -p starburst/agent_code/bin/obj \
    && cp starburst/agent_code/include/config.h starburst/agent_code/include/config.h.orig \
    && python3 -c "\
import re; \
p = 'starburst/agent_code/include/config.h'; \
t = open(p).read(); \
cmds = re.findall(r'#define (INCLUDE_CMD_\w+)', t); \
cmd_defs_all = '\n'.join(f'#define {c}' for c in cmds); \
cmd_defs_none = '\n'.join(f'#define _NOCMD_{c.replace(\"INCLUDE_CMD_\",\"\")} 1' for c in cmds); \
evasion = '#define INCLUDE_EVASION_SPOOF\n#define SPOOF_PROFILE SPOOF_PROFILE_THREAD\n#define INJECTION_TECHNIQUE INJECT_CRT\n#define SLEEP_MASK_TYPE MASK_DEFAULT\n#define INCLUDE_EVASION_AMSI\n#define INCLUDE_EVASION_ETW'; \
t_all = t.replace('%TRANSPORT_DEFINE%', '#define HTTP_TRANSPORT') \
         .replace('%CONFIG_BYTES%', '0x00') \
         .replace('%COMMAND_DEFINES%', cmd_defs_all) \
         .replace('%EVASION_DEFINES%', evasion); \
t_none = t.replace('%TRANSPORT_DEFINE%', '#define HTTP_TRANSPORT') \
          .replace('%CONFIG_BYTES%', '0x00') \
          .replace('%COMMAND_DEFINES%', cmd_defs_none) \
          .replace('%EVASION_DEFINES%', evasion); \
open(p, 'w').write(t_all); \
open(p + '.none', 'w').write(t_none)" \
    && echo '[+] warmup pass 1: all commands' \
    && make -C starburst/agent_code x64 2>&1 | tail -3; \
    make -C starburst/agent_code clean >/dev/null 2>&1; \
    cp starburst/agent_code/include/config.h.none starburst/agent_code/include/config.h \
    && echo '[+] warmup pass 2: no commands' \
    && make -C starburst/agent_code x64 2>&1 | tail -3; \
    make -C starburst/agent_code clean >/dev/null 2>&1; \
    rm -f starburst/agent_code/include/config.h.none; \
    mv starburst/agent_code/include/config.h.orig starburst/agent_code/include/config.h; \
    echo "[+] ccache warmed (both passes)"; ccache -s

CMD ["sh", "-c", "\
  chmod +x /Mythic/loaders/crystal-palace/crystal-linker/cpl 2>/dev/null; \
  for d in /Mythic/loaders/crystal-palace/default /Mythic/loaders/crystal-palace/post-ex; do \
    if [ -f \"$d/Makefile\" ] && ! ls \"$d/bin/\"*.o >/dev/null 2>&1; then \
      mkdir -p \"$d/bin\" && make -C \"$d\" x64 2>&1 && echo \"[+] Built COFF objects in $d\"; \
    fi; \
  done; \
  exec python3 main.py"]
