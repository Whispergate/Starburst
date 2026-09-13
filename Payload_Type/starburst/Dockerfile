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
        clang gcc gcc-multilib nasm \
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

COPY [".", "/Mythic"]

WORKDIR /Mythic/

CMD ["sh", "-c", "\
  chmod +x /Mythic/loaders/crystal-palace/crystal-linker/cpl 2>/dev/null; \
  for d in /Mythic/loaders/crystal-palace/default /Mythic/loaders/crystal-palace/post-ex; do \
    if [ -f \"$d/Makefile\" ] && ! ls \"$d/bin/\"*.o >/dev/null 2>&1; then \
      mkdir -p \"$d/bin\" && make -C \"$d\" x64 2>&1 && echo \"[+] Built COFF objects in $d\"; \
    fi; \
  done; \
  exec python3 main.py"]
