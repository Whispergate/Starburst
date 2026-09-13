FROM itsafeaturemythic/mythic_python_go:latest

RUN if grep -q bullseye /etc/apt/sources.list 2>/dev/null; then \
        sed -i \
            -e 's|deb.debian.org/debian|archive.debian.org/debian|g' \
            -e 's|security.debian.org|archive.debian.org|g' \
            -e '/bullseye-updates/d' -e '/bullseye-backports/d' \
            /etc/apt/sources.list && \
        echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive; \
    fi

RUN dpkg --add-architecture i386 && \
    apt-get update && apt-get install -y \
    clang \
    gcc \
    gcc-multilib \
    nasm \
    mingw-w64 \
    g++-mingw-w64-x86-64 \
    g++-mingw-w64-i686 \
    binutils-mingw-w64 \
    make \
    openjdk-11-jre-headless \
    libssl-dev \
    libssl-dev:i386 \
    zlib1g-dev \
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
