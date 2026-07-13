FROM itsafeaturemythic/mythic_python_go:latest

RUN apt-get update && apt-get install -y \
    clang \
    gcc \
    nasm \
    mingw-w64 \
    g++-mingw-w64-x86-64 \
    g++-mingw-w64-i686 \
    binutils-mingw-w64 \
    make \
    openjdk-11-jre-headless \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

WORKDIR /Mythic/

CMD ["sh", "-c", "\
  chmod +x /Mythic/loaders/crystal-palace/crystal-linker/cpl 2>/dev/null; \
  for d in /Mythic/loaders/crystal-palace/default /Mythic/loaders/crystal-palace/post-ex; do \
    if [ -f \"$d/Makefile\" ] && ! ls \"$d/bin/\"*.o >/dev/null 2>&1; then \
      mkdir -p \"$d/bin\" && make -C \"$d\" x64 2>&1 && echo \"[+] Built COFF objects in $d\"; \
    fi; \
  done; \
  exec python3 main.py"]
