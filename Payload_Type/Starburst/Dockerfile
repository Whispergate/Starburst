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

CMD ["python3", "main.py"]
