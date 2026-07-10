import os
import asyncio
import tempfile
import logging

from mythic_container.MythicRPC import *

logger = logging.getLogger("starburst.crystal_utilities")

AGENT_CODE_PATH = os.path.join(os.path.dirname(__file__), "agent_code")
LOADERS_PATH = os.path.join(os.path.dirname(__file__), "..", "loaders", "crystal-palace")


def get_crystal_linker_path():
    return os.path.join(LOADERS_PATH, "crystal-linker")


def is_crystal_palace_available():
    linker_path = get_crystal_linker_path()
    jar_file = os.path.join(linker_path, "crystalpalace.jar")
    return os.path.exists(jar_file)


async def link_shellcode_with_cp(shellcode_bytes, arch="x64", loader_path=None):
    if loader_path is None:
        loader_path = os.path.join(LOADERS_PATH, "default")

    crystal_linker = get_crystal_linker_path()
    spec_file = os.path.join(loader_path, "loader.spec")

    if not os.path.exists(spec_file):
        raise FileNotFoundError(f"loader.spec not found at {spec_file}")

    with tempfile.TemporaryDirectory() as tmpdir:
        sc_path = os.path.join(tmpdir, "shellcode.bin")
        out_path = os.path.join(tmpdir, f"out.{arch}.bin")

        with open(sc_path, "wb") as f:
            f.write(shellcode_bytes)

        jar_path = os.path.join(crystal_linker, "crystalpalace.jar")
        command = ["java", "-jar", jar_path, "link", spec_file, sc_path, out_path]

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=crystal_linker,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(
                f"Crystal Palace link failed (rc={proc.returncode}):\n"
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
