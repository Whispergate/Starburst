from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class SshArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                cli_name="hostname",
                type=ParameterType.String,
                description="Target hostname or IP address",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, group_name="Password Auth", ui_position=1),
                    ParameterGroupInfo(required=True, group_name="Key Auth", ui_position=1),
                ],
            ),
            CommandParameter(
                name="port",
                cli_name="port",
                type=ParameterType.Number,
                default_value=22,
                description="SSH port",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Password Auth", ui_position=2),
                    ParameterGroupInfo(required=False, group_name="Key Auth", ui_position=2),
                ],
            ),
            CommandParameter(
                name="username",
                cli_name="username",
                type=ParameterType.String,
                description="SSH username",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, group_name="Password Auth", ui_position=3),
                    ParameterGroupInfo(required=True, group_name="Key Auth", ui_position=3),
                ],
            ),
            CommandParameter(
                name="credential",
                cli_name="credential",
                type=ParameterType.String,
                description="SSH password (Password Auth) or key passphrase (Key Auth)",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, group_name="Password Auth", ui_position=4),
                    ParameterGroupInfo(required=False, group_name="Key Auth", ui_position=5),
                ],
            ),
            CommandParameter(
                name="private_key",
                cli_name="private_key",
                type=ParameterType.File,
                description="SSH private key file (PEM format, unencrypted RSA)",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, group_name="Key Auth", ui_position=4),
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                if len(parts) >= 3:
                    userhost = parts[0]
                    if "@" in userhost:
                        user, host = userhost.split("@", 1)
                        self.add_arg("username", user)
                        if ":" in host:
                            h, p = host.rsplit(":", 1)
                            self.add_arg("hostname", h)
                            self.add_arg("port", int(p))
                        else:
                            self.add_arg("hostname", host)
                    self.add_arg("credential", parts[1] if len(parts) > 1 else "")


class SshCommand(CommandBase):
    cmd = "ssh"
    needs_admin = False
    help_cmd = "ssh -hostname <host> -username <user> -credential <pass> [-port 22]"
    description = (
        "Interactive SSH2 terminal. Connects to remote hosts using built-in SSH2 "
        "protocol (ECDH-P256, AES-256-CTR, HMAC-SHA2-256). Opens a PTY shell "
        "with interactive I/O through Mythic's terminal UI. Supports password "
        "and RSA private key authentication. No ssh.exe dependency."
    )
    version = 10
    author = "@Lavender-exe"
    argument_class = SshArguments
    attackmapping = ["T1021.004"]
    supported_ui_features = ["task_response:interactive"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        hostname = taskData.args.get_arg("hostname")
        port = taskData.args.get_arg("port") or 22
        username = taskData.args.get_arg("username")
        credential = taskData.args.get_arg("credential") or ""

        if not hostname or not username:
            response.Success = False
            response.Error = "hostname and username required"
            return response

        key_data = ""
        private_key_id = taskData.args.get_arg("private_key")
        if private_key_id:
            try:
                file_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                    AgentFileId=private_key_id
                ))
                if not file_resp.Success or not file_resp.Content:
                    response.Success = False
                    response.Error = f"Failed to retrieve private key file: {file_resp.Error}"
                    return response

                pem_bytes = file_resp.Content
                passphrase = credential.encode() if credential else None

                try:
                    from cryptography.hazmat.primitives.serialization import (
                        load_pem_private_key, Encoding, PrivateFormat, NoEncryption
                    )
                    priv_key = load_pem_private_key(pem_bytes, password=passphrase)
                    key_data = priv_key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=NoEncryption()
                    ).decode("utf-8")
                except ValueError as e:
                    if "password" in str(e).lower() or "encrypt" in str(e).lower():
                        response.Success = False
                        response.Error = "Private key is encrypted - provide the passphrase in the credential field"
                        return response
                    raise
                except TypeError:
                    response.Success = False
                    response.Error = "Private key is encrypted - provide the passphrase in the credential field"
                    return response
            except Exception as e:
                if not response.Error:
                    response.Success = False
                    response.Error = f"Error processing private key: {str(e)}"
                return response

        taskData.args.add_arg("key_data", key_data)
        taskData.args.remove_arg("private_key")

        if not credential and not key_data:
            response.Success = False
            response.Error = "Either credential (password) or private_key is required"
            return response

        auth_method = "key" if key_data else "password"
        response.DisplayParams = f"{username}@{hostname}:{port} ({auth_method})"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
