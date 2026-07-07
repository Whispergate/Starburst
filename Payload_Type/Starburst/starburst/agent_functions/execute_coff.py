from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecuteCoffArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="COFF/BOF object file to execute",
            ),
            CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="Packed arguments for the BOF (hex-encoded or raw)",
                default_value="",
            ),
            CommandParameter(
                name="entrypoint",
                type=ParameterType.String,
                description="Entry point function name",
                default_value="go",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class ExecuteCoffCommand(CommandBase):
    cmd = "execute_coff"
    needs_admin = False
    help_cmd = "execute_coff -file <bof.o> -entrypoint go"
    description = "Execute a COFF/BOF (Beacon Object File) with Beacon API compatibility."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1106"]
    argument_class = ExecuteCoffArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
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
        taskData.args.add_arg("coff_data", base64.b64encode(file_resp.Content).decode(), ParameterType.String)
        taskData.args.remove_arg("file")

        entry = taskData.args.get_arg("entrypoint") or "go"
        coff_len = len(file_resp.Content)
        response.DisplayParams = f"{coff_len} bytes, entry={entry}"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
