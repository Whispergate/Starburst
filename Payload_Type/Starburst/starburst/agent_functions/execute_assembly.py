from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecuteAssemblyArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description=".NET assembly file to execute",
            ),
            CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="Arguments to pass to the assembly",
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class ExecuteAssemblyCommand(CommandBase):
    cmd = "execute_assembly"
    needs_admin = False
    help_cmd = "execute_assembly -file <assembly> -arguments \"arg1 arg2\""
    description = "Execute a .NET assembly in-process via CLR hosting."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1059.001"]
    argument_class = ExecuteAssemblyArguments
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
        taskData.args.add_arg("assembly_data", base64.b64encode(file_resp.Content).decode(), ParameterType.String)
        taskData.args.remove_arg("file")

        args_str = taskData.args.get_arg("arguments") or ""
        asm_len = len(file_resp.Content)
        response.DisplayParams = f"{asm_len} bytes, args='{args_str}'"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
