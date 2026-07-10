from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import base64


class InlineExecuteArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pic_file",
                type=ParameterType.File,
                description="PIC/shellcode file to execute",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="arguments",
                type=ParameterType.String,
                default_value="",
                description="Arguments to pass to the PIC",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(InlineExecuteCommand.help_cmd))


class InlineExecuteCommand(CommandBase):
    cmd = "inline_execute"
    needs_admin = False
    help_cmd = "inline_execute -pic_file <shellcode.bin> [-arguments 'arg1 arg2']"
    description = "Execute PIC/shellcode inline in the agent process"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1059"]
    argument_class = InlineExecuteArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=taskData.args.get_arg("pic_file"),
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get file content: {file_content.Error}"
            return response

        taskData.args.add_arg("pic_data", base64.b64encode(file_content.Content).decode(), ParameterType.String)

        sc_len = len(file_content.Content)
        arguments = taskData.args.get_arg("arguments")
        if arguments:
            response.DisplayParams = f"<pic_file> ({sc_len} bytes) args: {arguments}"
        else:
            response.DisplayParams = f"<pic_file> ({sc_len} bytes)"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
