from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class TimestompArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Target file path to modify timestamps on",
            ),
            CommandParameter(
                name="source",
                type=ParameterType.String,
                description="Source file to copy timestamps from (default: C:\\Windows\\System32\\notepad.exe)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                self.add_arg("path", self.command_line.strip())


class TimestompCommand(CommandBase):
    cmd = "timestomp"
    needs_admin = False
    help_cmd = "timestomp -path <target> [-source <reference_file>]"
    description = "Copy file timestamps from a source file to a target file. If no source is specified, copies timestamps from notepad.exe."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1070.006"]
    argument_class = TimestompArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        path = taskData.args.get_arg("path")
        source = taskData.args.get_arg("source")
        if source:
            response.DisplayParams = f"{path} <- {source}"
        else:
            response.DisplayParams = f"{path} <- notepad.exe"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
