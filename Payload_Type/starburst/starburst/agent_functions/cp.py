from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class CpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="source",
                type=ParameterType.String,
                description="Source file path",
            ),
            CommandParameter(
                name="destination",
                type=ParameterType.String,
                description="Destination file path",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class CpCommand(CommandBase):
    cmd = "cp"
    needs_admin = False
    help_cmd = "cp -source C:\\src.txt -destination C:\\dst.txt"
    description = "Copy a file to a new location."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1106"]
    argument_class = CpArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        src = taskData.args.get_arg("source")
        dst = taskData.args.get_arg("destination")
        response.DisplayParams = f"{src} -> {dst}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
