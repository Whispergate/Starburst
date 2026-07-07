from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class LocaltimeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class LocaltimeCommand(CommandBase):
    cmd = "localtime"
    needs_admin = False
    help_cmd = "localtime"
    description = "Display the local date and time of the target system."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1124"]
    argument_class = LocaltimeArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        return MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
