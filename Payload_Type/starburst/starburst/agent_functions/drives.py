from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class DrivesArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class DrivesCommand(CommandBase):
    cmd = "drives"
    needs_admin = False
    help_cmd = "drives"
    description = "Enumerate logical drives and their types"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1082"]
    argument_class = DrivesArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        return MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
