from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class UptimeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class UptimeCommand(CommandBase):
    cmd = "uptime"
    needs_admin = False
    help_cmd = "uptime"
    description = "Get system uptime and approximate boot time"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1082"]
    argument_class = UptimeArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        return MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
