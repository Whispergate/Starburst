from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class GetuidArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class GetuidCommand(CommandBase):
    cmd = "getuid"
    needs_admin = False
    help_cmd = "getuid"
    description = "Display the current user context including domain, username, SID, integrity level, and elevation status. Context-aware - shows impersonated token if active."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1033"]
    argument_class = GetuidArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        return MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
