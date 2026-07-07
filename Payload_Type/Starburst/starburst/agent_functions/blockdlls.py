from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class BlockdllsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class BlockdllsCommand(CommandBase):
    cmd = "blockdlls"
    needs_admin = False
    help_cmd = "blockdlls"
    description = "Block non-Microsoft-signed DLLs from loading into the current process. This is a one-way operation - once enabled, it cannot be disabled for the lifetime of the process (Windows kernel enforcement)."
    version = 2
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1574.001"]
    argument_class = BlockdllsArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        response.DisplayParams = "enable"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
