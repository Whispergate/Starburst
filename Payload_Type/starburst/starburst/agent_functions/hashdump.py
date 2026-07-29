from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class HashdumpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class HashdumpCommand(CommandBase):
    cmd = "hashdump"
    needs_admin = True
    help_cmd = "hashdump"
    description = "Dump SAM database hashes from the registry"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1003.002"]
    argument_class = HashdumpArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        response.DisplayParams = ""
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
