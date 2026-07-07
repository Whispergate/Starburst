from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class IdletimeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class IdletimeCommand(CommandBase):
    cmd = "idletime"
    needs_admin = False
    help_cmd = "idletime"
    description = "Display the number of seconds the user has been idle on the remote system."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1082"]
    argument_class = IdletimeArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        return MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
