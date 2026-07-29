from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class EnvArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class EnvCommand(CommandBase):
    cmd = "env"
    needs_admin = False
    help_cmd = "env"
    description = "List all environment variables."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1082"]
    argument_class = EnvArguments
    browser_script = BrowserScript(script_name="env", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        return MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
