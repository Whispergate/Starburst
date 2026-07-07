from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class TokenListArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class TokenListCommand(CommandBase):
    cmd = "token_list"
    needs_admin = False
    help_cmd = "token_list"
    description = "Enumerate process tokens (PID, User, Integrity, Process Name)."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1057", "T1134"]
    argument_class = TokenListArguments
    browser_script = BrowserScript(script_name="token_list", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        return MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
