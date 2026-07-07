from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class PsCommand(CommandBase):
    cmd = "ps"
    needs_admin = False
    help_cmd = "ps"
    description = "List running processes (name, PID, PPID)."
    version = 1
    supported_ui_features = ["process_browser:list"]
    author = "@Lavender-exe"
    attackmapping = ["T1057"]
    argument_class = PsArguments
    browser_script = BrowserScript(script_name="ps", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(
        builtin=False
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
