from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class StealTokenArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="Process ID to steal token from",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                self.add_arg("pid", int(self.command_line.strip()))


class StealTokenCommand(CommandBase):
    cmd = "steal_token"
    needs_admin = True
    help_cmd = "steal_token [pid]"
    description = "Steal and impersonate the access token from the specified process."
    version = 1
    supported_ui_features = ["process_browser:steal_token"]
    author = "@Lavender-exe"
    attackmapping = ["T1134.001"]
    argument_class = StealTokenArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        response.DisplayParams = str(taskData.args.get_arg("pid"))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
