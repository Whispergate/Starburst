from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RunArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Full command line to execute (no cmd.exe wrapper)",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                self.add_arg("command", self.command_line.strip())


class RunCommand(CommandBase):
    cmd = "run"
    needs_admin = False
    help_cmd = "run [command]"
    description = "Execute a process directly without cmd.exe wrapper. Captures stdout/stderr."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1106"]
    argument_class = RunArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        response.DisplayParams = taskData.args.get_arg("command")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
