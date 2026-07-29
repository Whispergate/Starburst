from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SleepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="interval",
                type=ParameterType.Number,
                default_value=10,
                description="Sleep interval in seconds",
            ),
            CommandParameter(
                name="jitter",
                type=ParameterType.Number,
                default_value=23,
                description="Jitter percentage (0-100)",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                parts = self.command_line.strip().split()
                if len(parts) >= 1:
                    self.add_arg("interval", int(parts[0]))
                if len(parts) >= 2:
                    self.add_arg("jitter", int(parts[1]))


class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep [interval] [jitter]"
    description = "Change the agent's sleep interval and jitter. Interval in seconds, jitter as percentage."
    version = 1
    supported_ui_features = ["callback_table:sleep"]
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = SleepArguments
    attributes = CommandAttributes(
        builtin=True
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        interval = taskData.args.get_arg("interval")
        jitter = taskData.args.get_arg("jitter")
        response.DisplayParams = f"interval={interval}s jitter={jitter}%"

        # convert seconds to milliseconds for the agent
        taskData.args.add_arg("interval", interval * 1000)

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
