from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class MigrateArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="Target process ID to migrate into",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                self.add_arg("pid", int(self.command_line.strip()))


class MigrateCommand(CommandBase):
    cmd = "migrate"
    needs_admin = False
    help_cmd = "migrate [pid]"
    description = "Migrate the agent into a target process. Injects agent shellcode into the target and terminates the current instance."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1055.001"]
    argument_class = MigrateArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        response.DisplayParams = f"PID {taskData.args.get_arg('pid')}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
