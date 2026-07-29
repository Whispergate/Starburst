from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PersistBashrcArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["install", "list"],
                default_value="install",
                description="install a command into .bashrc or list current rc file contents",
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                default_value="",
                description="Command to append to .bashrc (runs on each shell login)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class PersistBashrcCommand(CommandBase):
    cmd = "persist_bashrc"
    needs_admin = False
    help_cmd = "persist_bashrc -action install -command '/tmp/agent'"
    description = "Append a command to the user's .bashrc for shell login persistence, or list current rc file contents."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1546.004"]
    argument_class = PersistBashrcArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Linux])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        cmd = taskData.args.get_arg("command")
        response.DisplayParams = f"{action}: {cmd}" if cmd else action
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
