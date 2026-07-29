from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class NetSessionsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                description="Target hostname (default: localhost)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)


class NetSessionsCommand(CommandBase):
    cmd = "net_sessions"
    needs_admin = False
    help_cmd = "net_sessions [-hostname DC01]"
    description = "Enumerate active SMB sessions on a host"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1049"]
    argument_class = NetSessionsArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        hostname = taskData.args.get_arg("hostname")
        if hostname:
            response.DisplayParams = f"-Hostname {hostname}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
