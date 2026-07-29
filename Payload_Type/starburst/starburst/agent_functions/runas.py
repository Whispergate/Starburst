from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RunasArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                default_value=".",
                description="Domain name (use . for local)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Username to run as",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Password for the user",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to execute",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class RunasCommand(CommandBase):
    cmd = "runas"
    needs_admin = False
    help_cmd = 'runas -domain . -username admin -password P@ssw0rd -command "whoami"'
    description = "Execute a command as a different user"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134.002"]
    argument_class = RunasArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        domain = taskData.args.get_arg("domain")
        username = taskData.args.get_arg("username")
        command = taskData.args.get_arg("command")
        response.DisplayParams = f"{domain}\\{username} -> {command}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
