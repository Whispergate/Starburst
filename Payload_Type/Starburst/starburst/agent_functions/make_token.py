from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class MakeTokenArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                default_value=".",
                description="Domain or '.' for local logon",
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Username to authenticate as",
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Password for authentication",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class MakeTokenCommand(CommandBase):
    cmd = "make_token"
    needs_admin = False
    help_cmd = "make_token -domain CORP -username admin -password P@ssw0rd"
    description = "Create a new logon token with the specified credentials (LOGON32_LOGON_NEW_CREDENTIALS). Affects network authentication only."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134.001"]
    argument_class = MakeTokenArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        domain = taskData.args.get_arg("domain")
        username = taskData.args.get_arg("username")
        response.DisplayParams = f"{domain}\\{username}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
