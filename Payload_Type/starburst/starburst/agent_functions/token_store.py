from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class TokenStoreArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["list", "use", "remove"],
                default_value="list",
                description="Action to perform on the token store",
            ),
            CommandParameter(
                name="token_id",
                type=ParameterType.Number,
                default_value=0,
                description="Token ID to use or remove (0 for list)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)


class TokenStoreCommand(CommandBase):
    cmd = "token_store"
    needs_admin = False
    help_cmd = "token_store -action list | token_store -action use -token_id 2 | token_store -action remove -token_id 2"
    description = "Manage stored access tokens for impersonation"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134.001"]
    argument_class = TokenStoreArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        token_id = taskData.args.get_arg("token_id")
        if action != "list":
            response.DisplayParams = f"{action} #{token_id}"
        else:
            response.DisplayParams = f"{action}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
