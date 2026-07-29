from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PersistServiceArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["install", "remove"],
                default_value="install",
                description="Install or remove the service",
            ),
            CommandParameter(
                name="name",
                type=ParameterType.String,
                description="Service name",
            ),
            CommandParameter(
                name="display_name",
                type=ParameterType.String,
                description="Service display name (defaults to name if empty)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="binary_path",
                type=ParameterType.String,
                description="Full path to service binary (required for install)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)


class PersistServiceCommand(CommandBase):
    cmd = "persist_service"
    needs_admin = False
    help_cmd = "persist_service"
    description = "Install or remove a Windows service for persistence"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1543.003"]
    argument_class = PersistServiceArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        name = taskData.args.get_arg("name")
        binary_path = taskData.args.get_arg("binary_path")
        response.DisplayParams = f"{action} {name}" + (f" -> {binary_path}" if binary_path else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
