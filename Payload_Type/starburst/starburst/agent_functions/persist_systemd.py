from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PersistSystemdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["install", "remove", "list"],
                default_value="install",
                description="install, remove, or list systemd services",
            ),
            CommandParameter(
                name="name",
                type=ParameterType.String,
                default_value="",
                description="Service unit name (without .service suffix)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="binary_path",
                type=ParameterType.String,
                default_value="",
                description="Full path to the binary to run as a service",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class PersistSystemdCommand(CommandBase):
    cmd = "persist_systemd"
    needs_admin = False
    help_cmd = "persist_systemd -action install -name myagent -binary_path /tmp/agent"
    description = "Install, remove, or list systemd service persistence. Uses system units if root, user units otherwise."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1543.002"]
    argument_class = PersistSystemdArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Linux])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        name = taskData.args.get_arg("name")
        response.DisplayParams = f"{action} {name}" if name else action
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
