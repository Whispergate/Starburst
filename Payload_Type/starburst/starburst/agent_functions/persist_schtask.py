from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PersistSchtaskArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["install", "remove"],
                default_value="install",
                description="Install or remove the scheduled task",
            ),
            CommandParameter(
                name="name",
                type=ParameterType.String,
                description="Scheduled task name",
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to execute (required for install)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="trigger",
                type=ParameterType.ChooseOne,
                choices=["logon", "daily", "startup"],
                default_value="logon",
                description="Task trigger type",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)


class PersistSchtaskCommand(CommandBase):
    cmd = "persist_schtask"
    needs_admin = False
    help_cmd = "persist_schtask"
    description = "Create or delete a scheduled task for persistence"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1053.005"]
    argument_class = PersistSchtaskArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        name = taskData.args.get_arg("name")
        trigger = taskData.args.get_arg("trigger")
        response.DisplayParams = f"{action} {name}" + (f" trigger={trigger}" if action == "install" else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
