from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class NetLocalgroupMemberArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                default_value="",
                description="Target hostname (empty for local machine)",
            ),
            CommandParameter(
                name="group",
                type=ParameterType.String,
                description="Local group name to enumerate members of",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class NetLocalgroupMemberCommand(CommandBase):
    cmd = "net_localgroup_member"
    needs_admin = False
    help_cmd = "net_localgroup_member -group Administrators [-hostname DC01]"
    description = "Enumerate members of a local group on the specified host."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1069.001"]
    argument_class = NetLocalgroupMemberArguments
    browser_script = BrowserScript(script_name="net_localgroup_member", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        group = taskData.args.get_arg("group")
        hostname = taskData.args.get_arg("hostname")
        if hostname:
            response.DisplayParams = f"{hostname}\\{group}"
        else:
            response.DisplayParams = group
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
