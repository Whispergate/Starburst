from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class NetLocalgroupArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                default_value="",
                description="Target hostname (empty for local machine)",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                self.add_arg("hostname", self.command_line.strip())


class NetLocalgroupCommand(CommandBase):
    cmd = "net_localgroup"
    needs_admin = False
    help_cmd = "net_localgroup [-hostname DC01]"
    description = "Enumerate local groups on the specified host (or local machine if no hostname)."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1069.001"]
    argument_class = NetLocalgroupArguments
    browser_script = BrowserScript(script_name="net_localgroup", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        hostname = taskData.args.get_arg("hostname")
        if hostname:
            response.DisplayParams = hostname
        else:
            response.DisplayParams = "localhost"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
