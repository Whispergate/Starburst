from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PpidSpoofArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="ppid",
                type=ParameterType.Number,
                default_value=0,
                description="Parent PID to spoof (0 to disable)",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class PpidSpoofCommand(CommandBase):
    cmd = "ppid_spoof"
    needs_admin = False
    help_cmd = "ppid_spoof -ppid 1234"
    description = "Set or clear the parent PID for child process spoofing"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1134.004"]
    argument_class = PpidSpoofArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        ppid = taskData.args.get_arg("ppid")
        response.DisplayParams = f"PPID: {ppid}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
