from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ArgueArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["set", "clear"],
                default_value="set",
                description="Set or clear fake arguments",
            ),
            CommandParameter(
                name="fake_args",
                type=ParameterType.String,
                description="Fake command-line arguments to display",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class ArgueCommand(CommandBase):
    cmd = "argue"
    needs_admin = False
    help_cmd = 'argue -action set -fake_args "notepad.exe"'
    description = "Set or clear fake command-line arguments for child processes"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1564.010"]
    argument_class = ArgueArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        fake_args = taskData.args.get_arg("fake_args")
        response.DisplayParams = f"{action}" + (f": {fake_args}" if fake_args and action == "set" else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
