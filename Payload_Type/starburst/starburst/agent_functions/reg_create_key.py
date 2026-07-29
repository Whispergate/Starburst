from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RegCreateKeyArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hive",
                type=ParameterType.ChooseOne,
                choices=["HKLM", "HKCU", "HKCR", "HKU"],
                description="Registry hive",
            ),
            CommandParameter(
                name="key",
                type=ParameterType.String,
                description="Registry subkey path to create",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)


class RegCreateKeyCommand(CommandBase):
    cmd = "reg_create_key"
    needs_admin = False
    help_cmd = "reg_create_key -hive HKLM -key SOFTWARE\\NewKey"
    description = "Create a new registry key"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1112"]
    argument_class = RegCreateKeyArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        hive = taskData.args.get_arg("hive")
        key = taskData.args.get_arg("key")
        response.DisplayParams = f"-Hive {hive} -Key {key}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
