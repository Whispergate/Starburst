from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RegQueryArguments(TaskArguments):
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
                description="Registry subkey path",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class RegQueryCommand(CommandBase):
    cmd = "reg_query"
    needs_admin = False
    help_cmd = "reg_query -hive HKLM -key SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
    description = "Query registry key values and subkeys."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1012"]
    argument_class = RegQueryArguments
    browser_script = BrowserScript(script_name="reg_query", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        hive = taskData.args.get_arg("hive")
        key = taskData.args.get_arg("key")
        response.DisplayParams = f"{hive}\\{key}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
