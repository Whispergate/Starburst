from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RegDeleteArguments(TaskArguments):
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
            CommandParameter(
                name="value_name",
                type=ParameterType.String,
                description="Value name to delete (leave empty to delete the key itself)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)


class RegDeleteCommand(CommandBase):
    cmd = "reg_delete"
    needs_admin = False
    help_cmd = "reg_delete -hive HKLM -key SOFTWARE\\Test [-value_name MyValue]"
    description = "Delete a registry key or value"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1112"]
    argument_class = RegDeleteArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        hive = taskData.args.get_arg("hive")
        key = taskData.args.get_arg("key")
        value_name = taskData.args.get_arg("value_name")
        if value_name:
            response.DisplayParams = f"-Hive {hive} -Key {key} -ValueName {value_name}"
        else:
            response.DisplayParams = f"-Hive {hive} -Key {key}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
