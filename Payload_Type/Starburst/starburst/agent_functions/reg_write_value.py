from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RegWriteValueArguments(TaskArguments):
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
                name="name",
                type=ParameterType.String,
                description="Value name to write",
            ),
            CommandParameter(
                name="value",
                type=ParameterType.String,
                description="Value data to write",
            ),
            CommandParameter(
                name="type",
                type=ParameterType.ChooseOne,
                choices=["REG_SZ", "REG_DWORD", "REG_EXPAND_SZ"],
                default_value="REG_SZ",
                description="Registry value type",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class RegWriteValueCommand(CommandBase):
    cmd = "reg_write_value"
    needs_admin = False
    help_cmd = "reg_write_value -hive HKCU -key SOFTWARE\\Test -name MyVal -value hello -type REG_SZ"
    description = "Write a value to a registry key."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1112"]
    argument_class = RegWriteValueArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        reg_type_str = taskData.args.get_arg("type")
        type_map = {"REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_DWORD": 4}
        taskData.args.add_arg("type", type_map.get(reg_type_str, 1))
        hive = taskData.args.get_arg("hive")
        key = taskData.args.get_arg("key")
        name = taskData.args.get_arg("name")
        response.DisplayParams = f"{hive}\\{key} -> {name}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
