from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PortscanArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hosts",
                type=ParameterType.String,
                description="Comma-separated target hosts/IPs (e.g. 10.0.0.1,10.0.0.2)",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="ports",
                type=ParameterType.String,
                description="Comma-separated ports (e.g. 22,80,443,3389,8080)",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="timeout",
                type=ParameterType.Number,
                default_value=1000,
                description="Connection timeout in milliseconds",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)


class PortscanCommand(CommandBase):
    cmd = "portscan"
    needs_admin = False
    help_cmd = "portscan -hosts 10.0.0.1,10.0.0.2 -ports 22,80,443,3389,8080 [-timeout 1000]"
    description = "TCP connect port scanner"
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1046"]
    argument_class = PortscanArguments
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        hosts = taskData.args.get_arg("hosts")
        ports = taskData.args.get_arg("ports")
        response.DisplayParams = f"{hosts} -> {ports}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
