from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class JumpScshellArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                description="Target hostname or IP",
            ),
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Existing service to hijack on remote host",
                default_value="SensSvc",
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to execute (wrapped in %%COMSPEC%% /c)",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class JumpScshellCommand(CommandBase):
    cmd = "jump_scshell"
    needs_admin = True
    help_cmd = "jump_scshell -hostname TARGET -command whoami"
    description = "Execute a command on a remote host by modifying an existing service's binary path (SCShell-style, no file drop)."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1021.002", "T1543.003"]
    argument_class = JumpScshellArguments
    attributes = CommandAttributes(
        builtin=False
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        host = taskData.args.get_arg("hostname")
        svc = taskData.args.get_arg("service_name")
        cmd = taskData.args.get_arg("command")
        response.DisplayParams = f"{host} svc={svc} cmd={cmd}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
