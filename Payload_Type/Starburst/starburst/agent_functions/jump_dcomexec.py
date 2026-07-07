from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class JumpDcomexecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                description="Target hostname or IP",
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to execute via DCOM MMC20.Application",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class JumpDcomexecCommand(CommandBase):
    cmd = "jump_dcomexec"
    needs_admin = False
    help_cmd = "jump_dcomexec -hostname TARGET -command whoami"
    description = "Execute a command on a remote host via DCOM MMC20.Application ExecuteShellCommand (DCOMExec-style lateral movement)."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1021.003"]
    argument_class = JumpDcomexecArguments
    attributes = CommandAttributes(
        builtin=False
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        host = taskData.args.get_arg("hostname")
        cmd = taskData.args.get_arg("command")
        response.DisplayParams = f"{host} cmd={cmd}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
