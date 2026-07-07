from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class JumpPsexecArguments(TaskArguments):
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
                description="Service name to create on remote host",
                default_value="StarSvc",
            ),
            CommandParameter(
                name="binary_path",
                type=ParameterType.String,
                description="Full UNC path to binary to execute as service",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class JumpPsexecCommand(CommandBase):
    cmd = "jump_psexec"
    needs_admin = True
    help_cmd = "jump_psexec -hostname TARGET -binary_path \\\\share\\payload.exe"
    description = "Create and start a service on a remote host via SCM."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1021.002", "T1569.002"]
    argument_class = JumpPsexecArguments
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
        bp = taskData.args.get_arg("binary_path")
        response.DisplayParams = f"{host} svc={svc} bin={bp}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
