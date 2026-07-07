from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RpfwdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                default_value="start",
                description="Start or stop the reverse port forward",
            ),
            CommandParameter(
                name="port",
                cli_name="port",
                type=ParameterType.Number,
                default_value=8080,
                description="Port for Mythic to listen on (operator-side)",
            ),
            CommandParameter(
                name="remote_ip",
                cli_name="remote_ip",
                type=ParameterType.String,
                default_value="127.0.0.1",
                description="Target IP the agent connects to for each forwarded connection",
            ),
            CommandParameter(
                name="remote_port",
                cli_name="remote_port",
                type=ParameterType.Number,
                default_value=80,
                description="Target port the agent connects to for each forwarded connection",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class RpfwdCommand(CommandBase):
    cmd = "rpfwd"
    needs_admin = False
    help_cmd = "rpfwd"
    description = "Start or stop a reverse port forward. Mythic listens on the specified port; connections are forwarded through the agent to a target host:port."
    version = 1
    supported_ui_features = ["callback_table:rpfwd"]
    author = "@Lavender-exe"
    argument_class = RpfwdArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        action = taskData.args.get_arg("action")
        port = taskData.args.get_arg("port")
        remote_ip = taskData.args.get_arg("remote_ip")
        remote_port = taskData.args.get_arg("remote_port")

        if action == "start":
            resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
                TaskID=taskData.Task.ID,
                PortType="rpfwd",
                LocalPort=port,
                RemoteIP=remote_ip,
                RemotePort=remote_port,
            ))
            if not resp.Success:
                response.Success = False
                response.Error = f"Failed to start rpfwd: {resp.Error}"
                return response
            taskData.args.add_arg("remote_ip", remote_ip)
            taskData.args.add_arg("remote_port", remote_port)
            response.DisplayParams = f"start :{port} -> {remote_ip}:{remote_port}"
        else:
            resp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                TaskID=taskData.Task.ID,
                Port=port,
                PortType="rpfwd",
            ))
            response.DisplayParams = "stop"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
