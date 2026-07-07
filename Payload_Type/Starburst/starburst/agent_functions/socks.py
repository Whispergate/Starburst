from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                default_value="start",
                description="Start or stop the SOCKS5 proxy",
            ),
            CommandParameter(
                name="port",
                cli_name="port",
                type=ParameterType.Number,
                default_value=7000,
                description="Local port for the SOCKS5 proxy listener",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks"
    description = "Start or stop a SOCKS5 proxy through this callback. Mythic handles the SOCKS server; the agent creates TCP connections to targets."
    version = 1
    supported_ui_features = ["callback_table:socks"]
    author = "@Lavender-exe"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        action = taskData.args.get_arg("action")
        port = taskData.args.get_arg("port")

        if action == "start":
            resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                LocalPort=port,
            ))
            if not resp.Success:
                response.Success = False
                response.Error = f"Failed to start SOCKS proxy: {resp.Error}"
                return response
            response.DisplayParams = f"start on port {port}"
        else:
            resp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                TaskID=taskData.Task.ID,
                Port=port,
                PortType="socks",
            ))
            response.DisplayParams = "stop"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
