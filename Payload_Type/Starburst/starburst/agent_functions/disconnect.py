from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class DisconnectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="link_info",
                cli_name="RemoveConnection",
                type=ParameterType.LinkInfo,
                description="Info about the P2P connection to tear down",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class DisconnectCommand(CommandBase):
    cmd = "disconnect"
    needs_admin = False
    help_cmd = "disconnect"
    description = "Disconnect from a TCP-linked P2P agent."
    version = 1
    supported_ui_features = ["callback_table:disconnect"]
    author = "@Lavender-exe"
    argument_class = DisconnectArguments
    attackmapping = ["T1570"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        link_info = taskData.args.get_arg("link_info")
        callback_uuid = link_info.get("callback_uuid", "")
        response.DisplayParams = f"TCP agent {callback_uuid}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
