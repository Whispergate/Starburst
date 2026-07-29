from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class UnlinkArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="link_info",
                cli_name="Callback",
                display_name="Callback to Unlink",
                type=ParameterType.LinkInfo,
                description="The linked callback to disconnect from",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class UnlinkCommand(CommandBase):
    cmd = "unlink"
    needs_admin = False
    help_cmd = "unlink"
    description = "Disconnect from a linked P2P agent."
    version = 1
    supported_ui_features = ["callback_table:unlink"]
    author = "@Lavender-exe"
    argument_class = UnlinkArguments
    attackmapping = []
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        link_info = taskData.args.get_arg("link_info")
        host = link_info.get("host", "")
        callback_uuid = link_info.get("callback_uuid", "")

        response.DisplayParams = f"from {host} ({callback_uuid})"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
