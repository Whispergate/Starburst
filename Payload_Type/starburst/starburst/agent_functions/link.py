from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class LinkArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="connection_info",
                cli_name="NewConnection",
                type=ParameterType.ConnectionInfo,
                description="Connection info for the P2P agent to link to",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class LinkCommand(CommandBase):
    cmd = "link"
    needs_admin = False
    help_cmd = "link"
    description = "Link to a P2P agent on a remote host via SMB named pipe."
    version = 1
    supported_ui_features = ["callback_table:link"]
    author = "@Lavender-exe"
    argument_class = LinkArguments
    attackmapping = ["T1570", "T1572", "T1021"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        connection_info = taskData.args.get_arg("connection_info")
        host = connection_info.get("host", "")
        c2_profile = connection_info.get("c2_profile", {})
        c2_params = c2_profile.get("parameters", {})
        pipename = c2_params.get("pipename", "")

        response.DisplayParams = f"{host} via pipe {pipename}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
