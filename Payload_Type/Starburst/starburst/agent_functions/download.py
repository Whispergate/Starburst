from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class DownloadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.String,
                description="Full path of file to download from target",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                self.add_arg("file", self.command_line.strip())


class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download [file_path]"
    description = "Download a file from the target to the Mythic server."
    version = 1
    supported_ui_features = ["file_browser:download"]
    author = "@Lavender-exe"
    attackmapping = ["T1041", "T1005"]
    argument_class = DownloadArguments
    browser_script = BrowserScript(script_name="download", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(
        builtin=False
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = taskData.args.get_arg("file")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
