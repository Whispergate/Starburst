from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class LsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                default_value=".",
                description="Directory path to list",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                self.add_arg("path", self.command_line.strip())


class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls [path]"
    description = "List files and directories at the specified path."
    version = 1
    supported_ui_features = ["file_browser:list"]
    author = "@Lavender-exe"
    attackmapping = ["T1083", "T1106"]
    argument_class = LsArguments
    browser_script = BrowserScript(script_name="ls", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(
        builtin=False
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = taskData.args.get_arg("path")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
