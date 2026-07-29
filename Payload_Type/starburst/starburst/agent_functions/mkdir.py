from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class MkdirArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Directory path to create",
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class MkdirCommand(CommandBase):
    cmd = "mkdir"
    needs_admin = False
    help_cmd = "mkdir -path C:\\Users\\user\\newdir"
    description = "Create a new directory."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1106"]
    argument_class = MkdirArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        response.DisplayParams = taskData.args.get_arg("path")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
