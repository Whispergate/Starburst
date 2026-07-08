from mythic_container.MythicCommandBase import *


class SpawntoX64Arguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="application",
                cli_name="Application",
                display_name="Path to Application",
                type=ParameterType.String,
                default_value="C:\\Windows\\System32\\rundll32.exe",
            ),
            CommandParameter(
                name="arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception(
                "spawnto_x64 requires a path to an executable.\n"
                "\tUsage: spawnto_x64 [path] [args]"
            )
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split(None, 1)
            self.add_arg("application", parts[0])
            self.add_arg("arguments", parts[1] if len(parts) > 1 else "")


class SpawntoX64Command(CommandBase):
    cmd = "spawnto_x64"
    needs_admin = False
    help_cmd = "spawnto_x64 [path] [args]"
    description = "Change the default x64 binary used in post-exploitation jobs (shinject, execute_assembly, etc)."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1055"]
    argument_class = SpawntoX64Arguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )
        app = taskData.args.get_arg("application")
        args = taskData.args.get_arg("arguments")
        response.DisplayParams = f"-Application {app}"
        if args:
            response.DisplayParams += f" -Arguments {args}"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )
