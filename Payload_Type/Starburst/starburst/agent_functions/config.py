from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ConfigArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="sleep",
                type=ParameterType.Number,
                default_value=-1,
                description="New sleep interval in seconds (-1 = no change)",
            ),
            CommandParameter(
                name="jitter",
                type=ParameterType.Number,
                default_value=-1,
                description="New jitter percentage 0-100 (-1 = no change)",
            ),
            CommandParameter(
                name="killdate",
                type=ParameterType.Number,
                default_value=-1,
                description="New killdate as unix timestamp (-1 = no change)",
            ),
            CommandParameter(
                name="spawnto_x64",
                type=ParameterType.String,
                default_value="",
                description="x64 sacrifice binary path (empty = no change)",
            ),
            CommandParameter(
                name="spawnto_x64_args",
                type=ParameterType.String,
                default_value="",
                description="x64 sacrifice binary arguments (empty = no change)",
            ),
            CommandParameter(
                name="spawnto_x86",
                type=ParameterType.String,
                default_value="",
                description="x86 sacrifice binary path (empty = no change)",
            ),
            CommandParameter(
                name="spawnto_x86_args",
                type=ParameterType.String,
                default_value="",
                description="x86 sacrifice binary arguments (empty = no change)",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                pass


class ConfigCommand(CommandBase):
    cmd = "config"
    needs_admin = False
    help_cmd = "config [sleep=N] [jitter=N] [killdate=N] [spawnto_x64=path] [spawnto_x86=path]"
    description = "View or modify the agent's runtime configuration (sleep, jitter, killdate, spawnto paths)."
    version = 2
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = ConfigArguments
    attributes = CommandAttributes(
        builtin=False
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        sleep_val = taskData.args.get_arg("sleep")
        jitter_val = taskData.args.get_arg("jitter")
        killdate_val = taskData.args.get_arg("killdate")

        parts = []
        # convert seconds to ms for agent, use 0xFFFFFFFF sentinel for "no change"
        if sleep_val >= 0:
            taskData.args.add_arg("sleep", sleep_val * 1000)
            parts.append(f"sleep={sleep_val}s")
        else:
            taskData.args.add_arg("sleep", 0xFFFFFFFF)

        if jitter_val >= 0:
            parts.append(f"jitter={jitter_val}%")
        else:
            taskData.args.add_arg("jitter", 0xFFFFFFFF)

        if killdate_val >= 0:
            parts.append(f"killdate={killdate_val}")
        else:
            taskData.args.add_arg("killdate", 0xFFFFFFFF)

        spawnto_x64 = taskData.args.get_arg("spawnto_x64") or ""
        spawnto_x64_args = taskData.args.get_arg("spawnto_x64_args") or ""
        spawnto_x86 = taskData.args.get_arg("spawnto_x86") or ""
        spawnto_x86_args = taskData.args.get_arg("spawnto_x86_args") or ""

        if spawnto_x64:
            parts.append(f"spawnto_x64={spawnto_x64}")
        if spawnto_x64_args:
            parts.append(f"spawnto_x64_args={spawnto_x64_args}")
        if spawnto_x86:
            parts.append(f"spawnto_x86={spawnto_x86}")
        if spawnto_x86_args:
            parts.append(f"spawnto_x86_args={spawnto_x86_args}")

        if parts:
            response.DisplayParams = " ".join(parts)
        else:
            response.DisplayParams = "(view current config)"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
