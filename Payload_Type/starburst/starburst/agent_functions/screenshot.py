from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json
import time


class ScreenshotArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ScreenshotCommand(CommandBase):
    cmd = "screenshot"
    needs_admin = False
    help_cmd = "screenshot"
    description = "Capture a screenshot of the current desktop."
    version = 1
    supported_ui_features = ["callback_table:screenshot"]
    author = "@Lavender-exe"
    attackmapping = ["T1113"]
    argument_class = ScreenshotArguments
    browser_script = BrowserScript(script_name="screenshot", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(builtin=False, supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        return MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

        # The translator stashes task_id -> file_id when Mythic returns the
        # agent-registered file_id in a get_tasking response. Read it and emit a
        # {"file_id": ...} response so the browser script renders the screenshot
        # inline in the Mythic console (same pattern as Apollo/EmeraldStrike).
        try:
            with open("/Mythic/file_id_map.json") as f:
                mapping = json.load(f)
        except Exception:
            mapping = {}
        # the file_id arrives on the agent's NEXT get_tasking round-trip, so the
        # map may lag the task completion by a few seconds - wait for it
        file_id = mapping.get(task.Task.AgentTaskID) or mapping.get(str(task.Task.ID))
        if not file_id:
            for _ in range(10):
                time.sleep(1)
                try:
                    with open("/Mythic/file_id_map.json") as f:
                        mapping = json.load(f)
                except Exception:
                    continue
                file_id = mapping.get(task.Task.AgentTaskID) or mapping.get(str(task.Task.ID))
                if file_id:
                    break
        if file_id:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=json.dumps({"file_id": file_id}).encode(),
            ))
        return resp
