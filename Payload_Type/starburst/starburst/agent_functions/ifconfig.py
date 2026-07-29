from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class IfconfigArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class IfconfigCommand(CommandBase):
    cmd = "ifconfig"
    needs_admin = False
    help_cmd = "ifconfig"
    description = "List network adapter information including IP addresses, MAC addresses, gateways, and DHCP status."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1016"]
    argument_class = IfconfigArguments
    browser_script = BrowserScript(script_name="ifconfig", author="@Lavender-exe", for_new_ui=True)
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        return MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
