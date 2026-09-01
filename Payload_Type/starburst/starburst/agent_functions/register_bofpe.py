from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RegisterBofpeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                display_name="BOF-PE File",
                type=ParameterType.File,
                description="Upload a BOF-PE (.exe, .dll, or .bofpe) to register for use with execute_bofpe",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    )
                ],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON arguments.\n\tUsage: register_bofpe <file>")


class RegisterBofpeCommand(CommandBase):
    cmd = "register_bofpe"
    needs_admin = False
    help_cmd = "register_bofpe <bofpe.exe>"
    description = (
        "Upload and register a BOF-PE file (.exe, .dll, or .bofpe) in Mythic's file store. "
        "Registered BOF-PEs appear in the execute_bofpe dropdown for reuse."
    )
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = RegisterBofpeArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
        script_only=True,
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

        file_id = taskData.args.get_arg("file")
        file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=taskData.Task.ID,
            AgentFileID=file_id,
        ))
        if not file_search.Success or len(file_search.Files) == 0:
            response.Success = False
            response.Error = "Failed to find uploaded file"
            return response

        original_name = file_search.Files[0].Filename
        if not (original_name.endswith(".exe") or original_name.endswith(".dll") or original_name.endswith(".bofpe")):
            response.Success = False
            response.Error = f"Invalid file type: '{original_name}'. Expected .exe, .dll, or .bofpe"
            return response

        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to read file content: {file_content.Error}"
            return response

        reg_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
            TaskID=taskData.Task.ID,
            FileContents=file_content.Content,
            Filename=original_name,
            DeleteAfterFetch=False,
            IsScreenshot=False,
            IsDownloadFromAgent=False,
            Comment=f"Registered BOF-PE: {original_name}",
        ))
        if not reg_resp.Success:
            response.Success = False
            response.Error = f"Failed to register BOF-PE: {reg_resp.Error}"
            return response

        response.DisplayParams = f"{original_name} ({len(file_content.Content)} bytes)"
        response.Completed = True
        response.TaskStatus = "success"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
