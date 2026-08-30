from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RegisterCoffArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                display_name="COFF/BOF File",
                type=ParameterType.File,
                description="Upload a COFF/BOF object file (.o) to register for use with execute_coff",
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
            raise Exception("Require JSON arguments.\n\tUsage: register_coff <file>")


class RegisterCoffCommand(CommandBase):
    cmd = "register_coff"
    needs_admin = False
    help_cmd = "register_coff <bof.o>"
    description = (
        "Upload and register a COFF/BOF object file (.o) in Mythic's file store. "
        "Registered BOFs appear in the execute_coff dropdown for reuse."
    )
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = RegisterCoffArguments
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
        if not original_name.endswith(".o"):
            response.Success = False
            response.Error = f"Invalid file type: '{original_name}'. Expected .o (COFF object file)"
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
            Comment=f"Registered COFF/BOF: {original_name}",
        ))
        if not reg_resp.Success:
            response.Success = False
            response.Error = f"Failed to register COFF: {reg_resp.Error}"
            return response

        response.DisplayParams = f"{original_name} ({len(file_content.Content)} bytes)"
        response.Completed = True
        response.TaskStatus = "success"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
