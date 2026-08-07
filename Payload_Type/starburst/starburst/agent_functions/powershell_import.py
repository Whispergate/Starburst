from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PowershellImportArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                display_name="PowerShell Script",
                type=ParameterType.File,
                description="PowerShell .ps1 script to load into memory for use with powerpick",
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
            raise Exception("Require JSON arguments.\n\tUsage: powershell_import <file>")


class PowershellImportCommand(CommandBase):
    cmd = "powershell_import"
    needs_admin = False
    help_cmd = "powershell_import <script.ps1>"
    description = (
        "Import a PowerShell script into memory. Functions and variables "
        "defined in the imported script become available to subsequent "
        "powerpick commands. Importing a new script replaces any "
        "previously imported script."
    )
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1059.001"]
    argument_class = PowershellImportArguments
    attributes = CommandAttributes(
        builtin=True,
        supported_os=[SupportedOS.Windows],
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
        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to read file content: {file_content.Error}"
            return response

        script_bytes = file_content.Content
        try:
            script_text = script_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            script_text = script_bytes.decode("utf-8", errors="replace")

        if not script_text.strip():
            response.Success = False
            response.Error = "Imported script is empty"
            return response

        # Remove any previous psimport files, then register the new one
        # with a known name so powerpick can find it
        old_files = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=taskData.Task.ID,
            Filename="psimport_active.ps1",
            LimitByCallback=False,
        ))
        if old_files.Success:
            for f in old_files.Files:
                try:
                    await SendMythicRPCFileUpdate(MythicRPCFileUpdateMessage(
                        AgentFileID=f.AgentFileId,
                        Delete=True,
                    ))
                except Exception:
                    pass

        # Register the imported script under a known filename
        import base64
        reg_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
            TaskID=taskData.Task.ID,
            FileContents=script_bytes,
            Filename="psimport_active.ps1",
            DeleteAfterFetch=False,
            IsScreenshot=False,
            IsDownloadFromAgent=False,
            Comment=f"PowerShell import: {original_name}",
        ))
        if not reg_resp.Success:
            response.Success = False
            response.Error = f"Failed to register imported script: {reg_resp.Error}"
            return response

        line_count = script_text.count("\n") + 1
        response.DisplayParams = f"{original_name} ({len(script_bytes)} bytes, {line_count} lines)"
        response.Completed = True
        response.TaskStatus = "success"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
