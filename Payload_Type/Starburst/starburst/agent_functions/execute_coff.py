from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecuteCoffArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="coff_name",
                cli_name="Coff",
                display_name="COFF File",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_coff_files,
                description="Previously uploaded COFF/BOF to execute",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="bof_file",
                display_name="New BOF",
                type=ParameterType.File,
                description="Upload a new BOF to execute. After uploading, reuse via the Default tab.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="New",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                description="Packed arguments for the BOF (hex-encoded or raw)",
                default_value="",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=2),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=2),
                ],
            ),
            CommandParameter(
                name="entrypoint",
                cli_name="Function",
                display_name="Entry Point",
                type=ParameterType.String,
                description="Entry point function name",
                default_value="go",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=3),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=3),
                ],
            ),
        ]

    async def get_coff_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=inputMsg.Callback,
            LimitByCallback=False,
            Filename="",
        ))
        response = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        if file_resp.Success:
            names = []
            for f in file_resp.Files:
                if f.Filename not in names and f.Filename.endswith(".o"):
                    names.append(f.Filename)
            response.Success = True
            response.Choices = names
        else:
            response.Error = file_resp.Error
        return response

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(ExecuteCoffCommand.help_cmd))


class ExecuteCoffCommand(CommandBase):
    cmd = "execute_coff"
    needs_admin = False
    help_cmd = "execute_coff -Coff <bof.o> -Function go"
    description = "Execute a COFF/BOF (Beacon Object File) with Beacon API compatibility."
    version = 2
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1106"]
    argument_class = ExecuteCoffArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

        if taskData.args.get_parameter_group_name() == "New":
            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                AgentFileID=taskData.args.get_arg("bof_file"),
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = "Failed to find uploaded BOF file"
                return response

            file_id = taskData.args.get_arg("bof_file")
            coff_name = file_search.Files[0].Filename
            taskData.args.add_arg("coff_name", coff_name)
            taskData.args.remove_arg("bof_file")
        else:
            coff_name = taskData.args.get_arg("coff_name")
            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=coff_name,
                LimitByCallback=False,
                MaxResults=1,
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = f"Failed to find COFF file '{coff_name}' in Mythic"
                return response
            file_id = file_search.Files[0].AgentFileId

        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get file content: {file_content.Error}"
            return response

        import base64
        taskData.args.add_arg("coff_data", base64.b64encode(file_content.Content).decode(), ParameterType.String)

        entry = taskData.args.get_arg("entrypoint") or "go"
        coff_len = len(file_content.Content)
        response.DisplayParams = f"-Coff {coff_name} -Function {entry} ({coff_len} bytes)"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
