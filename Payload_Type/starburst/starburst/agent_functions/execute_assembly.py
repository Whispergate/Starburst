from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecuteAssemblyArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="assembly_name",
                cli_name="Assembly",
                display_name="Assembly",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_assembly_files,
                description="Previously uploaded .NET assembly to execute",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="assembly_file",
                display_name="New Assembly",
                type=ParameterType.File,
                description="Upload a new .NET assembly. After uploading, reuse via the Default tab.",
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
                description="Arguments to pass to the assembly",
                default_value="",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=2),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=2),
                ],
            ),
        ]

    async def get_assembly_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=inputMsg.Callback,
            LimitByCallback=False,
            Filename="",
        ))
        response = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        if file_resp.Success:
            names = []
            for f in file_resp.Files:
                if f.Filename not in names and (f.Filename.endswith(".exe") or f.Filename.endswith(".dll")):
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
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(ExecuteAssemblyCommand.help_cmd))


class ExecuteAssemblyCommand(CommandBase):
    cmd = "execute_assembly"
    needs_admin = False
    help_cmd = "execute_assembly -Assembly <assembly.exe> -Arguments \"arg1 arg2\""
    description = "Execute a .NET assembly in-process via CLR hosting."
    version = 2
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1059.001"]
    argument_class = ExecuteAssemblyArguments
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
                AgentFileID=taskData.args.get_arg("assembly_file"),
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = "Failed to find uploaded assembly file"
                return response

            file_id = taskData.args.get_arg("assembly_file")
            assembly_name = file_search.Files[0].Filename
            taskData.args.add_arg("assembly_name", assembly_name)
            taskData.args.remove_arg("assembly_file")
        else:
            assembly_name = taskData.args.get_arg("assembly_name")
            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=assembly_name,
                LimitByCallback=False,
                MaxResults=1,
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = f"Failed to find assembly '{assembly_name}' in Mythic"
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
        taskData.args.add_arg("assembly_data", base64.b64encode(file_content.Content).decode(), ParameterType.String)

        args_str = taskData.args.get_arg("arguments") or ""
        asm_len = len(file_content.Content)
        response.DisplayParams = f"-Assembly {assembly_name} ({asm_len} bytes) -Arguments '{args_str}'"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
