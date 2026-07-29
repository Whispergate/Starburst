from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ShinjectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="PID",
                display_name="Target PID",
                type=ParameterType.Number,
                description="Target process ID to inject into",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, group_name="Default", ui_position=1),
                    ParameterGroupInfo(required=True, group_name="New", ui_position=1),
                ],
            ),
            CommandParameter(
                name="shellcode_name",
                cli_name="Shellcode",
                display_name="Shellcode File",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_shellcode_files,
                description="Previously uploaded shellcode to inject",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=2,
                    )
                ],
            ),
            CommandParameter(
                name="shellcode_file",
                display_name="New Shellcode",
                type=ParameterType.File,
                description="Upload new shellcode to inject. After uploading, reuse via the Default tab.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="New",
                        ui_position=2,
                    )
                ],
            ),
        ]

    async def get_shellcode_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=inputMsg.Callback,
            LimitByCallback=False,
            Filename="",
        ))
        response = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        if file_resp.Success:
            names = []
            for f in file_resp.Files:
                if f.Filename not in names and (f.Filename.endswith(".bin") or f.Filename.endswith(".pic") or f.Filename.endswith(".raw")):
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
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(ShinjectCommand.help_cmd))


class ShinjectCommand(CommandBase):
    cmd = "shinject"
    needs_admin = False
    help_cmd = "shinject -PID 1234 -Shellcode <shellcode.bin>"
    description = "Inject shellcode into a remote process. Supports raw PIC and Crystal Palace payloads."
    version = 2
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1055.001"]
    argument_class = ShinjectArguments
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
                AgentFileID=taskData.args.get_arg("shellcode_file"),
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = "Failed to find uploaded shellcode file"
                return response

            file_id = taskData.args.get_arg("shellcode_file")
            sc_name = file_search.Files[0].Filename
            taskData.args.add_arg("shellcode_name", sc_name)
            taskData.args.remove_arg("shellcode_file")
        else:
            sc_name = taskData.args.get_arg("shellcode_name")
            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=sc_name,
                LimitByCallback=False,
                MaxResults=1,
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = f"Failed to find shellcode '{sc_name}' in Mythic"
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
        taskData.args.add_arg("shellcode_data", base64.b64encode(file_content.Content).decode(), ParameterType.String)

        pid = taskData.args.get_arg("pid")
        sc_len = len(file_content.Content)
        response.DisplayParams = f"-PID {pid} -Shellcode {sc_name} ({sc_len} bytes)"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
