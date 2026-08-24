from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecuteBofpeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pe_name",
                cli_name="PE",
                display_name="BOF-PE File",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_pe_files,
                description="Previously uploaded BOF-PE to execute",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="pe_file",
                display_name="New BOF-PE",
                type=ParameterType.File,
                description="Upload a new BOF-PE to execute. After uploading, reuse via the Default tab.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="New",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="pe_data",
                display_name="Inline BOF-PE (base64)",
                type=ParameterType.String,
                description="Base64-encoded BOF-PE data for inline execution",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Inline",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                description="Packed arguments for the BOF-PE (forge format or hex-encoded)",
                default_value="",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=2),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=2),
                    ParameterGroupInfo(required=False, group_name="Inline", ui_position=2),
                ],
            ),
            CommandParameter(
                name="entrypoint",
                cli_name="Function",
                display_name="Entry Point",
                type=ParameterType.String,
                description="Exported function name to call (default: go)",
                default_value="go",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=3),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=3),
                    ParameterGroupInfo(required=False, group_name="Inline", ui_position=3),
                ],
            ),
        ]

    async def get_pe_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=inputMsg.Callback,
            LimitByCallback=False,
            Filename="",
        ))
        response = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        if file_resp.Success:
            names = []
            for f in file_resp.Files:
                if f.Filename not in names and (
                    f.Filename.endswith(".exe") or
                    f.Filename.endswith(".dll") or
                    f.Filename.endswith(".bofpe")
                ):
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
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(ExecuteBofpeCommand.help_cmd))


class ExecuteBofpeCommand(CommandBase):
    cmd = "execute_bofpe"
    needs_admin = False
    help_cmd = "execute_bofpe -PE <bofpe.exe> -Function go"
    description = (
        "Execute a BOF-PE (Beacon Object File - Portable Executable). "
        "Loads a fully-linked PE in-memory using reflective loading, "
        "intercepts beacon.dll imports for C2 output routing, and calls "
        "the specified exported function. Supports C++20, STL, exceptions, "
        "and all standard PE features."
    )
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1106", "T1620"]
    argument_class = ExecuteBofpeArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    @staticmethod
    def _pack_forge_arguments(args_input):
        import ast, struct
        args_list = args_input
        if isinstance(args_input, str):
            try:
                args_list = ast.literal_eval(args_input)
            except Exception:
                return None
        if not isinstance(args_list, list):
            return None
        packed = b""
        for arg in args_list:
            if not isinstance(arg, (list, tuple)) or len(arg) != 2:
                return None
            atype, aval = str(arg[0]), str(arg[1]) if arg[1] is not None else ""
            if atype == "z":
                data = aval.encode("utf-8") + b"\x00"
                packed += struct.pack("<I", len(data)) + data
            elif atype == "Z":
                data = aval.encode("utf-16-le") + b"\x00\x00"
                packed += struct.pack("<I", len(data)) + data
            elif atype == "i":
                packed += struct.pack("<i", int(aval) if aval else 0)
            elif atype == "s":
                packed += struct.pack("<h", int(aval) if aval else 0)
            elif atype == "b":
                data = bytes.fromhex(aval) if aval else b""
                packed += struct.pack("<I", len(data)) + data
            else:
                return None
        return packed.hex()

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID, Success=True,
        )

        group = taskData.args.get_parameter_group_name()

        if group == "Inline":
            entry = taskData.args.get_arg("entrypoint") or "go"
            import base64
            pe_b64 = taskData.args.get_arg("pe_data")
            pe_len = len(base64.b64decode(pe_b64)) if pe_b64 else 0
            response.DisplayParams = f"-Inline ({pe_len} bytes) -Function {entry}"

            args_raw = taskData.args.get_arg("arguments") or ""
            packed = self._pack_forge_arguments(args_raw)
            if packed is not None:
                taskData.args.remove_arg("arguments")
                taskData.args.add_arg("arguments", packed, ParameterType.String,
                                      parameter_group_info=[
                                          ParameterGroupInfo(required=False, group_name="Inline"),
                                      ])
            return response

        if group == "New":
            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                AgentFileID=taskData.args.get_arg("pe_file"),
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = "Failed to find uploaded BOF-PE file"
                return response

            file_id = taskData.args.get_arg("pe_file")
            pe_name = file_search.Files[0].Filename
            taskData.args.add_arg("pe_name", pe_name)
            taskData.args.remove_arg("pe_file")
        else:
            pe_name = taskData.args.get_arg("pe_name")
            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=pe_name,
                LimitByCallback=False,
                MaxResults=1,
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = f"Failed to find BOF-PE file '{pe_name}' in Mythic"
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
        taskData.args.add_arg("pe_data", base64.b64encode(file_content.Content).decode(), ParameterType.String,
                              parameter_group_info=[
                                  ParameterGroupInfo(group_name="Default"),
                                  ParameterGroupInfo(group_name="New"),
                              ])

        args_raw = taskData.args.get_arg("arguments") or ""
        packed = self._pack_forge_arguments(args_raw)
        if packed is not None:
            taskData.args.remove_arg("arguments")
            taskData.args.add_arg("arguments", packed, ParameterType.String,
                                  parameter_group_info=[
                                      ParameterGroupInfo(required=False, group_name="Default"),
                                      ParameterGroupInfo(required=False, group_name="New"),
                                  ])

        entry = taskData.args.get_arg("entrypoint") or "go"
        pe_len = len(file_content.Content)
        response.DisplayParams = f"-PE {pe_name} -Function {entry} ({pe_len} bytes)"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
