from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import base64
import logging

logger = logging.getLogger("mythic")


class LoadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="commands",
                cli_name="Commands",
                display_name="Commands",
                type=ParameterType.ChooseMultiple,
                dynamic_query_function=self.get_remaining_commands,
                description="One or more commands to load into the agent",
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
                display_name="Module File",
                type=ParameterType.File,
                description="Upload a PIC module file directly",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="New",
                        ui_position=1,
                    )
                ],
            ),
        ]

    async def get_remaining_commands(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        fileResponse = PTRPCDynamicQueryFunctionMessageResponse(Success=False)

        all_cmds = await SendMythicRPCCommandSearch(MythicRPCCommandSearchMessage(
            SearchPayloadTypeName="starburst"
        ))
        loaded_cmds = await SendMythicRPCCallbackSearchCommand(MythicRPCCallbackSearchCommandMessage(
            CallbackID=inputMsg.Callback
        ))

        if not all_cmds.Success:
            raise Exception("Failed to get commands for starburst agent: {}".format(all_cmds.Error))
        if not loaded_cmds.Success:
            raise Exception("Failed to fetch loaded commands from callback {}: {}".format(inputMsg.Callback, loaded_cmds.Error))

        all_cmds_names = set([r.Name for r in all_cmds.Commands])
        loaded_cmds_names = set([r.Name for r in loaded_cmds.Commands])
        logger.debug(f"[load] all: {all_cmds_names}, loaded: {loaded_cmds_names}")

        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=inputMsg.Callback,
            LimitByCallback=False,
            Filename="",
        ))
        available_modules = set()
        if file_resp.Success:
            for f in file_resp.Files:
                if f.Filename.endswith(".bin"):
                    available_modules.add(f.Filename[:-4])

        diff = all_cmds_names.difference(loaded_cmds_names).intersection(available_modules)
        fileResponse.Success = True
        fileResponse.Choices = sorted(diff)
        logger.debug(f"[load] loadable: {fileResponse.Choices}")
        return fileResponse

    async def parse_dictionary(self, dictionary):
        cmds = dictionary.get("Commands") or dictionary.get("commands")
        module_file = dictionary.get("module_file")
        if cmds is not None:
            if isinstance(cmds, str):
                cmds = cmds.split()
            self.add_arg("commands", cmds, ParameterType.ChooseMultiple)
        elif module_file is not None:
            self.add_arg("module_file", module_file, ParameterType.File)
        else:
            raise Exception("Must provide Commands or module_file")

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            import json, ast
            try:
                tmpjson = json.loads(self.command_line)
            except json.JSONDecodeError:
                tmpjson = ast.literal_eval(self.command_line)
            await self.parse_dictionary(tmpjson)
        else:
            raise Exception("Require JSON arguments.\n\tUsage: {}".format(LoadCommand.help_cmd))


class LoadCommand(CommandBase):
    cmd = "load"
    needs_admin = False
    help_cmd = "load -Commands <cmd1> <cmd2>"
    description = "Load a PIC module into the agent at runtime, registering new command handlers."
    version = 2
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1129"]
    argument_class = LoadArguments
    attributes = CommandAttributes(
        builtin=False,
        suggested_command=True,
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
            cmd_name = module_name
            for ext in (".bin", ".pic", ".mod", ".raw"):
                cmd_name = cmd_name.replace(ext, "")
            taskData.args.remove_arg("module_file")
        else:
            requested = taskData.args.get_arg("commands")
            if isinstance(requested, str):
                requested = [requested]
            if not requested or len(requested) == 0:
                response.Success = False
                response.Error = "No commands specified"
                return response
            cmd_name = requested[0]
            module_name = f"{cmd_name}.bin"
            file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=module_name,
                LimitByCallback=False,
                MaxResults=1,
            ))
            if not file_search.Success or len(file_search.Files) == 0:
                response.Success = False
                response.Error = f"Module '{module_name}' not found in Mythic"
                return response
            file_id = file_search.Files[0].AgentFileId
            taskData.args.remove_arg("commands")

        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id,
        ))
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get file content: {file_content.Error}"
            return response

        taskData.args.add_arg("module_data",
            base64.b64encode(file_content.Content).decode(),
            ParameterType.String)
        taskData.args.add_arg("commands", [cmd_name], ParameterType.Array)

        try:
            reg_resp = await SendMythicRPCCallbackAddCommand(MythicRPCCallbackAddCommandMessage(
                TaskID=taskData.Task.ID,
                Commands=[cmd_name],
            ))
            if not reg_resp.Success:
                logger.warning(f"[load] Pre-enroll failed: {reg_resp.Error}")
        except Exception as e:
            logger.warning(f"[load] Pre-enroll exception: {e}")

        response.DisplayParams = f"-command {cmd_name} ({len(file_content.Content)} bytes)"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        result = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

        commands = task.args.get_arg("commands")
        if not commands:
            return result

        reg_resp = await SendMythicRPCCallbackAddCommand(MythicRPCCallbackAddCommandMessage(
            TaskID=task.Task.ID,
            Commands=commands,
        ))
        if not reg_resp.Success:
            raise Exception("Failed to register commands ({}): {}".format(commands, reg_resp.Error))

        return result
