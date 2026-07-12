from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class JobkillArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="task_id",
                type=ParameterType.String,
                description="Task ID (display ID or UUID) of the job to kill",
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if not self.command_line or len(self.command_line.strip()) == 0:
            return
        try:
            self.load_args_from_json_string(self.command_line)
        except Exception:
            self.add_arg("task_id", self.command_line.strip())


class JobkillCommand(CommandBase):
    cmd = "jobkill"
    needs_admin = False
    help_cmd = "jobkill [task_id]"
    description = "Kill a running background job or interactive session by its task ID."
    version = 2
    supported_ui_features = ["jobkill", "task:job_kill"]
    author = "@Lavender-exe"
    attackmapping = []
    argument_class = JobkillArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        task_id = taskData.args.get_arg("task_id") or ""
        if not task_id:
            task_id = taskData.args.command_line.strip() if taskData.args.command_line else ""
        if not task_id:
            response.Success = False
            response.Error = "task_id is required"
            return response

        response.DisplayParams = f"task {task_id}"

        tid_str = str(task_id).strip()
        agent_task_id = ""

        if tid_str.isdigit():
            search_resp = await SendMythicRPCTaskSearch(MythicRPCTaskSearchMessage(
                TaskID=taskData.Task.ID,
                SearchTaskID=int(tid_str),
            ))
            if search_resp.Success and len(search_resp.Tasks) > 0:
                found_task = search_resp.Tasks[0]
                agent_task_id = found_task.AgentTaskID
                if found_task.CommandName == "rpfwd":
                    await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                        TaskID=found_task.TaskID,
                        PortType="rpfwd",
                    ))
        else:
            search_resp = await SendMythicRPCTaskSearch(MythicRPCTaskSearchMessage(
                TaskID=taskData.Task.ID,
                SearchAgentTaskID=tid_str,
            ))
            if search_resp.Success and len(search_resp.Tasks) > 0:
                found_task = search_resp.Tasks[0]
                agent_task_id = found_task.AgentTaskID
                if found_task.CommandName == "rpfwd":
                    await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                        TaskID=found_task.TaskID,
                        PortType="rpfwd",
                    ))
            else:
                agent_task_id = tid_str

        if agent_task_id:
            taskData.args.add_arg("task_id", agent_task_id)

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
