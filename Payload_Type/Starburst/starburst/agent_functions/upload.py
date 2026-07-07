import json

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="File to upload to the target",
            ),
            CommandParameter(
                name="remote_path",
                type=ParameterType.String,
                description="Full destination path on target (including filename)",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                pass


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload"
    description = "Upload a file from Mythic to the target."
    version = 1
    supported_ui_features = ["file_browser:upload"]
    author = "@Lavender-exe"
    attackmapping = ["T1132", "T1105"]
    argument_class = UploadArguments
    attributes = CommandAttributes(
        builtin=False
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        file_id = taskData.args.get_arg("file")
        remote_path = taskData.args.get_arg("remote_path")
        response.DisplayParams = f"-> {remote_path}"

        # get file content from Mythic to determine chunk count
        file_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id
        ))

        if not file_resp.Success:
            raise Exception(f"Failed to get file content: {file_resp.Error}")

        file_data = file_resp.Content
        total_size = len(file_data)
        chunk_size = 512000
        total_chunks = (total_size + chunk_size - 1) // chunk_size
        if total_chunks == 0:
            total_chunks = 1

        # pack first chunk into params
        first_chunk = file_data[:chunk_size]

        import base64
        taskData.args.add_arg("file_id", file_id)
        taskData.args.add_arg("total_chunks", total_chunks)
        taskData.args.add_arg("chunk_num", 1)
        taskData.args.add_arg("chunk_data", base64.b64encode(first_chunk).decode())

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

        # handle upload continuation: if response contains upload request for next chunk,
        # fetch the chunk from Mythic and create a subtask with the next chunk
        if isinstance(response, dict) and "upload" in response:
            upload_info = response["upload"]
            file_id = upload_info.get("file_id", "")
            chunk_num = upload_info.get("chunk_num", 1)
            remote_path = upload_info.get("remote_path", "")
            total_chunks = upload_info.get("total_chunks", 1)

            file_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                AgentFileId=file_id
            ))

            if file_resp.Success:
                import base64
                chunk_size = 512000
                start = (chunk_num - 1) * chunk_size
                chunk_data = file_resp.Content[start:start + chunk_size]

                # create a new task with next chunk
                await SendMythicRPCTaskCreate(MythicRPCTaskCreateMessage(
                    AgentCallbackID=task.Callback.ID,
                    CommandName="upload",
                    Params=json.dumps({
                        "file_id": file_id,
                        "remote_path": remote_path,
                        "total_chunks": total_chunks,
                        "chunk_num": chunk_num,
                        "chunk_data": base64.b64encode(chunk_data).decode(),
                    }),
                    IsInteractiveTask=False,
                ))

        return resp
