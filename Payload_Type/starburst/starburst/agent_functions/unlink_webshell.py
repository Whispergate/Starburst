from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import mythic_container


class UnlinkWebshellArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="link_info",
                cli_name="Callback",
                display_name="Callback to Unlink",
                type=ParameterType.LinkInfo,
                description="The linked webshell callback to disconnect from",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class UnlinkWebshellCommand(CommandBase):
    cmd = "unlink_webshell"
    needs_admin = False
    help_cmd = "unlink_webshell"
    description = "Disconnect from a linked Ariadne webshell."
    version = 1
    supported_ui_features = ["callback_table:unlink"]
    author = "@Lavender-exe"
    argument_class = UnlinkWebshellArguments
    attackmapping = []
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        link_info = taskData.args.get_arg("link_info")
        host = link_info.get("host", "")
        callback_uuid = link_info.get("callback_uuid", "")

        response.DisplayParams = f"from {host} ({callback_uuid})"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        try:
            raw = response if isinstance(response, str) else str(response)
            if "webshell unlinked" not in raw:
                return resp

            link_info = task.args.get_arg("link_info")
            child_callback_uuid = link_info.get("callback_uuid", "") if link_info else ""
            if not child_callback_uuid:
                return resp

            parent_callback_id = task.Callback.ID
            parent_callback_uuid = task.Callback.AgentCallbackID

            edge_msg = {
                "action": "get_tasking",
                "tasking_size": -1,
                "edges": [
                    {
                        "source": parent_callback_uuid,
                        "destination": child_callback_uuid,
                        "action": "remove",
                        "c2_profile": "ariadne_webshell",
                    }
                ],
            }
            await _send_agent_message_json(parent_callback_id, edge_msg)
            _graphql_remove_edge(parent_callback_id, child_callback_uuid)
        except Exception:
            pass
        return resp


async def _send_agent_message_json(callback_id: int, agent_message: dict) -> dict:
    try:
        result = await mythic_container.RabbitmqConnection.SendRPCDictMessage(
            queue="mythic_rpc_handle_agent_message_json",
            body={
                "callback_id": callback_id,
                "agent_callback_id": None,
                "agent_message": agent_message,
                "update_checkin_time": False,
            }
        )
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def _graphql_remove_edge(parent_id: int, child_callback_uuid: str):
    from starburst.agent_functions.link_webshell import _graphql
    try:
        q = '{ callbackgraphedge(where: {source_id: {_eq: ' + str(parent_id) + '}, destination: {agent_callback_id: {_eq: "' + child_callback_uuid + '"}}, end_timestamp: {_is_null: true}}) { id } }'
        result = _graphql(q)
        edges = result.get("data", {}).get("callbackgraphedge", [])
        for e in edges:
            _graphql(f'mutation {{ callbackgraphedge_remove(edge_id: {e["id"]}) {{ status error }} }}')
    except Exception:
        pass
